use std::borrow::Cow;
use std::collections::{BTreeSet, HashSet, VecDeque};
use std::convert::TryInto;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use base64::prelude::{BASE64_STANDARD, Engine as _};
use bytes::Bytes;
use gix_actor::{Signature, SignatureRef};
use gix_date::Time;
use gix_object::bstr::ByteSlice;
use serde::Deserialize;
use smallvec::SmallVec;
use tracing::{Span, instrument};

use github_types::repos::*;
use github_types::webhooks::{Webhook, WebhookEvent};

use super::{GHError, HookConfig};
use crate::github::{
    Authorization, Config, Error, GithubError, GithubErrorDetails, SimpleUser,
    St, auth_to_user,
};
use crate::model::prs::ReferenceFinder;
use crate::model::{Read, Token, Write};

pub mod access;
pub mod git;
pub mod git_protocol;
pub mod issues;

// TODO: make WebhookEvent clonable instead? idk
pub fn send_hook<M, E: Fn() -> WebhookEvent>(
    tx: &Token<M>,
    repo: crate::model::repos::Repository,
    st: &Config,
    hook_type: HookEvent,
    sender: &super::User,
    event: E,
) {
    for hook in crate::model::repos::list_hooks(tx, repo.id) {
        if hook.active && hook.events.iter().any(|e| e == &hook_type) {
            let _ = st.webhooks.send((
                HookConfig {
                    id: hook.id,
                    active: hook.active,
                    url: hook.url,
                    content_type: hook.content_type.into(),
                    events: hook.events.into_iter().collect(),
                    secret: hook.secret,
                    insecure_ssl: hook.insecure_ssl,
                },
                Webhook {
                    sender: sender.to_simple(&st.root),
                    repository: repo.to_response(tx, &st.root),
                    event: event(),
                },
                Span::current(),
            ));
        }
    }
}

struct Bundle<'r, 's: 'r>(
    &'r crate::github::Config,
    &'r Token<Read>,
    &'r str,
    &'r str,
    &'r gix_hash::oid,
    &'r gix_object::CommitRef<'s>,
);
impl<'r, 's> From<Bundle<'r, 's>> for CommitsResponse {
    fn from(
        Bundle(st, tx, owner, name, oid, commit): Bundle<'r, 's>,
    ) -> CommitsResponse {
        let to_user = |u: SignatureRef<'_>| {
            (u.email.as_bytes() == b"noreply@github.com")
                .then(|| SimpleUser::for_login(&st.root, "web-flow".into()))
                .or_else(|| {
                    crate::model::users::get_user_from_email(
                        tx,
                        &u.email.to_string(),
                    )
                    .map(|u| u.to_simple(&st.root))
                })
        };
        Self {
            node_id: String::new(),
            sha: oid.to_string(),
            commit: CommitsResponseCommit {
                tree: Tree {
                    sha: commit.tree().to_string(),
                    url: None,
                },
                message: String::from_utf8_lossy(commit.message.trim())
                    .to_string(),
                author: Some(commit.author.into()),
                committer: Some(commit.committer.into()),
                comments_count: 0,
                url: format!(
                    "{}/repos/{}/{}/git/commits/{}",
                    st.root, owner, name, oid
                ),
            },
            parents: commit
                .parents()
                .map(|oid| CommitLink {
                    sha: oid.to_string(),
                    url: format!(
                        "{}/repos/{}/{}/git/commits/{}",
                        st.root, owner, name, oid
                    ),
                    html_url: None,
                })
                .collect(),
            url: format!(
                "{}/repos/{}/{}/commits/{}",
                st.root, owner, name, oid
            ),
            comments_url: String::new(),
            html_url: String::new(),
            author: to_user(commit.author),
            committer: to_user(commit.committer),
            files: vec![],
        }
    }
}

#[rustfmt::skip]
pub fn routes() -> Router<St> {
    Router::new()
        .nest(
            "/repos/{owner}/{name}",
            Router::new()
                .route(
                    "/",
                    get(get_repository)
                    .patch(update_repository)
                    .delete(delete_repository)
                )
                .route("/forks", post(create_fork))
                .route("/hooks", get(list_hooks).post(create_hook))
                .route("/hooks/{id}", get(get_hook).patch(update_hook).delete(delete_hook))
                .route("/branches", get(list_branches))
                .route("/branches/{name}", get(get_branch))
                .route("/branches/{name}/protection", put(update_branch_protection))
                .route("/commits", get(list_commits))
                .route("/commits/{*rest}", get(commits_query))
                .route("/contents/{*path}", get(get_contents).put(create_or_update_contents))
                .route("/statuses/{hash}", post(create_status))
                .route("/merges", post(create_branch_merge))
                .route("/deployments", post(create_deployment))
                .route("/deployments/{id}/statuses", post(create_deployment_status))
                .merge(access::routes())
                .merge(issues::routes())
                .nest("/git", git::routes())
        )
        .nest("/{owner}/{name}", git_protocol::routes())
}

#[instrument(skip(st, tx))]
async fn get_repository(
    State(st): State<St>,
    tx: Token<Read>,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Json<RepositoryResponse>, GHError<'static>> {
    match crate::model::repos::by_name(&tx, &owner, &name) {
        Some(repo) => Ok(Json(repo.to_response(&tx, &st.root))),
        None => Err(Error::NOT_FOUND.into_response(
            "repos",
            "repos",
            "get-a-repository",
        )),
    }
}

#[instrument(skip(st, tx))]
async fn update_repository(
    State(st): State<St>,
    tx: Token<Write>,
    Path((owner, name)): Path<(String, String)>,
    Json(updates): Json<UpdateRepository>,
) -> Result<Json<RepositoryResponse>, Response> {
    let Some(rid) = crate::model::repos::id_by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND
            .into_response("repos", "repos", "update-a-repository")
            .into_response());
    };

    // TODO: does the default branch need to exist?
    // TODO: what if we rename & change default branch but the branch doesn't exist? Or the reverse?
    if let Some(d) = &updates.default_branch
        && crate::model::git::refs::resolve(
            &tx,
            rid,
            &format!("refs/heads/{d}"),
        )
        .is_none()
    {
        return Err(Error::unprocessable("Validation Failed", &[
            Error::details(
                "Repository",
                "default_branch",
                "invalid",
                &format!("The branch {d} was not found. Please push that ref first or create it via the Git Data API."),
            )
        ]).into_response("repos", "repos", "update-a-repository").into_response());
    }
    // TODO: check if name editions follows same normalisation
    //       behaviour as creation
    crate::model::repos::update_repository(
        &tx,
        rid,
        updates.name.as_deref(),
        updates.default_branch.as_deref(),
    );
    let response =
        crate::model::repos::by_id(&tx, rid).to_response(&tx, &st.root);
    tx.commit();

    Ok(Json(response))
}

#[instrument(skip(tx))]
async fn delete_repository(
    auth: Authorization,
    State(_): State<St>,
    tx: Token<Write>,
    Path((owner, name)): Path<(String, String)>,
) -> Result<StatusCode, GHError<'static>> {
    let Some(user) = crate::github::auth_to_user(&tx, auth) else {
        return Err(Error::Unauthenticated(
            "You must be logged in to do that.",
        )
        .into_response("repos", "repos", "delete-a-repository"));
    };

    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "repos",
            "repos",
            "delete-a-repository",
        ));
    };

    if user.id != repo.owner.id {
        #[allow(clippy::collapsible_if)]
        if !crate::model::repos::get_collaborators(&tx, repo.id)
            .into_iter()
            .any(|(uid, role)| {
                user.id == uid
                    && matches!(role, crate::model::repos::Role::Administrate)
            })
        {
            return Err(Error::Forbidden("").into_response(
                "repos",
                "repos",
                "delete-a-repository",
            ));
        }
    }

    crate::model::repos::delete(&tx, repo.id);
    tx.commit();
    Ok(StatusCode::NO_CONTENT)
}

#[instrument(skip(st, tx))]
async fn create_fork(
    auth: Authorization,
    State(st): State<St>,
    tx: Token<Write>,
    Path((owner, name)): Path<(String, String)>,
    req: Bytes,
) -> Result<(StatusCode, Json<RepositoryResponse>), GHError<'static>> {
    let Some(user) = crate::github::auth_to_user(&tx, auth) else {
        return Err(Error::Unauthenticated(
            "You must be logged in to do that.",
        )
        .into_response(
            "guides",
            "getting-started-with-the-rest-api",
            "authentication",
        ));
    };

    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "repos",
            "forks",
            "create-a-fork",
        ));
    };

    // serde_json can parse `"{}"` to an empty object to default-fill, but `""`
    // is a straight up error, so need to handle that case
    let req = if req.is_empty() {
        CreateFork::default()
    } else {
        // because the json extractor requires an application/json content-type
        // and github does not (especially when the /forks body is empty)
        serde_json::from_slice::<CreateFork>(&req)
            // FIXME: error on invalid request body
            .map_err(|_| {
                Error::unprocessable("whatever", &[]).into_response(
                    "repos",
                    "forks",
                    "create-a-fork",
                )
            })?
    };

    let _org;
    let new_owner = if let Some(org) = req.organization {
        if let Some(u) = crate::model::users::get_user(&tx, &org) {
            if matches!(u.r#type, crate::model::users::Type::Organization) {
                _org = u;
                &_org
            } else {
                const DETAILS: &[GithubErrorDetails<'_>] =
                    &[Error::details("Fork", "organization", "invalid", "")];
                return Err(Error::Unprocessable(
                    format!(
                        "'{org}' is the login for a user account. \
                        You must pass the login for an organization account."
                    )
                    .into(),
                    DETAILS,
                )
                .into_response(
                    "repos",
                    "forks",
                    "create-a-fork",
                ));
            }
        } else {
            const DETAILS: &[GithubErrorDetails<'_>] =
                &[Error::details("Fork", "organization", "invalid", "")];
            return Err(Error::unprocessable("Validation Failed", DETAILS)
                .into_response("repos", "forks", "create-a-fork"));
        }
    } else {
        // since 2023-02-16 update (blog label innersource) forking to orgs doesn't dedup
        if let Some(existing) =
            crate::model::repos::find_fork(&tx, repo.id, user.id)
        {
            let repo = crate::model::repos::by_id(&tx, existing);
            return Ok((
                StatusCode::ACCEPTED,
                Json(repo.to_response(&tx, &st.root)),
            ));
        }
        &user
    };

    if crate::model::git::get_objects(&tx, repo.network).is_empty() {
        return Err(Error::Forbidden(
            "The repository exists, but it contains no Git content. Empty repositories cannot be forked."
        ).into_response("repos", "forks", "create-a-fork"));
    }

    // FIXME: does the transformation also happen if new_name is passed explicitely?
    // TODO: what happens when using org fork with an explicit name to an existing fork?
    let mut new_name = req.name.unwrap_or_else(|| repo.name.clone());
    // second, if there's already a repository of the same name (unrelated),
    // look for the next free name:
    while crate::model::repos::id_by_name(&tx, &new_owner.login, &new_name)
        .is_some()
    {
        let (prefix, counter) = new_name
            .rsplit_once('-')
            // - if the name ends with `-\d+`, increment the number
            .and_then(|(prefix, suffix)| {
                suffix.parse().ok().map(|n: usize| (prefix, n + 1))
            })
            // - otherwise append `-1`
            .unwrap_or((&new_name, 1));
        new_name = format!("{prefix}-{counter}");
    }

    let new_repo = crate::model::repos::create_repository(
        &tx,
        user.id,
        new_owner.id,
        &new_name,
        Some((repo.id, req.default_branch_only)),
    )
    .unwrap()
    .to_response(&tx, &st.root);
    tx.commit();

    // FIXME: this should be a FullRepositoryResponse, which has a few
    //        more fields (e.g. parent) than regular repository creation
    Ok((StatusCode::ACCEPTED, Json(new_repo)))
}

#[instrument(skip(st, tx))]
async fn list_hooks(
    State(st): State<St>,
    tx: Token<Read>,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Json<Vec<github_types::webhooks::Hook>>, GHError<'static>> {
    use crate::model::repos::{id_by_name, list_hooks};
    use github_types::webhooks::{Hook, LastResponse};
    let Some(repo) = id_by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "repos",
            "repos",
            "list-repository-webhooks",
        ));
    };

    let hooks = list_hooks(&tx, repo);
    Ok(Json(
        hooks
            .into_iter()
            .map(|h| Hook {
                r#type: "Repository".into(),
                id: h.id,
                name: "web".into(),
                active: h.active,
                events: h.events.into_iter().collect(),
                config: CreateHookConfig {
                    url: h.url.clone(),
                    content_type: h.content_type.into(),
                    secret: h.secret,
                    insecure_ssl: h.insecure_ssl,
                },
                created_at: String::new(),
                updated_at: String::new(),
                url: format!(
                    "{}/repos/{}/{}/hooks/{}",
                    st.root, owner, name, h.id
                ),
                test_url: format!(
                    "{}/repos/{}/{}/hooks/{}/test",
                    st.root, owner, name, h.id
                ),
                ping_url: format!(
                    "{}/repos/{}/{}/hooks/{}/pings",
                    st.root, owner, name, h.id
                ),
                deliveries_url: format!(
                    "{}/repos/{}/{}/hooks/{}/deliveries",
                    st.root, owner, name, h.id
                ),
                last_response: LastResponse {
                    code: h.last_response_code,
                    status: h.last_response_status,
                    message: h.last_response_message,
                },
            })
            .collect(),
    ))
}

#[instrument(skip(st, tx))]
async fn get_hook(
    State(st): State<St>,
    tx: Token<Read>,
    Path((owner, name, hook)): Path<(String, String, i64)>,
) -> Result<Json<github_types::webhooks::Hook>, GHError<'static>> {
    let Some(_) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "repos",
            "repos",
            "get-a-repository-webhook",
        ));
    };

    use github_types::webhooks::{Hook, LastResponse};
    // FIXME: should take the repo as input probably
    let h = crate::model::repos::get_hook(&tx, hook);
    Ok(Json(Hook {
        r#type: "Repository".into(),
        id: h.id,
        name: "web".into(),
        active: h.active,
        events: h.events.into_iter().collect(),
        config: CreateHookConfig {
            url: h.url.clone(),
            content_type: h.content_type.into(),
            secret: h.secret,
            insecure_ssl: h.insecure_ssl,
        },
        created_at: String::new(),
        updated_at: String::new(),
        url: format!("{}/repos/{}/{}/hooks/{}", st.root, owner, name, h.id),
        test_url: format!(
            "{}/repos/{}/{}/hooks/{}/test",
            st.root, owner, name, h.id
        ),
        ping_url: format!(
            "{}/repos/{}/{}/hooks/{}/pings",
            st.root, owner, name, h.id
        ),
        deliveries_url: format!(
            "{}/repos/{}/{}/hooks/{}/deliveries",
            st.root, owner, name, h.id
        ),
        last_response: LastResponse {
            code: h.last_response_code,
            status: h.last_response_status,
            message: h.last_response_message,
        },
    }))
}

#[instrument(skip(st, tx))]
async fn create_hook(
    State(st): State<St>,
    tx: Token<Write>,
    Path((owner, name)): Path<(String, String)>,
    Json(hook): Json<CreateHook>,
) -> Result<(StatusCode, Json<github_types::webhooks::Hook>), GHError<'static>>
{
    // TODO: error if hook.name != web
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "repos",
            "webhooks",
            "create-a-repository-webhook",
        ));
    };
    if hook.name != "web" {
        const DETAILS: &[GithubErrorDetails<'_>] =
            &[Error::details("Hook", "name", "invalid", "")];
        return Err(Error::unprocessable("Validation Failed", DETAILS)
            .into_response(
                "repos",
                "webhooks",
                "create-a-repository-webhook",
            ));
    }
    if hook.config.url.is_empty() {
        const DETAILS: &[GithubErrorDetails<'_>] = &[Error::details(
            "Hook",
            "url",
            "custom",
            "url cannot be blank",
        )];
        return Err(Error::unprocessable("Validation Failed", DETAILS)
            .into_response(
                "repos",
                "webhooks",
                "create-a-repository-webhook",
            ));
    }
    let mut conf = HookConfig {
        id: 0,
        active: hook.active,
        events: if hook.events.is_empty() {
            [HookEvent::Push].into()
        } else {
            hook.events.into_iter().collect()
        },
        content_type: hook.config.content_type,
        secret: hook.config.secret,
        url: hook.config.url,
        insecure_ssl: hook.config.insecure_ssl,
    };
    let Some(h) = crate::model::repos::create_hook(&tx, repo.id, &conf) else {
        const DETAILS: &[GithubErrorDetails<'_>] = &[Error::details(
            "Hook",
            "",
            "custom",
            "Hook already exists on this repository",
        )];
        return Err(Error::unprocessable("Validation Failed", DETAILS)
            .into_response(
                "repos",
                "webhooks",
                "create-a-repository-webhook",
            ));
    };
    conf.id = h.id;

    use github_types::webhooks::{Hook, LastResponse};
    let hook = Hook {
        r#type: "Repository".into(),
        id: h.id,
        name: "web".into(),
        active: h.active,
        events: h.events.into_iter().collect(),
        config: CreateHookConfig {
            url: h.url.clone(),
            content_type: h.content_type.into(),
            secret: h.secret,
            insecure_ssl: h.insecure_ssl,
        },
        created_at: String::new(),
        updated_at: String::new(),
        url: format!("{}/repos/{}/{}/hooks/{}", st.root, owner, name, h.id),
        test_url: format!(
            "{}/repos/{}/{}/hooks/{}/test",
            st.root, owner, name, h.id
        ),
        ping_url: format!(
            "{}/repos/{}/{}/hooks/{}/pings",
            st.root, owner, name, h.id
        ),
        deliveries_url: format!(
            "{}/repos/{}/{}/hooks/{}/deliveries",
            st.root, owner, name, h.id
        ),
        last_response: LastResponse {
            code: None,
            status: "unused".to_string().into(),
            message: None,
        },
    };
    let _ = st.webhooks.send((
        conf,
        Webhook {
            sender: SimpleUser::default(),
            repository: repo.to_response(&tx, &st.root),
            event: WebhookEvent::Ping {
                zen: String::new(),
                hook_id: h.id,
                hook: hook.clone(),
            },
        },
        Span::current(),
    ));
    tx.commit();

    Ok((StatusCode::CREATED, Json(hook)))
}

#[instrument(skip(st, tx))]
async fn update_hook(
    State(st): State<St>,
    tx: Token<Write>,
    Path((owner, name, hook_id)): Path<(String, String, i64)>,
    Json(update): Json<UpdateHook>,
) -> Result<Json<github_types::webhooks::Hook>, GHError<'static>> {
    let events = if !update.events.is_empty() {
        Some(update.events)
    } else if !update.add_events.is_empty() || !update.remove_events.is_empty()
    {
        let original_events =
            crate::model::repos::get_hook(&tx, hook_id).events;
        let mut updated_events = original_events
            .difference(&update.remove_events)
            .copied()
            .collect::<BTreeSet<_>>();
        updated_events.extend(update.add_events);
        (original_events != updated_events).then_some(updated_events)
    } else {
        None
    };

    if !crate::model::repos::update_hook(
        &tx,
        &owner,
        &name,
        hook_id,
        update.active,
        update.config.as_ref().and_then(|c| c.secret.as_deref()),
        events,
    ) {
        return Err(Error::NOT_FOUND.into_response(
            "repos",
            "webhooks",
            "update-a-repository-webhook",
        ));
    }

    use github_types::webhooks::{Hook, LastResponse};
    let h = crate::model::repos::get_hook(&tx, hook_id);
    let hook = Hook {
        r#type: "Repository".into(),
        id: h.id,
        name: "web".into(),
        active: h.active,
        events: h.events.into_iter().collect(),
        config: CreateHookConfig {
            url: h.url.clone(),
            content_type: h.content_type.into(),
            secret: h.secret,
            insecure_ssl: h.insecure_ssl,
        },
        created_at: String::new(),
        updated_at: String::new(),
        url: format!("{}/repos/{}/{}/hooks/{}", st.root, owner, name, h.id),
        test_url: format!(
            "{}/repos/{}/{}/hooks/{}/test",
            st.root, owner, name, h.id
        ),
        ping_url: format!(
            "{}/repos/{}/{}/hooks/{}/pings",
            st.root, owner, name, h.id
        ),
        deliveries_url: format!(
            "{}/repos/{}/{}/hooks/{}/deliveries",
            st.root, owner, name, h.id
        ),
        last_response: LastResponse {
            code: h.last_response_code,
            status: h.last_response_status,
            message: h.last_response_message,
        },
    };
    tx.commit();
    Ok(Json(hook))
}

#[instrument(skip(tx))]
async fn delete_hook(
    State(_): State<St>,
    tx: Token<Write>,
    Path((owner, name, hook_id)): Path<(String, String, i64)>,
) -> Result<StatusCode, GHError<'static>> {
    if crate::model::repos::delete_hook(&tx, &owner, &name, hook_id) {
        tx.commit();
        Ok(StatusCode::NO_CONTENT)
    } else {
        return Err(Error::NOT_FOUND.into_response(
            "repos",
            "webhooks",
            "delete-a-repository-webhook",
        ));
    }
}

fn default_page() -> usize {
    1
}
fn default_per_page() -> usize {
    30
}
#[derive(Deserialize, Debug)]
struct ListCommitQuery {
    sha: Option<String>,
    #[serde(default = "default_page")]
    page: usize,
    #[serde(default = "default_per_page")]
    per_page: usize,
}
#[instrument(skip(st, tx))]
async fn list_commits(
    State(st): State<St>,
    tx: Token<Read>,
    Path((owner, name)): Path<(String, String)>,
    Query(q): Query<ListCommitQuery>,
) -> Result<Json<Vec<CommitsResponse>>, GHError<'static>> {
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "repos",
            "repos",
            "list-commits",
        ));
    };

    // TODO: what happens if the requested ref does not exist?
    // FIXME: (IIRC) github sorts commits by date because it's a dummy
    let sha_or_branch = q.sha.as_ref().unwrap_or(&repo.default_branch);
    let sha_or_branch = gix_hash::ObjectId::from_hex(sha_or_branch.as_bytes())
        .ok()
        .or_else(|| {
            crate::model::git::refs::resolve(
                &tx,
                repo.id,
                &format!(
                    "refs/heads/{}",
                    sha_or_branch // can be of the form heads/<branch>
                        .trim_start_matches("refs/") // FIXME: test if that works on github
                        .trim_start_matches("heads/")
                ),
            )
        });
    let Some(oid) = sha_or_branch else {
        return Err(Error::NOT_FOUND.into_response(
            "repos",
            "repos",
            "list-commits",
        ));
    };

    let mut output = vec![];
    let mut oids = VecDeque::with_capacity(10);
    oids.push_back(oid);
    let mut seen = HashSet::new();
    seen.insert(oid);

    let mut commit_buf = Vec::new();
    while let Some(oid) = oids.pop_front() {
        commit_buf.clear();
        let (kind, data) =
            crate::model::git::get_in(&tx, repo.network, &oid, &mut commit_buf)
                .unwrap();
        assert_eq!(kind, gix_object::Kind::Commit);
        let commit = gix_object::CommitRef::from_bytes(data).unwrap();
        output.push(CommitsResponse::from(Bundle(
            &st, &tx, &owner, &name, &oid, &commit,
        )));
        for p in commit.parents() {
            if seen.insert(p) {
                oids.push_back(p);
            }
        }
    }
    Ok(Json(output))
}

/// Axum rejects overlapping routes, and github's commits endpoint(s) uses that
/// a lot:
///
/// - `commits/*ref` is a commit
/// - `commits/*ref/pulls` is the PRs associated with the commits
/// - `commits/*ref/status is the combined statuses for the ref
/// - `commits/*ref/statuses` is the individual statuses for the ref
///
/// This function serves as trampolines: by checking the `path`'s suffix it can
/// know which actual endpoint should be called
async fn commits_query(
    st: State<St>,
    tx: Token<Read>,
    Path((owner, name, path)): Path<(String, String, String)>,
) -> Result<Response, GHError<'static>> {
    if let Some(commit_ref) = path.strip_suffix("/status") {
        get_status(st, tx, Path((owner, name, commit_ref.to_string())))
            .await
            .map(|r| r.into_response())
    } else if let Some(_) = path.strip_suffix("/statuses") {
        todo!("List commit statuses for a reference")
    } else if let Some(_) = path.strip_suffix("/pulls") {
        todo!("List pull requests associated with a commit")
    } else if let Some(_) = path.strip_suffix("/comments") {
        todo!("List commit comments")
    } else if let Some(_) = path.strip_suffix("/branches-where-head") {
        todo!("List branches for HEAD commit")
    } else {
        get_commit(st, tx, Path((owner, name, path)))
            .await
            .map(|r| r.into_response())
    }
}

#[instrument(skip(st, tx))]
async fn get_commit(
    State(st): State<St>,
    tx: Token<Read>,
    Path((owner, name, commit_ref)): Path<(String, String, String)>,
) -> Result<Json<CommitsResponse>, GHError<'static>> {
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "commits",
            "commits",
            "get-a-commit",
        ));
    };

    let commit_ref = commit_ref.as_str();
    let oid =
        if let Ok(oid) = gix_hash::ObjectId::from_hex(commit_ref.as_bytes()) {
            oid
        } else {
            let commit_ref: Cow<'_, _> = if commit_ref.starts_with("refs/") {
                commit_ref.into()
            } else {
                // TODO: IIRC refs without the refs/ prefix behave oddly
                //       in gh but I don't remember how so directly alias
                //       them for now
                format!("refs/{commit_ref}").into()
            };
            if let Some(oid) =
                crate::model::git::refs::resolve(&tx, repo.id, &commit_ref)
            {
                oid
            } else {
                return Err(Error::NOT_FOUND.into_response(
                    "commits",
                    "commits",
                    "get-a-commit",
                ));
            }
        };

    let mut buf = Vec::new();
    let Some((kind, data)) =
        crate::model::git::get_in(&tx, repo.network, &oid, &mut buf)
    else {
        return Err(Error::NOT_FOUND.into_response(
            "commits",
            "commits",
            "get-a-commit",
        ));
    };

    if kind != gix_object::Kind::Commit {
        let msg = format!("No commit found for SHA: {commit_ref}");
        return Err(Error::Unprocessable(msg.into(), &[]).into_response(
            "commits",
            "commits",
            "get-a-commit",
        ));
    }
    let commit = gix_object::CommitRef::from_bytes(data).unwrap();

    Ok(Json(CommitsResponse::from(Bundle(
        &st, &tx, &owner, &name, &oid, &commit,
    ))))
}

#[instrument(skip(st, tx))]
async fn get_status(
    State(st): State<St>,
    tx: Token<Read>,
    Path((owner, name, commit_ref)): Path<(String, String, String)>,
) -> Result<Json<CombinedCommitStatus>, GHError<'static>> {
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "commits",
            "commits",
            "get-a-commit",
        ));
    };

    // FIXME: commit_ref can be a branch name (an actual ref)
    // TODO: is that what should happen for an invalid ref? Or am unknown commit?
    let Some(oid) = gix_hash::ObjectId::from_hex(commit_ref.as_bytes())
        .ok()
        .and_then(|oid| {
            crate::model::git::load(&tx, repo.network, &oid).map(|_| oid)
        })
    else {
        return Err(Error::NOT_FOUND.into_response(
            "repos",
            "repos",
            "get-the-combined-status-for-a-specific-reference",
        ));
    };

    let statuses = tx.get_statuses(repo.network, &oid);

    let state = if statuses.is_empty() {
        CombinedCommitStatusState::Pending
    } else {
        use CombinedCommitStatusState::*;
        statuses
            .iter()
            .fold(Success, |acc, st| match (acc, st.state) {
                // failure is final
                (Failure, _) => Failure,
                // any state combined with a failure is a failure
                (_, StatusState::Failure | StatusState::Error) => Failure,
                // pending is only overridden by failure
                (Pending, _) => Pending,
                (Success, StatusState::Pending) => Pending,
                (Success, StatusState::Success) => Success,
            })
    };

    Ok(Json(CombinedCommitStatus {
        sha: commit_ref,
        state,
        statuses,
        total_count: 0,
        repository: repo.to_response(&tx, &st.root),
        url: String::new(),
        commit_url: String::new(),
    }))
}

#[derive(Deserialize, Debug)]
struct GetContentsQuery {
    #[serde(rename = "ref")]
    refname: Option<String>,
}
#[instrument(skip(tx))]
async fn get_contents(
    tx: Token<Read>,
    headers: HeaderMap,
    Query(query): Query<GetContentsQuery>,
    Path((owner, name, path)): Path<(String, String, String)>,
) -> Result<Vec<u8>, GHError<'static>> {
    assert_eq!(headers["Accept"], "application/vnd.github.raw+json");

    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "repos",
            "repos",
            "get-repository-content",
        ));
    };

    // FIXME: path can lead to a tree, empty path lists the entries of the top-level tree
    // (oid | refname) > tree > blob
    let (_, blob) = query
        .refname
        .as_ref()
        .and_then(|r| gix_hash::ObjectId::from_hex(r.as_bytes()).ok())
        .or_else(|| {
            crate::model::git::refs::resolve(
                &tx,
                repo.id,
                &format!(
                    "refs/heads/{}",
                    query.refname.as_ref().unwrap_or(&repo.default_branch)
                ),
            )
        })
        .and_then(|oid| crate::model::git::load_tree(&tx, repo.network, &oid))
        .and_then(|entries| {
            crate::model::git::find_blob(&tx, repo.network, &path, entries)
        })
        .ok_or_else(|| {
            Error::NOT_FOUND.into_response(
                "repos",
                "repos",
                "get-repository-content",
            )
        })?;

    // FIXME: content-type?
    Ok(blob.data)
}

#[instrument(skip(st, tx))]
async fn create_or_update_contents(
    auth: Authorization,
    State(st): State<St>,
    tx: Token<Write>,
    Path((owner, name, path)): Path<(String, String, String)>,
    Json(request): Json<CreateContentsRequest>,
) -> Result<(StatusCode, Json<FileCommit>), GHError<'static>> {
    // TODO: is this the right error response?
    let Some(user) = auth_to_user(&tx, auth) else {
        return Err(Error::NOT_FOUND.into_response(
            "repos",
            "contents",
            "create-or-update-file-contents",
        ));
    };
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "repos",
            "contents",
            "create-or-update-file-contents",
        ));
    };

    // TODO: check what happens if giving github a ref (including prefix)
    let branch_name = request.branch.as_ref().unwrap_or(&repo.default_branch);
    let target_ref = format!("refs/heads/{branch_name}");
    let branch_head =
        crate::model::git::refs::resolve(&tx, repo.id, &target_ref);

    // GH only allows a branch which doesn't exist if the repository is empty
    if branch_head.is_none()
        && !crate::model::git::get_objects(&tx, repo.network).is_empty()
    {
        return Err(Error::NotFound(
            format!("Branch {branch_name} not found").into(),
        )
        .into_response(
            "repos",
            "contents",
            "create-or-update-file-contents",
        ));
    }
    // FIXME: this is probably the same shit as create_blob, but needs to verify
    let data = BASE64_STANDARD
        .decode(request.content)
        .expect("FIXME: what happens on invalid base64?");
    let data_size = data.len();
    let mut oid =
        crate::model::git::store(&tx, repo.network, gix_object::Blob { data });
    let file_oid = oid;
    let mut mode = gix_object::tree::EntryKind::Blob.into();
    // if we had a branch, we'd have to check if there was already a file at
    // the given path, and if so check what happens if the sha is missing or
    // incorrect
    if let Some(oid) = branch_head {
        let entries =
            crate::model::git::load_tree(&tx, repo.network, &oid).unwrap();
        // TODO: what if we find and object but it's not a blob?
        if let Some((oid, _)) =
            crate::model::git::find_blob(&tx, repo.network, &path, entries)
        {
            // TODO: what's the error?
            assert_eq!(
                Some(oid.to_string()),
                request.sha,
                "when modifying a blob, the old blob's hex must be provided"
            );
        }
    }

    // FIXME: need to lookup trees in order to create updated tree from them,
    //        so this has to go forwards to deref' the trees then back to zip
    //        them up
    for segment in path.as_str().rsplit('/') {
        oid = crate::model::git::store(
            &tx,
            repo.network,
            gix_object::Tree {
                entries: vec![gix_object::tree::Entry {
                    mode,
                    filename: segment.into(),
                    oid,
                }],
            },
        );
        mode = gix_object::tree::EntryKind::Tree.into();
    }

    let default_signature = Signature {
        name: user.login.as_ref().into(),
        // FIXME: email for default signature?
        email: user
            .email
            .as_ref()
            .map_or("user@example.org", Cow::as_ref)
            .into(),
        time: Time::now_utc(),
    };
    let mut parents = SmallVec::new();
    if let Some(h) = branch_head {
        parents.push(h);
    }
    let author = request
        .author
        .map_or_else(|| Ok(default_signature.clone()), |a| a.try_into())
        .map_err(|a| {
            Error::Unprocessable(
                format!(
                    "Invalid request.\n\n{} is not a valid date-time.",
                    a.date
                        .expect("a date parsing error implies we have a date"),
                )
                .into(),
                &[],
            )
            .into_response(
                "repos",
                "contents",
                "create-or-update-file-contents",
            )
        })?;

    let committer = request
        .committer
        .map_or_else(|| Ok(default_signature.clone()), |c| c.try_into())
        .map_err(|c| {
            Error::Unprocessable(
                format!(
                    "Invalid request.\n\n{} is not a valid date-time.",
                    c.date
                        .expect("a date parsing error implies we have a date"),
                )
                .into(),
                &[],
            )
            .into_response(
                "repos",
                "contents",
                "create-or-update-file-contents",
            )
        })?;

    let commit = gix_object::Commit {
        tree: oid,
        parents,
        author,
        committer,
        encoding: None,
        message: request.message.trim().into(),
        extra_headers: Vec::new(),
    };
    // oid is now the root tree
    let commit_oid = crate::model::git::store(&tx, repo.network, &commit);
    if let Some(h) = branch_head {
        if !crate::model::git::refs::update(
            &tx,
            &repo,
            &target_ref,
            &h,
            &commit_oid,
        ) {
            return Err(Error::Conflict(
                "Repository rule violations found\n\nCannot update this protected ref.\n\n",
                Some(serde_json::Value::Object(Default::default())),
            ).into_response(
                "repos",
                "contents",
                "create-or-update-file-contents",
            ));
        };
    } else {
        if !crate::model::git::refs::create(
            &tx,
            &repo,
            &target_ref,
            &commit_oid,
        ) {
            return Err(Error::Conflict(
                "Repository rule violations found\n\nCannot create ref due to creations being restricted.\n\n",
                Some(serde_json::Value::Object(Default::default())),
            ).into_response(
                "repos",
                "contents",
                "create-or-update-file-contents",
            ));
        };
        // baseline init (calling endpoint on an empty repository) => reset the
        // default branch of the repository to whichever branch was used here
        // (nb: re-setting to default branch if none was provided but shrug)
        if let Some(b) = request.branch {
            crate::model::repos::update_repository(
                &tx,
                repo.id,
                None,
                Some(&b),
            );
        }
    }
    tx.commit();

    let mut time_buf = Default::default();
    // replies with 200 for an update (?) and 201 for
    // a create as well as file-commit information
    Ok((
        StatusCode::CREATED,
        Json(FileCommit {
            content: Content {
                // `name` is the last segment of `path`...
                name: path.rsplit('/').next().unwrap().to_string(),
                path: path.to_owned(),
                sha: file_oid.to_string(),
                size: data_size,
                r#type: ContentType::File,
                url: None,
                download_url: None,
                git_url: None,
                html_url: None,
            },
            commit: Commit {
                sha: commit_oid.to_string(),
                node_id: None,
                message: String::from_utf8_lossy(commit.message.trim())
                    .to_string(),
                tree: Tree {
                    sha: oid.to_string(),
                    url: None,
                },
                parents: commit
                    .parents
                    .into_iter()
                    .map(|sha| CommitLink {
                        sha: sha.to_string(),
                        url: format!(
                            "{}/repos/{}/{}/git/commits/{}",
                            st.root, owner, name, sha
                        ),
                        html_url: None,
                    })
                    .collect(),
                author: Some(commit.author.to_ref(&mut time_buf).into()),
                committer: Some(commit.committer.to_ref(&mut time_buf).into()),
                url: format!(
                    "{}/repos/{}/{}/git/commits/{}",
                    st.root, owner, name, commit_oid
                ),
                html_url: None,
            },
        }),
    ))
}

#[instrument(skip(st, tx))]
async fn create_status(
    auth: Authorization,
    State(st): State<St>,
    tx: Token<Write>,
    Path((owner, name, commit)): Path<(String, String, String)>,
    Json(CreateStatusGarbage {
        context,
        state,
        target_url,
        description,
    }): Json<CreateStatusGarbage>,
) -> Result<Json<CreateStatusResponse>, GHError<'static>> {
    let creator = crate::github::auth_to_user(&tx, auth).unwrap();
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "commits",
            "statuses",
            "create-a-commit-status",
        ));
    };

    // because warp doesn't %-decode path fragments (seanmonstar/warp#242)
    let commit =
        percent_encoding::percent_decode_str(&commit).decode_utf8_lossy();

    let Some(c) = gix_hash::ObjectId::from_hex(commit.as_bytes())
        .ok()
        .filter(|c| {
            crate::model::git::load(&tx, repo.network, c).map(|o| o.kind())
                == Some(gix_object::Kind::Commit)
        })
        .and_then(|c| crate::model::git::get(&tx, repo.network, &c))
    else {
        return Err(Error::Unprocessable(
            format!("No commit found for SHA: {commit}").into(),
            &[],
        )
        .into_response("commits", "statuses", "create-a-commit-status"));
    };

    let Ok(state) = state.as_str().try_into() else {
        return Err(Error::UnprocessableValue(
            "Validation Failed".into(),
            "Validation failed: State is not included in the list".into(),
        )
        .into_response("commits", "statuses", "create-a-commit-status"));
    };

    if context.is_empty() {
        return Err(Error::UnprocessableValue(
            "Validation Failed".into(),
            "Validation failed: Context can't be blank".into(),
        )
        .into_response("commits", "statuses", "create-a-commit-status"));
    }

    let id = *crate::model::create_status(
        &tx,
        c,
        state,
        &context,
        target_url.as_deref(),
        description.as_deref(),
    );

    use github_types::webhooks::Status;
    send_hook(&tx, repo, &st, HookEvent::Status, &creator, || {
        WebhookEvent::Status(Status {
            sha: commit.to_string(),
            state,
            context: context.clone(),
            description: description.clone(),
            target_url: target_url.clone(),
        })
    });

    tx.commit();

    Ok(Json(CreateStatusResponse {
        id,
        context,
        state,
        description,
        target_url,
        creator: None,
    }))
}

#[instrument(skip(st, tx))]
async fn create_branch_merge(
    auth: Authorization,
    State(st): State<St>,
    tx: Token<Write>,
    Path((owner, name)): Path<(String, String)>,
    Json(req): Json<CreateBranchMerge>,
) -> Result<(StatusCode, Json<CommitsResponse>), Response> {
    let Some(user) = auth_to_user(&tx, auth) else {
        return Err(Error::Forbidden("")
            .into_response("branches", "branches", "merge-a-branch")
            .into_response());
    };
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND
            .into_response("branches", "branches", "merge-a-branch")
            .into_response());
    };

    let base_ref = format!("refs/heads/{}", req.base);
    let Some(base) = crate::model::git::refs::resolve(&tx, repo.id, &base_ref)
    else {
        return Err(Error::NOT_FOUND
            .into_response("branches", "branches", "merge-a-branch")
            .into_response());
    };

    // `head` can be either a sha1 or a branchname
    let head = if let Ok(h) = gix_hash::ObjectId::from_hex(req.head.as_bytes())
    {
        let Some(object) = crate::model::git::load(&tx, repo.network, &h)
        else {
            return Err(Error::NOT_FOUND
                .into_response("branches", "branches", "merge-a-branch")
                .into_response());
        };
        if object.kind() != gix_object::Kind::Commit {
            return Err(Error::unprocessable("", &[])
                .into_response("branches", "branches", "merge-a-branch")
                .into_response());
        }
        h
    } else if let Some(h) = crate::model::git::refs::resolve(
        &tx,
        repo.id,
        &format!("refs/heads/{}", req.head),
    ) {
        h
    } else {
        return Err(Error::NOT_FOUND
            .into_response("branches", "branches", "merge-a-branch")
            .into_response());
    };

    // TODO:
    // - what happens for a fast forward merge? What is returned?
    // - what's the response if the oids are not commits?
    let author = Signature {
        name: user.login.as_ref().into(),
        email: user
            .email
            .as_ref()
            .map_or("user@example.org", Cow::as_ref)
            .into(),
        time: Time::now_utc(),
    };
    // don't ask...
    let committer = Signature {
        name: "GitHub".into(),
        email: "noreply@github.com".into(),
        time: Time::now_utc(),
    };
    let m = crate::model::git::merge(
        &tx,
        repo.network,
        req.commit_message.as_ref().map_or_else(
            || format!("Merge {} into {}", req.head, req.base),
            |s| s.trim().to_string(),
        ),
        &base,
        &head,
        author,
        committer,
    );
    let mut buf = Vec::new();
    let (oid, commit) = if let Ok(oid) = m {
        let f = ReferenceFinder::new(&tx, &owner, &repo.name);

        crate::model::git::refs::set(&tx, repo.id, &base_ref, &oid);
        let (kind, data) =
            crate::model::git::get_in(&tx, repo.network, &oid, &mut buf)
                .unwrap();
        assert_eq!(kind, gix_object::Kind::Commit);
        let commit = gix_object::CommitRef::from_bytes(data).unwrap();

        // FIXME: technically should probably be hooked onto the updates to the default branch...
        if req.base == repo.default_branch {
            if let Some(m) = req.commit_message {
                f.find_issues(m.as_bytes()).for_each(|id| {
                    crate::model::prs::update(&tx, id)
                        .state(crate::model::prs::State::Closed)
                        .call();
                });
            }
            // FIXME: should really actually probably be any commit of the branch being merged?
            if let Some(pr) = crate::model::prs::find_by_head(&tx, &head) {
                // TODO: check if this shouldn't be merged
                use crate::model::prs::State::Closed;
                crate::model::prs::update(&tx, pr).state(Closed).call();
                let pr = crate::model::prs::get_pr(&tx, pr);
                if let Some(description) = pr.issue.body {
                    f.find_issues(description.as_bytes()).for_each(|id| {
                        crate::model::prs::update(&tx, id)
                            .state(crate::model::prs::State::Closed)
                            .call();
                    });
                }
            }
            use crate::model::git::*;
            let merge_base = find_merge_base(&tx, repo.network, &base, &head);
            for commit in log(&tx, repo.network, &head)
                .unwrap()
                .take_while(|&oid| Some(oid) != merge_base)
                .filter_map(|oid| {
                    load(&tx, repo.network, &oid)?.try_into_commit().ok()
                })
            {
                f.find_issues(&commit.message).for_each(|id| {
                    crate::model::prs::update(&tx, id)
                        .state(crate::model::prs::State::Closed)
                        .call();
                });
            }
        }

        tx.commit();

        (oid, commit)
    } else {
        return Err((
            StatusCode::CONFLICT,
            Json(GithubError {
                status: "409".into(),
                message: "Merge Conflict".into(),
                documentation_url: "https://docs.github.com/rest/branches/branches#merge-a-branch" ,
                errors: either::Right(&[]),
                metadata: None,
            })
        ).into_response());
    };

    let tx = Token::<Read>::get().await.unwrap();
    Ok((
        StatusCode::CREATED,
        Json(CommitsResponse::from(Bundle(
            &st, &tx, &owner, &name, &oid, &commit,
        ))),
    ))
}

#[instrument]
async fn create_deployment() -> (StatusCode, Json<Deployment>) {
    (StatusCode::CREATED, Json(Deployment { id: 1 }))
}

#[instrument]
async fn create_deployment_status() -> StatusCode {
    StatusCode::CREATED
}

async fn list_branches(
    State(st): State<St>,
    tx: Token<Read>,
    Path((owner, name)): Path<(String, String)>,
) -> Result<
    Json<Vec<github_types::branches::BranchWithProtection>>,
    GHError<'static>,
> {
    // FIXME: pagination
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "branches",
            "branches",
            "list-branches",
        ));
    };

    let mut response = Vec::new();
    let mut buf = Vec::new();
    let mut err = None;
    crate::model::git::refs::list(&tx, repo.id, |refname, oid| {
        if err.is_some() {
            return;
        }
        let Some(branch_name) = refname.strip_prefix("refs/heads/") else {
            return;
        };

        buf.clear();
        let Some((kind, data)) =
            crate::model::git::get_in(&tx, repo.network, oid, &mut buf)
        else {
            err = Some(Error::NOT_FOUND);
            return;
        };

        if kind != gix_object::Kind::Commit {
            let msg = format!("No commit found for SHA: {branch_name}");
            err = Some(Error::Unprocessable(msg.into(), &[]));
            return;
        }

        let commit = gix_object::CommitRef::from_bytes(data).unwrap();
        response.push(github_types::branches::BranchWithProtection {
            name: branch_name.into(),
            commit: CommitsResponse::from(Bundle(
                &st, &tx, &owner, &name, oid, &commit,
            )),
        });
    });

    if let Some(err) = err {
        return Err(err.into_response("branches", "branches", "list-branches"));
    }

    Ok(Json(response))
}

async fn get_branch(
    State(st): State<St>,
    tx: Token<Read>,
    Path((owner, name, branch_name)): Path<(String, String, String)>,
) -> Result<Json<github_types::branches::BranchWithProtection>, GHError<'static>>
{
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "branches",
            "branches",
            "get-a-branch",
        ));
    };

    let branch_ref = format!("refs/heads/{branch_name}");
    let Some(oid) = crate::model::git::refs::resolve(&tx, repo.id, &branch_ref)
    else {
        return Err(Error::NOT_FOUND.into_response(
            "branches",
            "branches",
            "get-a-branch",
        ));
    };

    let mut buf = Vec::new();
    let Some((kind, data)) =
        crate::model::git::get_in(&tx, repo.network, &oid, &mut buf)
    else {
        return Err(Error::NOT_FOUND.into_response(
            "branches",
            "branches",
            "get-a-branch",
        ));
    };

    // FIXME: is this the right error?
    if kind != gix_object::Kind::Commit {
        let msg = format!("No commit found for SHA: {branch_ref}");
        return Err(Error::Unprocessable(msg.into(), &[]).into_response(
            "branches",
            "branches",
            "get-a-branch",
        ));
    }
    let commit = gix_object::CommitRef::from_bytes(data).unwrap();

    Ok(Json(github_types::branches::BranchWithProtection {
        name: branch_name,
        commit: CommitsResponse::from(Bundle(
            &st, &tx, &owner, &name, &oid, &commit,
        )),
    }))
}

#[derive(Deserialize)]
struct UpdateBranchProtection {}
async fn update_branch_protection() {}
