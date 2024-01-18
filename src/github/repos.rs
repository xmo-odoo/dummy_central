use std::borrow::Cow;
use std::collections::{HashSet, VecDeque};
use std::convert::TryInto;

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post, put};
use axum::{Json, Router};
use base64::prelude::{Engine as _, BASE64_STANDARD};
use bytes::Bytes;
use git_actor::{Signature, Time};
use git_object::bstr::ByteSlice;
use http::StatusCode;
use serde::Deserialize;
use smallvec::SmallVec;
use tracing::instrument;

use github_types::repos::*;
use github_types::webhooks::{Webhook, WebhookEvent};

use super::{GHError, HookConfig};
use crate::github::{
    auth_to_user, Authorization, Config, Error, GithubError,
    GithubErrorDetails, SimpleUser, St,
};
use crate::model::{Source, Token};

pub mod git;
pub mod git_protocol;
pub mod issues;

// TODO: make WebhookEvent clonable instead? idk
pub fn send_hook<E: Fn() -> WebhookEvent>(
    tx: &Token<'_>,
    repo: crate::model::repos::Repository,
    st: &Config,
    hook_type: HookEvent,
    sender: &super::User,
    event: E,
) {
    for hook in crate::model::repos::list_hooks(tx, repo.id) {
        if hook.active && hook.events.iter().any(|e| e.eq(hook_type.as_str())) {
            let _ = st.webhooks.send((
                HookConfig {
                    id: hook.id,
                    active: hook.active,
                    url: hook.url,
                    content_type: hook.content_type.into(),
                    events: hook
                        .events
                        .into_iter()
                        .map(|e| e.parse().unwrap())
                        .collect(),
                    secret: hook.secret.unwrap_or_default(),
                },
                Webhook {
                    sender: sender.to_simple(&st.root),
                    repository: repo.to_response(tx, &st.root),
                    event: event(),
                },
            ));
        }
    }
}

struct Bundle<'r, 's: 'r>(
    &'r crate::github::Config,
    &'r str,
    &'r str,
    &'r git_hash::oid,
    &'r git_object::CommitRef<'s>,
);
impl<'r, 's> From<Bundle<'r, 's>> for CommitsResponse {
    fn from(
        Bundle(st, owner, name, oid, commit): Bundle<'r, 's>,
    ) -> CommitsResponse {
        let mut db = Source::get();
        let tx = &db.token();
        // FIXME: users are not correct, I *think* the match should actually be
        //        between the committer email and one of the user's emails (
        //        public or private) for UI attribution, and that's why it's
        //        possible for the user not to be found... maybe
        let committer = if commit.committer.name.as_bytes() == b"GitHub" {
            Some(SimpleUser::for_login(&st.root, "web-flow".into()))
        } else {
            crate::model::users::get_user(
                tx,
                &commit.committer.name.to_string(),
            )
            .map(|u| u.to_simple(&st.root))
        };
        Self {
            node_id: String::new(),
            sha: oid.to_string(),
            commit: CommitsResponseCommit {
                tree: Tree {
                    sha: commit.tree().to_hex().to_string(),
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
                    sha: oid.to_hex().to_string(),
                    url: None,
                    html_url: None,
                })
                .collect(),
            url: format!(
                "{}/repos/{}/{}/commits/{}",
                st.root, owner, name, oid
            ),
            comments_url: String::new(),
            html_url: String::new(),
            author: crate::model::users::get_user(
                tx,
                &commit.author.name.to_string(),
            )
            .map(|u| u.to_simple(&st.root)),
            committer,
        }
    }
}

#[rustfmt::skip]
pub fn routes() -> Router<St> {
    Router::new()
        .nest(
            "/repos/:owner/:name",
            Router::new()
                .route(
                    "/",
                    get(get_repository)
                    .patch(update_repository)
                    .delete(delete_repository)
                )
                .route("/forks", post(create_fork))
                .route("/hooks", get(list_hooks).post(create_hook))
                .route("/hooks/:id", patch(update_hook).delete(delete_hook))
                .route("/branches/:name", get(get_branch))
                .route("/branches/:name/protection", put(update_branch_protection))
                .route("/commits", get(list_commits))
                .route("/commits/*rest", get(commits_query))
                .route("/contents/*path", put(create_or_update_contents))
                .route("/statuses/:hash", post(create_status))
                .route("/merges", post(create_branch_merge))
                .route("/deployments", post(create_deployment))
                .route("/deployments/:id/statuses", post(create_deployment_status))
                .route("/collaborators", get(list_collaborators))
                .route("/collaborators/:login", put(add_collaborator))
                .merge(issues::routes())
                .nest("/git", git::routes())
        )
        .nest("/:owner/:name", git_protocol::routes())
}

#[instrument(skip(st), err(Debug))]
async fn get_repository(
    State(st): State<St>,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Json<RepositoryResponse>, GHError<'static>> {
    let mut db = Source::get();
    let tx = &db.token();

    match crate::model::repos::by_name(tx, &owner, &name) {
        Some(repo) => Ok(Json(repo.to_response(tx, &st.root))),
        None => Err(Error::NOT_FOUND.into_response(
            "repos",
            "repos",
            "get-a-repository",
        )),
    }
}

#[instrument(skip(st), err(Debug))]
async fn update_repository(
    State(st): State<St>,
    Path((owner, name)): Path<(String, String)>,
    Json(updates): Json<UpdateRepository>,
) -> Result<Json<RepositoryResponse>, Response> {
    let mut db = Source::get();
    let tx = db.token_eager();

    let Some(rid) = crate::model::repos::id_by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND
            .into_response("repos", "repos", "update-a-repository")
            .into_response());
    };

    // TODO: does the default branch need to exist?
    // TODO: what if we rename & change default branch but the branch doesn't exist? Or the reverse?
    if let Some(d) = &updates.default_branch {
        if crate::model::git::refs::resolve(
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
    tx.commit().unwrap();

    Ok(Json(response))
}

#[instrument(err(Debug))]
async fn delete_repository(
    State(_): State<St>,
    Path((owner, name)): Path<(String, String)>,
) -> Result<StatusCode, GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token_eager();

    // FIXME: ACL to delete a repo
    if let Some(repo_id) = crate::model::repos::id_by_name(&tx, &owner, &name) {
        crate::model::repos::delete(&tx, repo_id);
        tx.commit().unwrap();
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(Error::NOT_FOUND.into_response(
            "repos",
            "repos",
            "delete-a-repository",
        ))
    }
}

#[instrument(skip(st), err(Debug))]
async fn create_fork(
    auth: Authorization,
    State(st): State<St>,
    Path((owner, name)): Path<(String, String)>,
    req: Bytes,
) -> Result<(StatusCode, Json<RepositoryResponse>), GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token_eager();
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

    // because the json extractor requires an application/json content-type
    // and github does not (especially when the /forks body is empty)
    let org = serde_json::from_slice::<CreateFork>(&req)
        .ok()
        .and_then(|r| r.organization);

    let _org;
    let new_owner = if let Some(org) = org {
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
        &user
    };

    if crate::model::git::get_objects(&tx, repo.network).is_empty() {
        return Err(Error::Forbidden(
            "The repository exists, but it contains no Git content. Empty repositories cannot be forked."
        ).into_response("repos", "forks", "create-a-fork"));
    }

    // if the prospective new owner already has a fork (or source,
    // same diff), return that directly
    // FIXME: not the case anymore for organisations (cf 2023-02-16 update,
    //        github blob label innersource)
    if let Some(existing) =
        crate::model::repos::find_fork(&tx, repo.id, new_owner.id)
    {
        let repo = crate::model::repos::by_id(&tx, existing);
        return Ok((
            StatusCode::ACCEPTED,
            Json(repo.to_response(&tx, &st.root)),
        ));
    }

    let mut new_name = repo.name.clone();
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
        Some(repo.id),
    )
    .unwrap()
    .to_response(&tx, &st.root);
    tx.commit().unwrap();

    // FIXME: this should be a FullRepositoryResponse, which has a few
    //        more fields (e.g. parent) than regular repository creation
    Ok((StatusCode::ACCEPTED, Json(new_repo)))
}

#[instrument(skip(st), err(Debug))]
async fn list_hooks(
    State(st): State<St>,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Json<Vec<github_types::webhooks::Hook>>, GHError<'static>> {
    use crate::model::repos::{id_by_name, list_hooks};
    use github_types::webhooks::{Hook, LastResponse};
    let mut db = Source::get();
    let tx = &db.token();
    let Some(repo) = id_by_name(tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "repos",
            "repos",
            "list-repository-webhooks",
        ));
    };

    let hooks = list_hooks(tx, repo);
    Ok(Json(
        hooks
            .into_iter()
            .map(|h| Hook {
                r#type: "Repository".into(),
                id: h.id,
                url: format!(
                    "{}/repos/{}/{}/hooks/{}",
                    st.root, owner, name, h.id
                ),
                name: "web".into(),
                active: h.active,
                events: h
                    .events
                    .into_iter()
                    .map(|e| e.parse().unwrap())
                    .collect(),
                config: CreateHookConfig {
                    url: h.url.clone(),
                    content_type: h.content_type.into(),
                    secret: h.secret.unwrap_or_default(),
                    insecure_ssl: true,
                },
                created_at: String::new(),
                updated_at: String::new(),
                test_url: String::new(),
                ping_url: String::new(),
                deliveries_url: None,
                app_id: None,
                last_response: LastResponse {
                    code: None,
                    status: None,
                    message: None,
                },
            })
            .collect(),
    ))
}

#[instrument(skip(st), err(Debug))]
async fn create_hook(
    State(st): State<St>,
    Path((owner, name)): Path<(String, String)>,
    Json(hook): Json<CreateHook>,
) -> Result<(StatusCode, Json<github_types::webhooks::Hook>), GHError<'static>>
{
    let mut db = Source::get();
    let tx = db.token_eager();

    // TODO: error if hook.name != web
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "repos",
            "repos",
            "create-a-repository-webhook",
        ));
    };
    let mut conf = HookConfig {
        id: 0,
        active: hook.active,
        events: hook.events.into_iter().collect(),
        content_type: hook.config.content_type,
        secret: hook.config.secret,
        url: hook.config.url,
    };
    let h = crate::model::repos::create_hook(&tx, repo.id, &conf);
    conf.id = h.id;

    use github_types::webhooks::{Hook, LastResponse};
    let hook = Hook {
        r#type: "Repository".into(),
        id: h.id,
        url: format!("{}/repos/{}/{}/hooks/{}", st.root, owner, name, h.id),
        name: "web".into(),
        active: h.active,
        events: h.events.into_iter().map(|e| e.parse().unwrap()).collect(),
        config: CreateHookConfig {
            url: h.url.clone(),
            content_type: h.content_type.into(),
            secret: h.secret.unwrap_or_default(),
            insecure_ssl: true,
        },
        created_at: String::new(),
        updated_at: String::new(),
        test_url: String::new(),
        ping_url: String::new(),
        deliveries_url: None,
        app_id: None,
        last_response: LastResponse {
            code: None,
            status: None,
            message: None,
        },
    };
    let _ = st.webhooks.send((
        conf,
        Webhook {
            sender: Default::default(),
            repository: repo.to_response(&tx, &st.root),
            event: WebhookEvent::Ping {
                zen: String::new(),
                hook_id: h.id,
                hook: hook.clone(),
            },
        },
    ));
    tx.commit().unwrap();

    Ok((StatusCode::CREATED, Json(hook)))
}

#[instrument(skip(st), err(Debug))]
async fn update_hook(
    State(st): State<St>,
    Path((owner, name, hook_id)): Path<(String, String, i64)>,
    Json(update): Json<UpdateHook>,
) -> Result<Json<github_types::webhooks::Hook>, StatusCode> {
    let mut db = Source::get();
    let tx = db.token_eager();

    // FIXME: what if hook and repo don't match?
    // TODO: is hook_id per repo?
    if !crate::model::repos::update_hook(
        &tx,
        hook_id,
        update.active,
        update.config.as_ref().and_then(|c| c.secret.as_deref()),
    ) {
        return Err(StatusCode::NOT_FOUND);
    }

    use github_types::webhooks::{Hook, LastResponse};
    let h = crate::model::repos::get_hook(&tx, hook_id);
    let hook = Hook {
        r#type: "Repository".into(),
        id: h.id,
        url: format!("{}/repos/{}/{}/hooks/{}", st.root, owner, name, h.id),
        name: "web".into(),
        active: h.active,
        events: h.events.into_iter().map(|e| e.parse().unwrap()).collect(),
        config: CreateHookConfig {
            url: h.url.clone(),
            content_type: h.content_type.into(),
            secret: h.secret.unwrap_or_default(),
            insecure_ssl: true,
        },
        created_at: String::new(),
        updated_at: String::new(),
        test_url: String::new(),
        ping_url: String::new(),
        deliveries_url: None,
        app_id: None,
        last_response: LastResponse {
            code: None,
            status: None,
            message: None,
        },
    };
    tx.commit().unwrap();
    Ok(Json(hook))
}

#[instrument(err(Debug))]
async fn delete_hook(
    State(_): State<St>,
    Path((owner, name, hook_id)): Path<(String, String, i64)>,
) -> Result<StatusCode, StatusCode> {
    let mut db = Source::get();
    let tx = db.token();

    if crate::model::repos::delete_hook(&tx, hook_id) {
        tx.commit().unwrap();
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(StatusCode::NOT_FOUND)
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
#[instrument(skip(st), err(Debug))]
async fn list_commits(
    State(st): State<St>,
    Path((owner, name)): Path<(String, String)>,
    Query(q): Query<ListCommitQuery>,
) -> Result<Json<Vec<CommitsResponse>>, GHError<'static>> {
    let mut db = Source::get();
    let tx = &db.token();

    let Some(repo) = crate::model::repos::by_name(tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "repos",
            "repos",
            "list-commits",
        ));
    };

    // TODO: what happens if the requested ref does not exist?
    // FIXME: (IIRC) github sorts commits by date because it's a dummy
    let sha_or_branch = q.sha.as_ref().unwrap_or(&repo.default_branch);
    let sha_or_branch = git_hash::ObjectId::from_hex(sha_or_branch.as_bytes())
        .ok()
        .or_else(|| {
            crate::model::git::refs::resolve(
                tx,
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
            crate::model::git::get_in(tx, repo.network, &oid, &mut commit_buf)
                .unwrap();
        assert_eq!(kind, git_object::Kind::Commit);
        let commit = git_object::CommitRef::from_bytes(data).unwrap();
        output.push(CommitsResponse::from(Bundle(
            &st, &owner, &name, &oid, &commit,
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
    Path((owner, name, path)): Path<(String, String, String)>,
) -> Result<Response, GHError<'static>> {
    if let Some(commit_ref) = path.strip_suffix("/status") {
        return get_status(st, Path((owner, name, commit_ref.to_string())))
            .await
            .map(|r| r.into_response());
    }

    get_commit(st, Path((owner, name, path)))
        .await
        .map(|r| r.into_response())
}

#[instrument(skip(st), err(Debug))]
async fn get_commit(
    State(st): State<St>,
    Path((owner, name, commit_ref)): Path<(String, String, String)>,
) -> Result<Json<CommitsResponse>, GHError<'static>> {
    let mut db = Source::get();
    let tx = &db.token();

    let Some(repo) = crate::model::repos::by_name(tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "commits",
            "commits",
            "get-a-commit",
        ));
    };

    let commit_ref = commit_ref.as_str();
    let oid =
        if let Ok(oid) = git_hash::ObjectId::from_hex(commit_ref.as_bytes()) {
            oid
        } else {
            let commit_ref: Cow<'_, _> = if !commit_ref.starts_with("refs/") {
                // TODO: IIRC refs without the refs/ prefix behave oddly
                //       in gh but I don't remember how so directly alias
                //       them for now
                format!("refs/{commit_ref}").into()
            } else {
                commit_ref.into()
            };
            if let Some(oid) =
                crate::model::git::refs::resolve(tx, repo.id, &commit_ref)
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
        crate::model::git::get_in(tx, repo.network, &oid, &mut buf)
    else {
        return Err(Error::NOT_FOUND.into_response(
            "commits",
            "commits",
            "get-a-commit",
        ));
    };

    if kind != git_object::Kind::Commit {
        let msg = format!("No commit found for SHA: {commit_ref}");
        return Err(Error::Unprocessable(msg.into(), &[]).into_response(
            "commits",
            "commits",
            "get-a-commit",
        ));
    }
    let commit = git_object::CommitRef::from_bytes(data).unwrap();

    Ok(Json(CommitsResponse::from(Bundle(
        &st, &owner, &name, &oid, &commit,
    ))))
}

#[instrument(skip(st), err(Debug))]
async fn get_status(
    State(st): State<St>,
    Path((owner, name, commit_ref)): Path<(String, String, String)>,
) -> Result<Json<CombinedCommitStatus>, GHError<'static>> {
    let mut db = Source::get();
    let tx = &db.token();

    let Some(repo) = crate::model::repos::by_name(tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "commits",
            "commits",
            "get-a-commit",
        ));
    };

    // FIXME: commit_ref can be a branch name (an actual ref)
    // TODO: is that what should happen for an invalid ref? Or am unknown commit?
    let Some(oid) = git_hash::ObjectId::from_hex(commit_ref.as_bytes())
        .ok()
        .and_then(|oid| {
            crate::model::git::load(tx, repo.network, &oid).map(|_| oid)
        })
    else {
        return Err(Error::NOT_FOUND.into_response(
            "repos",
            "repos",
            "get-the-combined-status-for-a-specific-reference",
        ));
    };

    let statuses = crate::model::repos::get_statuses(tx, repo.network, &oid);

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
        repository: repo.to_response(tx, &st.root),
        url: String::new(),
        commit_url: String::new(),
    }))
}

#[instrument(skip(st), err(Debug))]
async fn create_or_update_contents(
    auth: Authorization,
    State(st): State<St>,
    Path((owner, name, path)): Path<(String, String, String)>,
    Json(request): Json<CreateContentsRequest>,
) -> Result<(StatusCode, Json<FileCommit>), GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token_eager();
    // TODO: is this the right error response?
    let Some(user) = auth_to_user(&tx, auth) else {
        return Err(Error::NOT_FOUND.into_response(
            "repos",
            "repos",
            "create-or-update-file-contents",
        ));
    };
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "repos",
            "repos",
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
            "repos",
            "create-or-update-file-contents",
        ));
    }
    // FIXME: this is probably the same shit as create_blob, but needs to verify
    let data = BASE64_STANDARD
        .decode(request.content)
        .expect("FIXME: what happens on invalid base64?");
    let data_size = data.len();
    let mut oid =
        crate::model::git::store(&tx, repo.network, git_object::Blob { data });
    let file_oid = oid;
    let mut mode = git_object::tree::EntryMode::Blob;
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
                Some(oid.to_hex().to_string()),
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
            git_object::Tree {
                entries: vec![git_object::tree::Entry {
                    mode,
                    filename: segment.into(),
                    oid,
                }],
            },
        );
        mode = git_object::tree::EntryMode::Tree;
    }

    let default_signature = Signature {
        name: user.login.as_ref().into(),
        // FIXME: email for default signature?
        email: user
            .email
            .as_ref()
            .map(Cow::as_ref)
            .unwrap_or("user@example.org")
            .into(),
        time: Time::now_utc(),
    };
    let mut parents = SmallVec::new();
    if let Some(h) = branch_head {
        parents.push(h);
    }
    let commit = git_object::Commit {
        tree: oid,
        parents,
        author: request
            .author
            .map_or_else(|| default_signature.clone(), Into::into),
        committer: request.committer.map_or(default_signature, Into::into),
        encoding: None,
        message: request.message.trim().into(),
        extra_headers: Vec::new(),
    };
    // oid is now the root tree
    let commit_oid = crate::model::git::store(&tx, repo.network, &commit);
    if let Some(h) = branch_head {
        crate::model::git::refs::update(
            &tx,
            repo.id,
            &target_ref,
            &h,
            &commit_oid,
        );
    } else {
        crate::model::git::refs::create(&tx, repo.id, &target_ref, &commit_oid);
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
    tx.commit().unwrap();

    // replies with 200 for an update (?) and 201 for
    // a create as well as file-commit information
    Ok((
        StatusCode::CREATED,
        Json(FileCommit {
            content: Content {
                // `name` is the last segment of `path`...
                name: path.rsplit('/').next().unwrap().to_string(),
                path: path.to_owned(),
                sha: file_oid.to_hex().to_string(),
                size: data_size,
                r#type: ContentType::File,
                url: None,
                download_url: None,
                git_url: None,
                html_url: None,
            },
            commit: Commit {
                sha: commit_oid.to_hex().to_string(),
                node_id: None,
                message: String::from_utf8_lossy(commit.message.trim())
                    .to_string(),
                tree: Tree {
                    sha: oid.to_hex().to_string(),
                    url: None,
                },
                parents: Some(
                    commit
                        .parents
                        .into_iter()
                        .map(|sha| CommitLink {
                            sha: sha.to_hex().to_string(),
                            url: None,
                            html_url: None,
                        })
                        .collect(),
                ),
                author: Some(commit.author.to_ref().into()),
                committer: Some(commit.committer.to_ref().into()),
                url: format!(
                    "{}/repos/{}/{}/git/commits/{}",
                    st.root, owner, name, commit_oid
                ),
                html_url: None,
            },
        }),
    ))
}

#[instrument(skip(st), err(Debug))]
async fn create_status(
    auth: Authorization,
    State(st): State<St>,
    Path((owner, name, commit)): Path<(String, String, String)>,
    Json(CreateStatusGarbage {
        context,
        state,
        target_url,
        description,
    }): Json<CreateStatusGarbage>,
) -> Result<Json<CreateStatusResponse>, GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token_eager();
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

    let Some(c) = git_hash::ObjectId::from_hex(commit.as_bytes())
        .ok()
        .filter(|c| {
            crate::model::git::load(&tx, repo.network, c).map(|o| o.kind())
                == Some(git_object::Kind::Commit)
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
        const DETAILS: &[GithubErrorDetails<'_>] = &[Error::details(
            "Status",
            "state",
            "custom",
            "state is not included in the list",
        )];
        return Err(Error::unprocessable("Validation Failed", DETAILS)
            .into_response("commits", "statuses", "create-a-commit-status"));
    };

    if context.is_empty() {
        const DETAILS: &[GithubErrorDetails<'_>] =
            &[Error::details("Status", "context", "missing_field", "")];
        return Err(Error::unprocessable("Validation Failed", DETAILS)
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

    tx.commit().unwrap();

    Ok(Json(CreateStatusResponse {
        id,
        context,
        state,
        description,
        target_url,
        creator: None,
    }))
}

#[instrument(skip(st), err(Debug))]
async fn create_branch_merge(
    auth: Authorization,
    State(st): State<St>,
    Path((owner, name)): Path<(String, String)>,
    Json(req): Json<CreateBranchMerge>,
) -> Result<(StatusCode, Json<CommitsResponse>), Response> {
    let mut db = Source::get();
    let tx = db.token_eager();
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
    let head = if let Ok(h) = git_hash::ObjectId::from_hex(req.head.as_bytes())
    {
        let Some(object) = crate::model::git::load(&tx, repo.network, &h)
        else {
            return Err(Error::NOT_FOUND
                .into_response("branches", "branches", "merge-a-branch")
                .into_response());
        };
        if object.kind() != git_object::Kind::Commit {
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
            .map(Cow::as_ref)
            .unwrap_or("user@example.org")
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
    if let Ok(oid) = m {
        crate::model::git::refs::set(&tx, repo.id, &base_ref, &oid);
        let mut buf = Vec::new();
        let (kind, data) =
            crate::model::git::get_in(&tx, repo.network, &oid, &mut buf)
                .unwrap();
        assert_eq!(kind, git_object::Kind::Commit);
        let commit = git_object::CommitRef::from_bytes(data).unwrap();
        tx.commit().unwrap();

        Ok((
            StatusCode::CREATED,
            Json(CommitsResponse::from(Bundle(
                &st, &owner, &name, &oid, &commit,
            ))),
        ))
    } else {
        Err((
            StatusCode::CONFLICT,
            Json(GithubError {
                message: "Merge Conflict".into(),
                documentation_url: "https://docs.github.com/rest/branches/branches#merge-a-branch" ,
                errors: &[]
            })
        ).into_response())
    }
}

#[instrument]
async fn create_deployment() -> (StatusCode, Json<Deployment>) {
    (StatusCode::CREATED, Json(Deployment { id: 1 }))
}

#[instrument]
async fn create_deployment_status() -> StatusCode {
    StatusCode::CREATED
}

#[instrument(err(Debug))]
async fn list_collaborators(
    State(_): State<St>,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Json<Vec<Collaborator>>, GHError<'static>> {
    let mut db = Source::get();
    let tx = &db.token();
    let Some(repo_id) = crate::model::repos::id_by_name(tx, &owner, &name)
    else {
        // FIXME: correct error?
        return Err(Error::NOT_FOUND.into_response(
            "collaborators",
            "collaborators",
            "list-collaborators",
        ));
    };
    Ok(Json(
        crate::model::repos::get_collaborators(tx, repo_id)
            .into_iter()
            .map(|login| Collaborator { login })
            .collect(),
    ))
}

/// Invitation from from a UI perspective:
/// - when inviting to a personal repo, no role can be selected
/// - invitation is visible next to collaborators
/// - if invitation is rejected, it is removed from the list
/// - otherwise it's converted from pending invitation" to "collaborator"
/// - when inviting to an org repo, role selection is added
///   - role can be changed in list after invitation has been created (whether
///     accepted or not)
/// - invitations expire after 7 days (since 2020), in UI they remain present in
///   the list, but flagged as expired (and the invitation link doesn't work
///   anymore)
///
/// TODO:
/// - permission levels (pull, triage, push, maintain, admin) -- doc says only
///   valid for organization-owned repository? is it specific perms or explicit
///   perms and individual repo is always push?
///
///   Passed as body content `{permission: ...}`.
/// - if inviting an org member and org has base role, permission must be higher
///   than base role otherwise request will fail
/// - can update an existing collaborator's permission level, just call endpoint
///   with new permission, response is 204
/// - rate limit of 50 invitations / repository / 24h, unless inviting org
///   member to org repo
///
/// Returns:
/// - 201 (created) when a new invitation is created
/// - 204 (no content) when an existing collaborator is re-added, an org member
///   is added as a collaborator, or an existing team member (whose team is a
///   collaborator) is added
/// - 403 (forbidden) ???
/// - 422 (validation failed) ???
#[instrument(err(Debug))]
async fn add_collaborator(
    State(_): State<St>,
    Path((owner, name, new_collaborator)): Path<(String, String, String)>,
) -> Result<(StatusCode, Json<RepositoryInvitation>), GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token();
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "collaborators",
            "collaborators",
            "add-a-repository-collaborator",
        ));
    };
    if new_collaborator == repo.owner.login {
        static DEETS: &[crate::github::GithubErrorDetails<'_>] =
            &[Error::details(
                "Repository",
                "",
                "custom",
                "Repository owner cannot be a collaborator",
            )];
        return Err(Error::unprocessable("Validation Failed", DEETS)
            .into_response(
                "reference",
                "repos",
                "add-a-repository-collaborator",
            ));
    }
    if !crate::model::repos::add_collaborator(&tx, repo.id, new_collaborator) {
        return Err(Error::NOT_FOUND.into_response(
            "collaborators",
            "collaborators",
            "add-a-repository-collaborator",
        ));
    };
    tx.commit().unwrap();

    // 204 when:
    // - an existing collaborator is added as a collaborator
    // - an organization member is added as an individual collaborator
    // - an existing team member (whose team is also a repository collaborator)
    //   is added as an individual collaborator
    Ok((StatusCode::CREATED, Json(RepositoryInvitation { id: 1 })))
}

async fn get_branch(
    State(st): State<St>,
    Path((owner, name, branch_name)): Path<(String, String, String)>,
) -> Result<Json<github_types::branches::BranchWithProtection>, GHError<'static>>
{
    let mut db = Source::get();
    let tx = &db.token();
    let Some(repo) = crate::model::repos::by_name(tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "branches",
            "branches",
            "get-a-branch",
        ));
    };

    let branch_ref = format!("refs/heads/{branch_name}");
    let Some(oid) = crate::model::git::refs::resolve(tx, repo.id, &branch_ref)
    else {
        return Err(Error::NOT_FOUND.into_response(
            "branches",
            "branches",
            "get-a-branch",
        ));
    };

    let mut buf = Vec::new();
    let Some((kind, data)) =
        crate::model::git::get_in(tx, repo.network, &oid, &mut buf)
    else {
        return Err(Error::NOT_FOUND.into_response(
            "branches",
            "branches",
            "get-a-branch",
        ));
    };

    // FIXME: is this the right error?
    if kind != git_object::Kind::Commit {
        let msg = format!("No commit found for SHA: {branch_ref}");
        return Err(Error::Unprocessable(msg.into(), &[]).into_response(
            "branches",
            "branches",
            "get-a-branch",
        ));
    }
    let commit = git_object::CommitRef::from_bytes(data).unwrap();

    Ok(Json(github_types::branches::BranchWithProtection {
        name: branch_name,
        commit: CommitsResponse::from(Bundle(
            &st, &owner, &name, &oid, &commit,
        )),
    }))
}

#[derive(Deserialize)]
struct UpdateBranchProtection {}
async fn update_branch_protection() {}
