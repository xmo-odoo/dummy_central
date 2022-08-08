use base64::prelude::{Engine as _, BASE64_STANDARD};
use git_actor::{Signature, Time};
use git_object::bstr::{BString, ByteSlice};
use git_object::ObjectRef;
use github_types::users::UserType;
use guard::guard;
use hex::ToHex;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use smallvec::SmallVec;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::{TryFrom, TryInto};
use std::sync::{Arc, RwLock, RwLockReadGuard};
use std::time::{SystemTime, UNIX_EPOCH};
use warp::*;

use super::HookConfig;
use github_types::git::Authorship;
use github_types::repos::*;
use github_types::webhooks::{Webhook, WebhookEvent};

pub mod git;
pub mod git_protocol;
pub mod issues;

use crate::github::{
    auth_to_user, Authorization, Config, Error, GithubError, SimpleUser, St,
};
use crate::model::repos::RepositoryId;
use crate::model::users::find_current_user;
use crate::model::{Source, Token};

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
                message: commit.message.to_string(),
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
pub fn routes<T>(old_base: T) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone
where
    T: Filter<Extract = (Authorization, St), Error = Rejection> + Clone + Send + Sync + 'static,
{
    let base = old_base.clone().and(path!("repos" / String / String / ..));
    let git_base = old_base
        .and(path::param::<String>())
        .and(path::param().map(|mut p: String| {
            // on github at least foo/bar.git and foo/bar seem to yield more or
            // less the same thing wrt git?
            if p.ends_with(".git") {
                p.truncate(p.len() - 4);
            }
            p
        }));

    base.clone().and(path::end()).and(get().or(head()).unify()).map(get_repository).boxed()
        .or(base.clone().and(path::end()).and(patch()).and(body::json()).map(update_repository).boxed())
        .or(base.clone().and(path::end()).and(delete()).map(delete_repository).boxed())
        .or(base.clone().and(path!("forks")).and(post()).and(
            body::json() // FIXME: better way to make the body optional
            .or(any().map(|| CreateFork { organization: None })).unify()
        ).map(create_fork).boxed())
        .or(base.clone().and(path!("hooks")).and(get()).map(list_hooks).boxed())
        .or(base.clone().and(path!("hooks")).and(post()).and(body::json()).map(create_hook).boxed())
        .or(base.clone().and(path!("hooks" / i64)).and(patch()).and(body::json()).map(update_hook).boxed())
        .or(base.clone().and(path!("hooks" / i64)).and(delete()).map(delete_hook).boxed())
        .or(base.clone().and(path!("branches" / String)).and(get()).map(get_branch).boxed())
        .or(base.clone().and(path!("branches" / String / "protection")).and(put()).and(body::json()).map(update_branch_protection).boxed())
        .or(base.clone().and(path!("commits" / String / "status")).and(get()).map(get_status).boxed())
        .or(base.clone().and(path!("commits")).and(get()).and(query()).map(list_commits).boxed())
        // NOTE: must be after everything else
        .or(base.clone().and(path::path("commits")).and(path::tail()).and(get()).map(get_commit).boxed())
        .or(base.clone().and(path::path("contents")).and(path::tail()).and(put()).and(body::json()).map(create_or_update_contents).boxed())
        .or(base.clone().and(path!("statuses" / String)).and(post()).and(body::json()).map(create_status).boxed())
        .or(base.clone().and(path!("merges")).and(post()).and(body::json()).map(create_branch_merge).boxed())
        .or(base.clone().and(path!("deployments")).and(post()).map(create_deployment).boxed())
        .or(base.clone().and(path!("deployments" / usize / "statuses")).and(post()).map(create_deployment_status).boxed())
        .or(base.clone().and(path!("collaborators")).and(get()).map(list_collaborators).boxed())
        .or(base.clone().and(path!("collaborators" / String)).and(put()).map(add_collaborator).boxed())
        .or(issues::routes(base.clone()))
        .or(git::routes(base))
        .or(git_protocol::routes(git_base))
}

fn get_repository(
    _: Authorization,
    st: St,
    owner: String,
    name: String,
) -> impl Reply {
    let mut db = Source::get();
    let tx = &db.token();

    guard!(let Some(repo) = crate::model::repos::by_name(tx, &owner, &name) else {
        return Error::NotFound.into_response("repos", "get-a-repository");
    });

    // this should be a FullRepositoryResponse, not just Repository
    reply::with_status(
        reply::json(&repo.to_response(tx, &st.root)),
        http::StatusCode::OK,
    )
    .into_response()
}

fn update_repository(
    _: Authorization,
    st: St,
    owner: String,
    name: String,
    updates: UpdateRepository,
) -> impl Reply {
    let mut db = Source::get();
    let tx = db.token_eager();

    guard!(let Some(rid) = crate::model::repos::id_by_name(&tx, &owner, &name) else {
        return Error::NotFound.into_response("repos", "update-a-repository");
    });

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
            return Error::Unprocessable("Validation Failed", &[
                Error::details(
                    "Repository",
                    "default_branch",
                    "invalid",
                    &format!("The branch {d} was not found. Please push that ref first or create it via the Git Data API."),
                )
            ]).into_response("repos", "update-a-repository");
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

    reply::with_status(reply::json(&response), http::StatusCode::OK)
        .into_response()
}

fn delete_repository(
    _: Authorization,
    st: St,
    owner: String,
    name: String,
) -> impl Reply {
    let mut db = Source::get();
    let tx = db.token_eager();

    // FIXME: ACL to delete a repo
    if let Some(repo_id) = crate::model::repos::id_by_name(&tx, &owner, &name) {
        crate::model::repos::delete(&tx, repo_id);
        tx.commit().unwrap();
        http::StatusCode::NO_CONTENT.into_response()
    } else {
        Error::NotFound.into_response("repos", "delete-a-repository")
    }
}

fn create_fork(
    auth: Authorization,
    st: St,
    owner: String,
    name: String,
    req: CreateFork,
) -> impl Reply {
    let mut db = Source::get();
    let tx = db.token_eager();
    guard!(let Some(user) = crate::github::auth_to_user(&tx, auth) else {
        return Error::Unauthenticated("You must be logged in to do that.")
            .into_response_full("guides", "getting-started-with-the-rest-api", "authentication");
    });

    guard!(let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Error::NotFound.into_response("repos", "create-a-fork");
    });

    let _org;
    let new_owner = if let Some(org) = req.organization {
        if let Some(u) = crate::model::users::get_user(&tx, &org) {
            if matches!(u.r#type, crate::model::users::Type::Organization) {
                _org = u;
                &_org
            } else {
                return Error::Unprocessable(
                    &format!(
                        "'{org}' is the login for a user account. \
                        You must pass the login for an organization account."
                    ),
                    &[Error::details("Fork", "organization", "invalid", "")],
                )
                .into_response("repos", "create-a-fork");
            }
        } else {
            return Error::Unprocessable(
                "Validation Failed",
                &[Error::details("Fork", "organization", "invalid", "")],
            )
            .into_response("repos", "create-a-fork");
        }
    } else {
        &user
    };

    if crate::model::git::get_objects(&tx, repo.network).is_empty() {
        return Error::Forbidden(
            "The repository exists, but it contains no Git content. Empty repositories cannot be forked."
        ).into_response("repos", "create-a-fork");
    }

    // if the prospective new owner already has a fork (or source,
    // same diff), return that directly
    if let Some(existing) =
        crate::model::repos::find_fork(&tx, repo.id, new_owner.id)
    {
        let repo = crate::model::repos::by_id(&tx, existing);
        return reply::with_status(
            reply::json(&repo.to_response(&tx, &st.root)),
            http::StatusCode::ACCEPTED,
        )
        .into_response();
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
    reply::with_status(reply::json(&new_repo), http::StatusCode::ACCEPTED)
        .into_response()
}

fn list_hooks(
    _: Authorization,
    st: St,
    owner: String,
    name: String,
) -> impl Reply {
    use crate::model::repos::{id_by_name, list_hooks, ContentType};
    use github_types::repos::CreateHookConfig;
    use github_types::webhooks::{Hook, LastResponse, Webhook, WebhookEvent};
    let mut db = Source::get();
    let tx = &db.token();
    guard!(let Some(repo) = id_by_name(tx, &owner, &name) else {
        return Error::NotFound.into_response("repos", "list-repository-webhooks");
    });

    let hooks = list_hooks(tx, repo);
    reply::with_status(
        reply::json(
            &hooks
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
                .collect::<Vec<_>>(),
        ),
        http::StatusCode::OK,
    )
    .into_response()
}

fn create_hook(
    _: Authorization,
    st: St,
    owner: String,
    name: String,
    hook: CreateHook,
) -> impl Reply {
    let mut db = Source::get();
    let tx = db.token_eager();

    // TODO: error if hook.name != web
    guard!(let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Error::NotFound.into_response("repos", "create-a-repository-webhook")
    });
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

    use github_types::repos::CreateHookConfig;
    use github_types::webhooks::{Hook, LastResponse, Webhook, WebhookEvent};
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

    reply::with_status(reply::json(&hook), http::StatusCode::CREATED)
        .into_response()
}

fn update_hook(
    _: Authorization,
    st: St,
    owner: String,
    name: String,
    hook_id: i64,
    update: UpdateHook,
) -> impl Reply {
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
        return http::StatusCode::NOT_FOUND.into_response();
    }

    use github_types::repos::CreateHookConfig;
    use github_types::webhooks::{Hook, LastResponse, Webhook, WebhookEvent};
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
    reply::with_status(reply::json(&hook), http::StatusCode::OK).into_response()
}

fn delete_hook(
    _: Authorization,
    st: St,
    owner: String,
    name: String,
    hook_id: i64,
) -> impl Reply {
    let mut db = Source::get();
    let tx = db.token();

    if crate::model::repos::delete_hook(&tx, hook_id) {
        tx.commit().unwrap();
        http::StatusCode::NO_CONTENT.into_response()
    } else {
        http::StatusCode::NOT_FOUND.into_response()
    }
}

fn default_page() -> usize {
    1
}
fn default_per_page() -> usize {
    30
}
#[derive(Deserialize)]
struct ListCommitQuery {
    sha: Option<String>,
    #[serde(default = "default_page")]
    page: usize,
    #[serde(default = "default_per_page")]
    per_page: usize,
}
fn list_commits(
    _: Authorization,
    st: St,
    owner: String,
    name: String,
    q: ListCommitQuery,
) -> impl Reply {
    let mut db = Source::get();
    let tx = &db.token();

    guard!(let Some(repo) = crate::model::repos::by_name(tx, &owner, &name) else {
        return Error::NotFound.into_response("repos", "list-commits");
    });

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
    guard!(let Some(oid) = sha_or_branch else {
        return Error::NotFound.into_response("repos", "list-commits");
    });

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
    reply::with_status(reply::json(&output), http::StatusCode::OK)
        .into_response()
}

fn get_commit(
    _: Authorization,
    st: St,
    owner: String,
    name: String,
    commit_ref: path::Tail,
) -> impl Reply {
    let mut db = Source::get();
    let tx = &db.token();

    guard!(let Some(repo) = crate::model::repos::by_name(tx, &owner, &name) else {
        return Error::NotFound.into_response_full("commits", "commits", "get-a-commit");
    });

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
                return Error::NotFound.into_response_full(
                    "commits",
                    "commits",
                    "get-a-commit",
                );
            }
        };

    let mut buf = Vec::new();
    guard!(let Some((kind, data)) = crate::model::git::get_in(tx, repo.network, &oid, &mut buf) else {
        return Error::NotFound.into_response_full("commits", "commits", "get-a-commit");
    });

    if kind != git_object::Kind::Commit {
        let msg = format!("No commit found for SHA: {commit_ref}");
        return Error::Unprocessable(&msg, &[]).into_response_full(
            "commits",
            "commits",
            "get-a-commit",
        );
    }
    let commit = git_object::CommitRef::from_bytes(data).unwrap();

    reply::with_status(
        reply::json(&CommitsResponse::from(Bundle(
            &st, &owner, &name, &oid, &commit,
        ))),
        http::StatusCode::OK,
    )
    .into_response()
}

fn get_status(
    _: Authorization,
    st: St,
    owner: String,
    name: String,
    commit_ref: String,
) -> impl Reply {
    let mut db = Source::get();
    let tx = &db.token();

    guard!(let Some(repo) = crate::model::repos::by_name(tx, &owner, &name) else {
        return Error::NotFound.into_response_full("commits", "commits", "get-a-commit");
    });

    // FIXME: commit_ref can be a branch name (an actual ref)
    // TODO: is that what should happen for an invalid ref? Or am unknown commit?
    guard! {
        let Some(oid) = git_hash::ObjectId::from_hex(commit_ref.as_bytes()).ok()
            .and_then(|oid| crate::model::git::load(tx, repo.network, &oid).map(|_| oid))
        else {
            return Error::NotFound.into_response("repos", "get-the-combined-status-for-a-specific-reference");
        }
    }

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

    reply::with_status(
        reply::json(&CombinedCommitStatus {
            sha: commit_ref,
            state,
            statuses,
            total_count: 0,
            repository: repo.to_response(tx, &st.root),
            url: String::new(),
            commit_url: String::new(),
        }),
        http::StatusCode::OK,
    )
    .into_response()
}

fn create_or_update_contents(
    auth: Authorization,
    st: St,
    owner: String,
    name: String,
    path: path::Tail,
    request: CreateContentsRequest,
) -> impl Reply {
    let mut db = Source::get();
    let tx = db.token_eager();
    // TODO: is this the right error response?
    guard!(let Some(user) = auth_to_user(&tx, auth) else {
        return Error::NotFound.into_response("respo", "create-or-update-file-contents");
    });
    guard!(let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Error::NotFound.into_response("respo", "create-or-update-file-contents");
    });

    // TODO: check what happens if giving github a ref (including prefix)
    let branch_name = request.branch.as_ref().unwrap_or(&repo.default_branch);
    let target_ref = format!("refs/heads/{branch_name}");
    let branch_head =
        crate::model::git::refs::resolve(&tx, repo.id, &target_ref);
    // TODO: if we had a branch, we'd have to check if
    //       there was already a file at the given
    //       path, and if so check what happens if the
    //       sha is missing or incorrect

    // anyway here we're in the straightforward case
    // of creating everything from scratch
    assert!(branch_head.is_none(), "FIXME: we only use this endpoint to create repos because github raises an error on the other \"data\" endpoints");
    if !crate::model::git::get_objects(&tx, repo.network).is_empty() {
        // GH triggers an error when trying to create content in a
        // branch which doesn't exist, but only the second time around
        // (if there's already data in the repo)
        return Error::NotFound2(&format!("Branch {branch_name} not found"))
            .into_response("repos", "create-or-update-file-contents");
    }
    // FIXME: this is probably the same shit as create_blob, but needs to verify
    let data = BASE64_STANDARD.decode(request.content)
        .expect("FIXME: what happens on invalid base64?");
    let data_size = data.len();
    let mut oid =
        crate::model::git::store(&tx, repo.network, git_object::Blob { data });
    let file_oid = oid;
    let mut mode = git_object::tree::EntryMode::Blob;
    // TODO: what if path is an empty string?
    // FIXME: need to lookup trees in order to create
    //        updated tree from them, so this has to
    //        go forwards to deref' the trees then
    //        back to zip them up
    // FIXME: why is Tree.entries not a BTreeSet if
    //        the files must be sorted by filename
    //        (and probably unique)?
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
    // oid is now the root tree
    let commit_oid = crate::model::git::store(
        &tx,
        repo.network,
        git_object::Commit {
            tree: oid,
            parents: SmallVec::new(),
            author: request
                .author
                .map_or_else(|| default_signature.clone(), Into::into),
            committer: request.committer.map_or(default_signature, Into::into),
            encoding: None,
            message: request.message.trim().into(),
            extra_headers: Vec::new(),
        },
    );
    crate::model::git::refs::create(&tx, repo.id, &target_ref, &commit_oid);
    // since this is only the baseline init, re-set the default branch of the
    // repo: when init-ing, the repo's default branch is updated to whatever the
    // contents call specifies
    if let Some(b) = request.branch {
        crate::model::repos::update_repository(&tx, repo.id, None, Some(&b));
    }

    let commit = crate::model::git::load(&tx, repo.network, &commit_oid)
        .unwrap()
        .into_commit();
    tx.commit().unwrap();

    // replies with 200 for an update (?) and 201 for
    // a create as well as file-commit information
    reply::with_status(
        reply::json(&FileCommit {
            content: Content {
                // `name` is the last segment of `path`...
                name: path.as_str().rsplit('/').next().unwrap().to_string(),
                path: path.as_str().to_owned(),
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
                message: commit.message.to_string(),
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
        http::StatusCode::CREATED,
    )
    .into_response()
}

fn create_status(
    auth: Authorization,
    st: St,
    owner: String,
    name: String,
    commit: String,
    CreateStatusGarbage {
        context,
        state,
        target_url,
        description,
    }: CreateStatusGarbage,
) -> impl Reply {
    let mut db = Source::get();
    let tx = db.token_eager();
    let creator = crate::github::auth_to_user(&tx, auth).unwrap();
    guard!(let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Error::NotFound.into_response_full(
            "commits",
            "statuses",
            "create-a-commit-status",
        )
    });

    // because warp doesn't %-decode path fragments (seanmonstar/warp#242)
    let commit =
        percent_encoding::percent_decode_str(&commit).decode_utf8_lossy();

    guard!(let Some(c) = git_hash::ObjectId::from_hex(commit.as_bytes())
        .ok()
        .filter(|c| {
            crate::model::git::load(&tx, repo.network, c).map(|o| o.kind())
                == Some(git_object::Kind::Commit)
        })
        .and_then(|c| crate::model::git::get(&tx, repo.network, &c)
        ) else {
        return Error::Unprocessable(
            &format!("No commit found for SHA: {commit}"), &[])
            .into_response_full("commits", "statuses", "create-a-commit-status");
    });

    guard!(let Ok(state_) = state.as_str().try_into() else {
        return Error::Unprocessable(
            "Validation Failed",
            &[Error::details("Status", "state", "custom", "state is not included in the list")]
        ).into_response_full("commits", "statuses", "create-a-commit-status");
    });

    if context.is_empty() {
        return Error::Unprocessable(
            "Validation Failed",
            &[Error::details("Status", "context", "missing_field", "")],
        )
        .into_response_full(
            "commits",
            "statuses",
            "create-a-commit-status",
        );
    }

    let id = crate::model::create_status(
        &tx,
        c,
        &state,
        &context,
        target_url.as_deref(),
        description.as_deref(),
    );

    use github_types::webhooks::Status;
    send_hook(&tx, repo, &st, HookEvent::Status, &creator, || {
        WebhookEvent::Status(Status {
            sha: commit.to_string(),
            state: state_,
            context: context.clone(),
            description: description.clone(),
            target_url: target_url.clone(),
        })
    });

    tx.commit().unwrap();

    reply::with_status(
        reply::json(&CreateStatusResponse {
            id: *id, // FIXME type discrepancy
            context,
            state: state_,
            description,
            target_url,
            creator: None,
        }),
        http::StatusCode::OK,
    )
    .into_response()
}

fn create_branch_merge(
    auth: Authorization,
    st: St,
    owner: String,
    name: String,
    req: CreateBranchMerge,
) -> impl Reply {
    let mut db = Source::get();
    let tx = db.token_eager();
    guard!(let Some(user) = auth_to_user(&tx, auth) else {
        return Error::Forbidden("").into_response("branches", "merge-a-branch");
    });
    guard!(let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Error::NotFound.into_response("branches", "merge-a-branch");
    });

    let base_ref = format!("refs/heads/{}", req.base);
    guard!(let Some(base) = crate::model::git::refs::resolve(&tx, repo.id, &base_ref) else {
        return Error::NotFound.into_response("branches", "merge-a-branch");
    });

    // `head` can be either a sha1 or a branchname
    let head = if let Ok(h) = git_hash::ObjectId::from_hex(req.head.as_bytes())
    {
        guard!(let Some(object) = crate::model::git::load(&tx, repo.network, &h) else {
            return Error::NotFound.into_response("branches", "merge-a-branch");
        });
        if object.kind() != git_object::Kind::Commit {
            return Error::Unprocessable("", &[])
                .into_response("branches", "merge-a-branch");
        }
        h
    } else if let Some(h) = crate::model::git::refs::resolve(
        &tx,
        repo.id,
        &format!("refs/heads/{}", req.head),
    ) {
        h
    } else {
        return Error::NotFound.into_response("branches", "merge-a-branch");
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
        reply::with_status(
            reply::json(&CommitsResponse::from(Bundle(
                &st, &owner, &name, &oid, &commit,
            ))),
            http::StatusCode::CREATED,
        )
        .into_response()
    } else {
        reply::with_status(
            reply::json(&GithubError {
                message: "Merge Conflict",
                documentation_url: "https://docs.github.com/rest/reference/branches#merge-a-branch" ,
                errors: &[]
            }),
            http::StatusCode::CONFLICT
        ).into_response()
    }
}

fn create_deployment(
    _: Authorization,
    _: St,
    _: String,
    _: String,
    // req: CreateDeployment,
) -> impl Reply {
    reply::with_status(
        reply::json(&Deployment { id: 1 }),
        http::StatusCode::CREATED,
    )
}

fn create_deployment_status(
    _: Authorization,
    _: St,
    _: String,
    _: String,
    _: usize,
) -> impl Reply {
    http::StatusCode::CREATED
}

fn list_collaborators(
    _: Authorization,
    st: St,
    owner: String,
    name: String,
) -> impl Reply {
    let mut db = Source::get();
    let tx = &db.token();
    guard!(let Some(repo_id) = crate::model::repos::id_by_name(tx, &owner, &name) else {
        // FIXME: correct error?
        return Error::NotFound.into_response("collaborators", "list-collaborators");
    });
    reply::with_status(
        reply::json(
            &crate::model::repos::get_collaborators(tx, repo_id)
                .into_iter()
                .map(|login| Collaborator { login })
                .collect::<Vec<_>>(),
        ),
        http::StatusCode::OK,
    )
    .into_response()
}
// FIXME: only create an invitation and have the user accept the invitation
// TODO: add permissions body param (default: push = write)
/// The endpoint can also be used to change the permissions of an existing
/// collaborator without first removing and re-adding the collaborator. To
/// change the permissions, use the same endpoint and pass a different
/// permission parameter. The response will be a 204, with no other indication
/// that the permission level changed.
fn add_collaborator(
    _: Authorization,
    st: St,
    owner: String,
    name: String,
    new_collaborator: String,
) -> impl Reply {
    let mut db = Source::get();
    let tx = db.token();
    guard!(let Some(repo_id) = crate::model::repos::id_by_name(&tx, &owner, &name) else {
        return Error::NotFound.into_response("collaborators", "add-a-repository-collaborator");
    });
    if !crate::model::repos::add_collaborator(&tx, repo_id, new_collaborator) {
        return Error::NotFound
            .into_response("collaborators", "add-a-repository-collaborator");
    };
    tx.commit().unwrap();

    // 204 when:
    // - an existing collaborator is added as a collaborator
    // - an organization member is added as an individual collaborator
    // - an existing team member (whose team is also a repository collaborator)
    //   is added as an individual collaborator
    reply::with_status(
        reply::json(&RepositoryInvitation { id: 1 }),
        http::StatusCode::CREATED,
    )
    .into_response()
}

fn get_branch(
    _: Authorization,
    st: St,
    owner: String,
    name: String,
    branch_name: String,
) -> impl Reply {
    let mut db = Source::get();
    let tx = &db.token();
    guard!(let Some(repo) = crate::model::repos::by_name(tx, &owner, &name) else {
        return Error::NotFound.into_response("branches", "get-a-branch");
    });

    let branch_ref = format!("refs/heads/{branch_name}");
    guard!(let Some(oid) = crate::model::git::refs::resolve(tx, repo.id, &branch_ref) else {
        return Error::NotFound.into_response("branches", "get-a-branch");
    });

    let mut buf = Vec::new();
    guard!(let Some((kind, data)) = crate::model::git::get_in(tx, repo.network, &oid, &mut buf) else {
        return Error::NotFound.into_response("branches", "get-a-branch");
    });

    // FIXME: is this the right error?
    if kind != git_object::Kind::Commit {
        let msg = format!("No commit found for SHA: {branch_ref}");
        return Error::Unprocessable(&msg, &[])
            .into_response("branches", "get-a-branch");
    }
    let commit = git_object::CommitRef::from_bytes(data).unwrap();

    reply::with_status(
        reply::json(&github_types::branches::BranchWithProtection {
            name: branch_name,
            commit: CommitsResponse::from(Bundle(
                &st, &owner, &name, &oid, &commit,
            )),
        }),
        http::StatusCode::OK,
    )
    .into_response()
}

#[derive(Deserialize)]
struct UpdateBranchProtection {}
fn update_branch_protection(
    _: Authorization,
    _: St,
    _: String,
    _: String,
    _: String,
    _: UpdateBranchProtection,
) -> impl Reply {
    http::StatusCode::OK
}
