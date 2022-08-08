/*!
# Straight pseudo-github implementation.
 */
use base64::prelude::{Engine as _, BASE64_STANDARD};
use guard::guard;
use hmac::{Hmac, Mac};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use serde_json::Deserializer;
use sha1::Sha1;
use sha2::Sha256;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Instant;
use tokio::sync::mpsc::{
    unbounded_channel, UnboundedReceiver, UnboundedSender,
};
use tracing::*;
use warp::*;

use github_types::orgs::OrganizationFull;
use github_types::repos::{
    CreateRepositoryRequest, HookContentType, RepositoryResponse,
};
use github_types::users::{
    Email, PublicUser, SimpleUser, UserType, Visibility,
};
use github_types::webhooks::{self, Webhook};
use github_types::{Core, RateLimit, Resource};

use crate::model::repos::{Repository, RepositoryId};
use crate::model::users::{find_current_user, list_user_emails, User};
use crate::model::{Source, Token};

mod repos;

#[derive(Serialize)]
struct GithubError<'a> {
    message: &'a str,
    documentation_url: &'a str,
    #[serde(skip_serializing_if = "<[_]>::is_empty")]
    errors: &'a [GithubErrorDetails<'a>],
}
#[derive(Serialize, Copy, Clone)]
struct GithubErrorDetails<'a> {
    resource: &'a str,
    field: &'a str,
    code: &'a str,
    #[serde(skip_serializing_if = "<str>::is_empty")]
    message: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct HookConfig {
    id: i64,
    pub active: bool,
    pub url: String,
    pub content_type: HookContentType,
    pub events: HashSet<github_types::repos::HookEvent>,
    pub secret: String,
    // ignore ssl and secret for now
}
type HookEvent = (HookConfig, Webhook);
pub struct Config {
    root: String,
    webhooks: UnboundedSender<HookEvent>,
}
impl Config {
    pub fn new(
        root: String,
    ) -> Result<
        (Config, impl std::future::Future<Output = ()> + 'static),
        Box<dyn std::error::Error>,
    > {
        let (sender, receiver) = unbounded_channel::<HookEvent>();
        Ok((
            Self {
                root,
                webhooks: sender,
            },
            Config::send_hooks(receiver),
        ))
    }

    async fn send_hooks(mut r: UnboundedReceiver<HookEvent>) {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10)) // matches github
            .pool_max_idle_per_host(1) // only one hooks worker
            .build()
            .expect("Couldn't build a client!");

        // note: github can send hooks mis-ordered, probably because
        //       it has multiple webhook workers, maybe even multiple
        //       webhook queues.
        while let Some((conf, event)) = r.recv().await {
            let mut req = client
                .post(&conf.url)
                .header("User-Agent", "GitHub-Hookshot/1234567") // hexadecimal thing
                .header("X-Github-Delivery", "00000000-0000-0000-000000000000") // FIXME: actual UUID + trace out for tracking?
                .header("X-Github-Event", event.event.name())
                .header("X-Github-Hook-Id", conf.id);

            req = match conf.content_type {
                HookContentType::Json => req.json(&event),
                HookContentType::Form => {
                    req.multipart(reqwest::multipart::Form::new().text(
                        "payload",
                        serde_json::to_string(&event).expect(
                            "Couldn't serialize a webhook payload to json...",
                        ),
                    ))
                }
            };
            // TODO: log errors, store history (?), send in a separate Task?
            if conf.secret.is_empty() {
                let _ = req.send().await;
            } else {
                let mut req = req.build().unwrap();
                let b = req.body().unwrap().as_bytes().unwrap();

                let mac = Hmac::<Sha1>::new_from_slice(conf.secret.as_bytes())
                    .unwrap()
                    .chain_update(b)
                    .finalize()
                    .into_bytes();
                let mac256 =
                    Hmac::<Sha256>::new_from_slice(conf.secret.as_bytes())
                        .unwrap()
                        .chain_update(b)
                        .finalize()
                        .into_bytes();

                req.headers_mut().insert(
                    "X-Hub-Signature",
                    format!("sha1={}", hex::encode(mac)).try_into().unwrap(),
                );
                req.headers_mut().insert(
                    "X-Hub-Signature-256",
                    format!("sha256={}", hex::encode(mac256))
                        .try_into()
                        .unwrap(),
                );

                let _ = client.execute(req).await;
            }
        }
    }
}
enum Error<'a> {
    NotFound,
    NotFound2(&'a str),
    Unauthenticated(&'a str),
    Forbidden(&'a str),
    Unprocessable(&'a str, &'a [GithubErrorDetails<'a>]),
}
impl Error<'_> {
    fn repo(m: &'static str) -> GithubErrorDetails<'static> {
        Self::details("Repository", "name", "custom", m)
    }
    fn details<'a>(
        resource: &'a str,
        field: &'a str,
        code: &'a str,
        message: &'a str,
    ) -> GithubErrorDetails<'a> {
        GithubErrorDetails {
            resource,
            field,
            code,
            message,
            value: None,
        }
    }
    /// Convenience method for generating github error JSON.
    ///
    /// Takes the name of a section of the Github v3 docs
    /// (e.g. `"issues"`, `"repos"`) and the name of the specific item
    /// (anchor) within that page, prepends with the rest of the URL
    /// up to and including `"reference/"`.
    fn into_response(self, section: &str, item: &str) -> reply::Response {
        self.into_response_full("reference", section, item)
    }
    fn into_response_full(
        self,
        category: &str,
        section: &str,
        item: &str,
    ) -> reply::Response {
        let documentation_url;
        let documentation_url = if section.is_empty() {
            "https://docs.github.com/rest"
        } else {
            documentation_url = format!(
                "https://docs.github.com/rest/{category}/{section}#{item}",
            );
            &documentation_url
        };
        match self {
            Error::NotFound => reply::with_status(
                reply::json(&GithubError {
                    message: "Not Found",
                    documentation_url,
                    errors: &[],
                }),
                http::StatusCode::NOT_FOUND,
            ),
            Error::NotFound2(message) => reply::with_status(
                reply::json(&GithubError {
                    message,
                    documentation_url,
                    errors: &[],
                }),
                http::StatusCode::NOT_FOUND,
            ),
            Error::Unauthenticated(message) => reply::with_status(
                reply::json(&GithubError {
                    message,
                    documentation_url,
                    errors: &[],
                }),
                http::StatusCode::UNAUTHORIZED,
            ),
            Error::Forbidden(message) => reply::with_status(
                reply::json(&GithubError {
                    message,
                    documentation_url,
                    errors: &[],
                }),
                http::StatusCode::FORBIDDEN,
            ),
            Error::Unprocessable(message, errors) => reply::with_status(
                reply::json(&GithubError {
                    message,
                    documentation_url,
                    errors,
                }),
                http::StatusCode::UNPROCESSABLE_ENTITY,
            ),
        }
        .into_response()
    }
}

impl User<'_> {
    fn to_simple(&self, root: &str) -> SimpleUser {
        SimpleUser {
            url: SimpleUser::url(root, &self.login),
            email: self.email.clone().map(Into::into),
            login: self.login.clone().into(),
            name: self.name.clone().map(Into::into),
            r#type: self.r#type.into(),
        }
    }
    fn into_simple(self, root: &str) -> SimpleUser {
        SimpleUser {
            url: SimpleUser::url(root, &self.login),
            email: self.email.clone().map(Into::into),
            login: self.login.clone().into(),
            name: self.name.clone().map(Into::into),
            r#type: self.r#type.into(),
        }
    }
}
impl From<User<'_>> for PublicUser {
    fn from(u: User<'_>) -> Self {
        PublicUser {
            login: u.login.into(),
            name: u.name.map(Into::into),
            email: u.email.map(Into::into),
            r#type: u.r#type.into(),
            ..Self::default()
        }
    }
}
impl From<crate::model::users::Type> for UserType {
    fn from(t: crate::model::users::Type) -> Self {
        match t {
            crate::model::users::Type::User => UserType::User,
            crate::model::users::Type::Organization => UserType::Organization,
        }
    }
}
impl Repository {
    fn to_response(&self, tx: &Token<'_>, root: &str) -> RepositoryResponse {
        let full_name = format!("{}/{}", self.owner.login, self.name);
        RepositoryResponse {
            id: *self.id,
            url: format!("{root}/repos/{full_name}"),
            statuses_url: format!("{root}/repos/{full_name}/statuses/{{sha}}"),
            name: self.name.clone(),
            full_name,
            fork: self.source.is_some(),
            parent: self.parent.map(|p| {
                Box::new(
                    crate::model::repos::by_id(tx, p).to_response(tx, root),
                )
            }),
            source: self.source.map(|p| {
                Box::new(
                    crate::model::repos::by_id(tx, p).to_response(tx, root),
                )
            }),
            default_branch: self.default_branch.clone(),
            owner: self.owner.to_simple(root),
            ..RepositoryResponse::default()
        }
    }
}
type St = Arc<Config>;
type Authorization = Option<(Option<String>, String)>;
fn auth_to_user(tx: &Token, auth: Authorization) -> Option<User<'static>> {
    auth.and_then(|(_, token)| find_current_user(tx, &token))
}

fn base(
    st: St,
) -> impl Filter<Extract = (Authorization, St), Error = Rejection> + Clone {
    header::optional(AUTHORIZATION.as_str())
        .map(|h: Option<String>| {
            h.and_then(|mut h| {
                // auth-scheme SP data
                if h.starts_with("token ") {
                    h.replace_range(..6, "");
                    Some((None, h))
                } else if let Some(h) = h
                    .strip_prefix("basic ")
                    .or_else(|| h.strip_prefix("Basic "))
                {
                    String::from_utf8(BASE64_STANDARD.decode(h).ok()?)
                        .ok()?
                        .split_once(':')
                        .map(|(user, key)| {
                            (Some(user.to_string()), key.to_string())
                        })
                } else {
                    None
                }
            })
        })
        .and(any().map(move || Arc::clone(&st)))
}
pub fn routes(
    st: St,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let base = base(st);

    base.clone()
        .and(path!("user"))
        .and(get())
        .map(get_current_user)
        .boxed()
        .or(base
            .clone()
            .and(path!("user" / "emails"))
            .and(get())
            .map(get_current_user_emails)
            .boxed())
        .or(base
            .clone()
            .and(path!("user" / "repository_invitations" / usize))
            .and(patch())
            .map(accept_invitation)
            .boxed())
        .or(base
            .clone()
            .and(path!("users" / String))
            .and(get())
            .map(get_user)
            .boxed())
        .or(base
            .clone()
            .and(path!("orgs" / String))
            .and(get())
            .map(|_auth, st: St, orgname: String| {
                use crate::model::users::*;
                let _span = span!(Level::INFO, "get-org").entered();
                let mut db = Source::get();
                let tx = &db.token();
                if let Some(u) = get_user(tx, &orgname) {
                    info!("{} found => {:?}", orgname, u);
                    if matches!(u.r#type, Type::Organization) {
                        return reply::with_status(
                            reply::json(&OrganizationFull {
                                id: 0,
                                node_id: String::new(),
                                url: format!("{}/orgs/{}", st.root, u.login),
                                r#type: match u.r#type {
                                    Type::User => UserType::User,
                                    Type::Organization => {
                                        UserType::Organization
                                    }
                                },
                                login: u.login.into_owned(),
                                name: u.name.map(Cow::into_owned),
                                is_verified: false,
                                followers: 0,
                                following: 0,
                                public_gists: 0,
                                public_repos: 0,
                                has_organization_projects: false,
                                has_repository_projects: false,
                            }),
                            http::StatusCode::OK,
                        )
                        .into_response();
                    }
                }
                info!("{} not found", orgname);
                Error::NotFound.into_response("orgs", "get-an-organization")
            })
            .boxed())
        .or(base
            .clone()
            .and(
                path!("user" / "repos")
                    .map(String::new)
                    .or(path!("orgs" / String / "repos"))
                    .unify(),
            )
            .and(post())
            .and(body::json())
            .map(create_repository)
            .boxed())
        .or(base
            .clone()
            .and(path!("rate_limit"))
            .and(get())
            .map(rate_limit)
            .boxed())
        .or(base
            .clone()
            .and(path!("graphql"))
            .and(post())
            .and(body::json())
            .map(graphql)
            .boxed())
        .or(repos::routes(base))
        .recover(|e: Rejection| async {
            if e.is_not_found() {
                Ok(Error::NotFound.into_response("", ""))
            } else {
                Err(e)
            }
        })
}

fn create_repository(
    auth: Authorization,
    st: St,
    owner: String,
    request: CreateRepositoryRequest,
) -> impl Reply {
    let mut db = Source::get();
    let tx = db.token_eager();
    let _span = span!(Level::INFO, "create-a-repository").entered();
    let endpoint = if owner.is_empty() {
        "create-a-repository-for-the-authenticated-user"
    } else {
        "create-an-organization-repository"
    };
    let u = if let Some(u) = auth_to_user(&tx, auth) {
        u
    } else {
        return Error::Unauthenticated("Requires authentication")
            .into_response("repos", endpoint);
    };

    // Repository name can only contain ASCII letters,
    // numbers, `-`, `_`, and `.`, get auto-fixed at creation.
    // NOTE: normalization only occurs on creation
    let name = regex::Regex::new("[^[:alnum:]_.-]+")
        .expect("Regex should be valid.")
        .replace_all(&request.name, "-");

    // apparently length check is after replacement (at least
    // conceptually)
    if name.len() > 100 {
        return Error::Unprocessable(
            "Repository creation failed.",
            &[Error::repo("name is too long (maximum is 100 characters)")],
        )
        .into_response("repos", endpoint);
    }

    guard!(let Some(owner) =
        owner.is_empty().then(|| u.clone())
            .or_else(|| crate::model::users::get_user(&tx, &owner)) else {
        return Error::NotFound.into_response("repos", endpoint);
    });

    guard!(let Some(repo) = crate::model::repos::create_repository(&tx, u.id, owner.id, &name, None) else {
        return Error::Unprocessable(
            "Repository creation failed.",
            &[Error::repo("name already exists on this account")],
        )
        .into_response("repos", endpoint);
    });

    let reply = reply::json(&repo.to_response(&tx, &st.root));
    info!("Created repository {}/{}", owner.login, name);
    tx.commit().unwrap();
    reply::with_status(reply, http::StatusCode::OK).into_response()
}

fn get_current_user(auth: Authorization, st: St) -> impl Reply {
    let mut db = Source::get();
    let tx = &db.token();
    auth_to_user(tx, auth).map_or_else(
        || {
            Error::Unauthenticated("Requires authentication")
                .into_response("users", "get-the-authenticated-user")
        },
        |u| {
            reply::with_header(
                reply::json(&PublicUser::from(u)),
                "X-OAuth-Scopes",
                "user:email",
            )
            .into_response()
        },
    )
}

use crate::model::users::Email as ModelEmail;
impl From<ModelEmail<'_>> for Email {
    fn from(
        ModelEmail {
            email,
            verified,
            primary,
            visibility,
            ..
        }: ModelEmail,
    ) -> Email {
        Email {
            email: email.into(),
            verified,
            primary,
            visibility: visibility.into(),
        }
    }
}
use crate::model::users::Visibility as ModelVisibility;
use github_types::users::Visibility as APIVisibility;

impl From<ModelVisibility> for APIVisibility {
    fn from(vis: ModelVisibility) -> Self {
        match vis {
            ModelVisibility::Public => APIVisibility::Public,
            ModelVisibility::Private => APIVisibility::Private,
        }
    }
}
fn get_current_user_emails(auth: Authorization, st: St) -> impl Reply {
    let mut db = Source::get();
    let tx = &db.token();
    auth_to_user(tx, auth).map_or_else(
        || {
            Error::Unauthenticated("Requires authentication")
                .into_response("users", "get-the-authenticated-user")
        },
        |u| {
            reply::json(
                &list_user_emails(tx, &u.id)
                    .into_iter()
                    .map(Email::from)
                    .collect::<Vec<_>>(),
            )
            .into_response()
        },
    )
}

fn get_user(_: Authorization, st: St, username: String) -> impl Reply {
    // dumb magical user, alternative would be to always create it in the DB I
    // guess but if it's going to be hardcoded into the system...
    if username == "web-flow" {
        return reply::json(&PublicUser {
            login: "web-flow".into(),
            name: Some("GitHub Web Flow".into()),
            ..PublicUser::default()
        })
        .into_response();
    }
    let mut db = Source::get();
    let tok = &db.token();
    if let Some(u) = crate::model::users::get_user(tok, &username) {
        // NOTE: works fine for API, but not web
        reply::json(&PublicUser::from(u)).into_response()
    } else {
        Error::NotFound.into_response("users", "get-a-user")
    }
}
fn accept_invitation(_: Authorization, _: St, _: usize) -> impl Reply {
    http::StatusCode::NO_CONTENT
}

fn rate_limit(_: Authorization, _: St) -> impl Reply {
    reply::with_header(
        reply::with_status(
            reply::json(&RateLimit::default()),
            http::StatusCode::OK,
        ),
        "X-OAuth-Scopes",
        "admin:repo_hook, delete_repo, public_repo, user:email",
    )
}

#[derive(Deserialize)]
struct GraphqlRequest {
    query: String,
    #[serde(default)]
    variables: HashMap<String, serde_json::Value>,
}
#[derive(Serialize)]
struct GraphqlResponse {
    data: Option<()>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errors: Vec<GraphqlError>,
}
#[derive(Serialize)]
struct GraphqlError {
    message: Cow<'static, str>,
}
impl reply::Reply for GraphqlResponse {
    fn into_response(self) -> reply::Response {
        reply::json(&self).into_response()
    }
}
/**
# NODE IDS

GraphQL being a single global endpoints it can't have fine-grained ids the
way the REST API does, instead it relies on globally unique, possibly opaque,
nodeids.

Github decided to use payload-bearing nodeids, in two formats:
`<https://github.community/t/what-is-the-new-id-format-and-how-is-it-generated/161208/4>`

## format 1

Is a base64-encoded, padded, textual pointer to the object. The basic structure
of the decoded id is

    <typlen>:<typ><typid>

The "typ" identifies the object kind (e.g. Commit, User, PullRequest, ...), typid is
type-specific but apparently tends to start with the database id of the repo,
then might contain an object-specific id e.g. the sha for a commit.

Note: looking at a super old PR it's apparently just the database ID of the PR,
so I guess github does have a single db? Or is it that they *had* a single db?

## format 2

Has a direct structure of

    <typ>_<payload>

The typ is different than format one e.g. PSH for a push (???), PR for a PR.
The payload then provides a pointer as a base64-encoded, unpaded, messagepack
array, the linked comments mentions that for an issue comment the array contains
the following items:

- a version (?) integer, 0
- the database id of the repository
- the database id of the object

note: for a repo there's apparently only the db id of the repo (no way!) but it
      seems to work correctly for a PR
*/
fn graphql(
    auth: Authorization,
    st: St,
    request: GraphqlRequest,
) -> GraphqlResponse {
    let mut db = Source::get();
    let tx = db.token_eager();
    guard!(let Some(user) = auth_to_user(&tx, auth) else {
        return GraphqlResponse {
            data: None,
            errors: vec![GraphqlError {
                message: "Unknown user".into()
            }]
        };
    });
    // assume the query is either markPullRequestReadyForReview or
    // convertPullRequestToDraft and in both case the pullRequestId is provided
    // through the `pid` query variable
    //
    // This is a quick hack, and note that the pullRequestId in gql is a global
    // node_id value, which has implications (namely that the real github
    // should probably be a single db, or has a quick lookup of node_id to repo)
    let new_draft = if request.query.contains("markPullRequestReadyForReview(")
    {
        false
    } else if request.query.contains("convertPullRequestToDraft(") {
        true
    } else {
        return GraphqlResponse {
            data: None,
            errors: vec![GraphqlError {
                message:
                    "Invalid query, only updating draft status is kinda handled"
                        .into(),
            }],
        };
    };

    let pid: Pid =
        serde_json::from_str(request.variables["pid"].as_str().unwrap())
            .unwrap();

    guard!(let Some(pr) = crate::model::prs::find_by_id(&tx, pid.0) else {
        return GraphqlResponse {
            data: None,
            errors: vec![GraphqlError {
                message: "PR not found".into(),
            }]
        }
    });

    if !crate::model::prs::can_write(&tx, user.id, pr.id) {
        return GraphqlResponse {
            data: None,
            errors: vec![GraphqlError {
                message: "No write access".into(),
            }],
        };
    }

    if crate::model::prs::set_draft(&tx, pr.id, new_draft) {
        repos::send_hook(
            &tx,
            pr.issue.repository,
            &st,
            github_types::repos::HookEvent::PullRequest,
            &user,
            || {
                webhooks::WebhookEvent::PullRequest(webhooks::PullRequest {
                    action: if new_draft {
                        webhooks::PullRequestAction::ConvertedToDraft
                    } else {
                        webhooks::PullRequestAction::ReadyForReview
                    },
                    number: pr.issue.number,
                    pull_request: repos::issues::pr_response(&tx, &st, pr.id),
                })
            },
        );
        tx.commit().unwrap();

        GraphqlResponse {
            data: Some(()),
            errors: vec![],
        }
    } else {
        GraphqlResponse {
            data: None,
            errors: vec![GraphqlError {
                message: "something bad happened".into(),
            }],
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Pid(i64);
