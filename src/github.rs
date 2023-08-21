/*!
# Straight pseudo-github implementation.
 */
use axum::extract::{FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{async_trait, Json, Router};
use base64::prelude::{Engine as _, BASE64_STANDARD};
use git_object::bstr::{BStr, BString};
use git_object::Blob;
use hmac::{Hmac, Mac};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use hyper::StatusCode;
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
    #[serde(skip_serializing_if = "<str>::is_empty")]
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

struct GHError<'a> {
    error: Error<'a>,
    category: &'a str,
    section: &'a str,
    item: &'a str,
}
impl IntoResponse for GHError<'_> {
    fn into_response(self) -> Response {
        let documentation_url;
        let documentation_url = if self.section.is_empty() {
            "https://docs.github.com/rest"
        } else {
            documentation_url = format!(
                "https://docs.github.com/rest/{}/{}#{}",
                self.category, self.section, self.item,
            );
            &documentation_url
        };
        match self.error {
            Error::NotFound => (
                StatusCode::NOT_FOUND,
                Json(GithubError {
                    message: "Not Found",
                    documentation_url,
                    errors: &[],
                }),
            ),
            Error::NotFound2(message) => (
                StatusCode::NOT_FOUND,
                Json(GithubError {
                    message,
                    documentation_url,
                    errors: &[],
                }),
            ),
            Error::Unauthenticated(message) => (
                StatusCode::UNAUTHORIZED,
                Json(GithubError {
                    message,
                    documentation_url,
                    errors: &[],
                }),
            ),
            Error::Forbidden(message) => (
                StatusCode::FORBIDDEN,
                Json(GithubError {
                    message,
                    documentation_url,
                    errors: &[],
                }),
            ),
            Error::Unprocessable(message, errors) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(GithubError {
                    message,
                    documentation_url,
                    errors,
                }),
            ),
        }
        .into_response()
    }
}

enum Error<'a> {
    NotFound,
    NotFound2(&'a str),
    Unauthenticated(&'a str),
    Forbidden(&'a str),
    Unprocessable(&'a str, &'a [GithubErrorDetails<'a>]),
}
impl<'e> Error<'e> {
    const fn repo(m: &'static str) -> GithubErrorDetails<'static> {
        Self::details("Repository", "name", "custom", m)
    }
    const fn details<'a>(
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
    fn into_response(self, section: &'e str, item: &'e str) -> GHError<'e> {
        self.into_response_full("reference", section, item)
    }
    fn into_response_full(
        self,
        category: &'e str,
        section: &'e str,
        item: &'e str,
    ) -> GHError<'e> {
        GHError {
            error: self,
            category,
            section,
            item,
        }
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
fn auth_to_user(tx: &Token, auth: Authorization) -> Option<User<'static>> {
    find_current_user(tx, &auth.1)
}

#[derive(Debug)]
struct Authorization(Option<String>, String);
#[async_trait]
impl<S> FromRequestParts<S> for Authorization
where
    S: Send + Sync,
{
    type Rejection = GHError<'static>;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|mut h| {
                let h = h.to_str().ok()?;
                // auth-scheme SP data
                if h.starts_with("token ") {
                    Some((None, h[6..].to_string()))
                } else if let Some(h) = h
                    .strip_prefix("basic ")
                    .or_else(|| h.strip_prefix("Basic "))
                {
                    let v = String::from_utf8(BASE64_STANDARD.decode(h).ok()?).ok().filter(|v| !v.is_empty())?;
                    v.split_once(':')
                        .map_or_else(
                            || (None, v.to_string()),
                            |(user, key)| if key.is_empty() {
                                // apparently `foo@bar.com` translates to
                                // `basic foo:` rather than `basic foo`
                                (None, user.to_string())
                            } else {
                                (Some(user.to_string()), key.to_string())
                            }
                        ).into()
                } else {
                    None
                }
            })
            .map(|(a, b)| Authorization(a, b))
            .ok_or_else(|| {
                Error::Unauthenticated("You must be logged in to do that.")
                    .into_response_full(
                        "guides",
                        "getting-started-with-the-rest-api",
                        "authentication",
                    )
            })
    }
}

#[rustfmt::skip]
pub fn routes(st: Config) -> Router {
    Router::new()
        .route("/user", get(get_current_user))
        .route("/user/emails", get(get_current_user_emails))
        .route("/user/repository_invitations/:id", patch(accept_invitation))
        .route("/users/:name", get(get_user))
        .route("/orgs/:name", get(get_org))
        .route("/user/repos", post(create_repository))
        .route("/orgs/:name/repos", post(create_repository))
        .route("/rate_limit", get(rate_limit))
        .route("/graphql", post(graphql))
        .merge(repos::routes())
        .fallback(|| async { Error::NotFound.into_response("", "") })
        .with_state(Arc::new(st))
}

async fn get_current_user(
    auth: Authorization,
) -> Result<
    ([(&'static str, &'static str); 1], Json<PublicUser>),
    GHError<'static>,
> {
    let mut db = Source::get();
    let tx = &db.token();
    auth_to_user(tx, auth)
        .ok_or_else(|| {
            Error::Unauthenticated("Requires authentication")
                .into_response("users", "get-the-authenticated-user")
        })
        .map(|u| {
            (
                [("X-OAuth-Scopes", "user:email")],
                Json(PublicUser::from(u)),
            )
        })
}

async fn get_current_user_emails(
    auth: Authorization,
) -> Result<Json<Vec<Email>>, GHError<'static>> {
    let mut db = Source::get();
    let tx = &db.token();
    auth_to_user(tx, auth)
        .ok_or_else(|| {
            Error::Unauthenticated("Requires authentication")
                .into_response("users", "get-the-authenticated-user")
        })
        .map(|u| {
            Json(
                list_user_emails(tx, &u.id)
                    .into_iter()
                    .map(Email::from)
                    .collect(),
            )
        })
}

/// Accepts a repository invitation (based on a global id), see
/// [`add_collaborator`](repos/fn.add_collaborator.html) for details
///
/// Returns:
/// - 204 (no content) if accepted
/// - 304 (not modified) ???
/// - 403 (forbidden) ???
/// - 404 (not found) ???
/// - 409 (conflict) ???
async fn accept_invitation(Path(_invitation_id): Path<usize>) -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn get_user(
    Path(username): Path<String>,
) -> Result<Json<PublicUser>, GHError<'static>> {
    let mut db = Source::get();
    let tok = &db.token();
    crate::model::users::get_user(tok, &username)
        .ok_or_else(|| Error::NotFound.into_response("users", "get-a-user"))
        .map(
            // NOTE: works fine for API, but not web
            |u| Json(PublicUser::from(u)),
        )
}

async fn get_org(
    State(st): State<St>,
    Path(orgname): Path<String>,
) -> Result<Json<OrganizationFull>, GHError<'static>> {
    use crate::model::users::*;
    let _span = span!(Level::INFO, "get-org").entered();
    let mut db = Source::get();
    let tx = &db.token();
    get_user(tx, &orgname)
        .filter(|u| matches!(u.r#type, Type::Organization))
        .ok_or_else(|| {
            info!("{orgname} not found");
            Error::NotFound.into_response("orgs", "get-an-organization")
        })
        .map(|u| {
            info!("{orgname} found => {u:?}");
            Json(OrganizationFull {
                id: 0,
                node_id: String::new(),
                url: format!("{}/orgs/{}", st.root, u.login),
                r#type: match u.r#type {
                    Type::User => UserType::User,
                    Type::Organization => UserType::Organization,
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
            })
        })
}

const NAME_TOO_LONG: Error = Error::Unprocessable(
    "Repository creation failed.",
    &[Error::repo("name is too long (maximum is 100 characters)")],
);
const REPO_CREATION_FAILED: Error = Error::Unprocessable(
    "Repository creation failed.",
    &[Error::repo("name already exists on this account")],
);
async fn create_repository(
    auth: Option<Authorization>,
    State(st): State<St>,
    owner: Option<Path<String>>,
    Json(request): Json<CreateRepositoryRequest>,
) -> Result<Response, GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token_eager();
    let _span = span!(Level::INFO, "create-a-repository").entered();
    let owner = owner.as_deref().map_or("", |o| &**o);
    let endpoint = if owner.is_empty() {
        "create-a-repository-for-the-authenticated-user"
    } else {
        "create-an-organization-repository"
    };
    let Some(u) = auth.and_then(|a| auth_to_user(&tx, a)) else {
        return Err(Error::Unauthenticated("Requires authentication")
            .into_response("repos", endpoint));
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
        return Err(NAME_TOO_LONG.into_response("repos", endpoint));
    }

    let Some(owner) =
        owner.is_empty().then(|| u.clone())
            .or_else(|| crate::model::users::get_user(&tx, owner)) else {
        return Err(Error::NotFound.into_response("repos", endpoint));
    };

    let Some(repo) = crate::model::repos::create_repository(&tx, u.id, owner.id, &name, None) else {
        return Err(REPO_CREATION_FAILED.into_response("repos", endpoint));
    };

    info!("Created repository {}/{}", owner.login, name);
    if request.auto_init {
        let readme = crate::model::git::store(
            &tx,
            repo.network,
            git_object::BlobRef::from_bytes(b"").unwrap(),
        );
        let mut t = git_object::TreeRef::empty();
        t.entries.push(git_object::tree::EntryRef {
            mode: git_object::tree::EntryMode::Blob,
            filename: "README".into(),
            oid: &readme,
        });
        let tree = crate::model::git::store(&tx, repo.network, t);
        let sig = git_actor::SignatureRef {
            name: u.login.as_ref().into(),
            // FIXME: email for default signature?
            email: u
                .email
                .as_ref()
                .map(Cow::as_ref)
                .unwrap_or("user@example.org")
                .into(),
            time: git_actor::Time::now_utc(),
        };
        let c = crate::model::git::store(
            &tx,
            repo.network,
            git_object::CommitRef {
                tree: BString::from(tree.to_hex().to_string()).as_ref(),
                parents: Default::default(),
                author: sig.clone(),
                committer: sig,
                encoding: None,
                message: BStr::new(b"Initial commit"),
                extra_headers: Vec::new(),
            },
        );
        crate::model::git::refs::create(
            &tx,
            repo.id,
            &format!("refs/heads/{}", repo.default_branch),
            &c,
        );
    }
    let r = Json(repo.to_response(&tx, &st.root)).into_response();
    tx.commit().unwrap();
    Ok(r)
}

async fn rate_limit() -> ([(&'static str, &'static str); 1], Json<RateLimit>) {
    (
        [(
            "X-OAuth-Scopes",
            "admin:repo_hook, delete_repo, public_repo, user:email",
        )],
        Json(RateLimit::default()),
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
async fn graphql(
    auth: Authorization,
    State(st): State<St>,
    Json(request): Json<GraphqlRequest>,
) -> Json<GraphqlResponse> {
    let mut db = Source::get();
    let tx = db.token_eager();
    let Some(user) = auth_to_user(&tx, auth) else {
        return Json(GraphqlResponse {
            data: None,
            errors: vec![GraphqlError {
                message: "Unknown user".into()
            }]
        });
    };
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
        return Json(GraphqlResponse {
            data: None,
            errors: vec![GraphqlError {
                message:
                    "Invalid query, only updating draft status is kinda handled"
                        .into(),
            }],
        });
    };

    let pid: Pid =
        serde_json::from_str(request.variables["pid"].as_str().unwrap())
            .unwrap();

    let Some(pr) = crate::model::prs::find_by_id(&tx, pid.0) else {
        return Json(GraphqlResponse {
            data: None,
            errors: vec![GraphqlError {
                message: "PR not found".into(),
            }]
        });
    };

    if !crate::model::prs::can_write(&tx, user.id, pr.id) {
        return Json(GraphqlResponse {
            data: None,
            errors: vec![GraphqlError {
                message: "No write access".into(),
            }],
        });
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

        Json(GraphqlResponse {
            data: Some(()),
            errors: vec![],
        })
    } else {
        Json(GraphqlResponse {
            data: None,
            errors: vec![GraphqlError {
                message: "something bad happened".into(),
            }],
        })
    }
}

#[derive(Serialize, Deserialize)]
struct Pid(i64);
