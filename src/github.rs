/*!
# Straight pseudo-github implementation.
 */
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Arc;

use axum::extract::{FromRequestParts, OptionalFromRequestParts, Path, State};
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post};
use axum::{Json, Router};
use base64::prelude::{BASE64_STANDARD, Engine as _};
use gix_object::bstr::{BStr, BString};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::Sha256;
use tokio::sync::mpsc::{
    UnboundedReceiver, UnboundedSender, unbounded_channel,
};
use tracing::field::Empty;
use tracing::*;

use github_types::RateLimit;
use github_types::orgs::OrganizationFull;
use github_types::repos::{
    CreateRepositoryRequest, HookContentType, MinimalRepository,
    RepositoryResponse,
};
use github_types::users::{Email, PublicUser, SimpleUser, UserType};
use github_types::webhooks::Webhook;

use crate::model::repos::Repository;
use crate::model::users::{
    Email as ModelEmail, Type, User, Visibility, find_current_user,
    list_user_emails,
};
use crate::model::{Read, Token, Write};

mod graphql;
mod repos;

fn either_empty<T>(v: &either::Either<serde_json::Value, &[T]>) -> bool {
    v.as_ref().right().filter(|s| s.is_empty()).is_some()
}

#[derive(Serialize)]
struct GithubError<'a> {
    message: Cow<'a, str>,
    documentation_url: &'a str,
    #[serde(
        with = "either::serde_untagged",
        skip_serializing_if = "either_empty"
    )]
    errors: either::Either<serde_json::Value, &'a [GithubErrorDetails<'a>]>,
    status: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<serde_json::Value>,
}
#[derive(Serialize, Copy, Clone, Debug)]
struct GithubErrorDetails<'a> {
    resource: &'a str,
    #[serde(skip_serializing_if = "<str>::is_empty")]
    field: &'a str,
    code: &'a str,
    #[serde(skip_serializing_if = "<str>::is_empty")]
    message: &'a str,
    // FIXME: this should actually be a serde_json::Value (probably) but lifetime issues
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
    pub insecure_ssl: bool,
}
type HookEvent = (HookConfig, Webhook, Span);
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
        let user_agent =
            format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10)) // matches github
            .pool_max_idle_per_host(1) // only one hooks worker
            .build()
            .expect("Couldn't build a client!");

        // note: github can send hooks mis-ordered, probably because
        //       it has multiple webhook workers, maybe even multiple
        //       webhook queues.
        while let Some((conf, event, source)) = r.recv().await {
            {
                let tx = Token::<Read>::get().await.unwrap();
                let MinimalRepository { owner, name, .. } = &event.repository;
                if crate::model::repos::id_by_name(&tx, &owner.login, name)
                    .is_none()
                {
                    continue;
                }
            }

            // TODO: store history (?), send in a separate Task (to add concurrency)?
            let delivery_id = uuid::Uuid::new_v4().to_string();
            let span = span!(
                parent: &source,
                Level::INFO,
                "webhook",
                otel.name = format!("webhook:{}", event.event.name()),
                event = event.event.name(),
                status = Empty,
                error = Empty,
                delivery_id = delivery_id,
            )
            .entered();
            span.follows_from(source.id());
            let mut req = client
                .post(&conf.url)
                .header("User-Agent", &user_agent)
                .header("X-Github-Delivery", &delivery_id)
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
            let Ok(mut req) = req.build().inspect_err(|e| {
                span.record("error", e as &dyn std::error::Error);
            }) else {
                continue;
            };
            #[cfg(feature = "otlp")]
            {
                use opentelemetry::global::get_text_map_propagator;
                use opentelemetry_http::HeaderInjector;
                use tracing_opentelemetry::OpenTelemetrySpanExt as _;
                let cx = span.context();
                get_text_map_propagator(|p| {
                    p.inject_context(
                        &cx,
                        &mut HeaderInjector(req.headers_mut()),
                    );
                });
            }

            if !conf.secret.is_empty() {
                let b = req
                    .body()
                    .expect("a body should have been set")
                    .as_bytes()
                    .expect("the body should not be a stream");

                let mac = Hmac::<Sha1>::new_from_slice(conf.secret.as_bytes())
                    .expect("hmac keys can be of any size")
                    .chain_update(b)
                    .finalize()
                    .into_bytes();
                let mac256 =
                    Hmac::<Sha256>::new_from_slice(conf.secret.as_bytes())
                        .expect("hmac keys can be of any size")
                        .chain_update(b)
                        .finalize()
                        .into_bytes();

                req.headers_mut().insert(
                    "X-Hub-Signature",
                    format!("sha1={}", hex::encode(mac))
                        .try_into()
                        .expect("hex should be a valid header value"),
                );
                req.headers_mut().insert(
                    "X-Hub-Signature-256",
                    format!("sha256={}", hex::encode(mac256))
                        .try_into()
                        .expect("hex should be a valid header value"),
                );
            }
            match client.execute(req).await {
                Ok(r) => {
                    span.record("status", r.status().as_str());
                    let tx = Token::<Write>::get().await.unwrap();
                    crate::model::repos::hook_set_last_response(
                        &tx,
                        conf.id,
                        r.status().as_u16(),
                    );
                    tx.commit();
                }
                Err(e) => {
                    // FIXME: otel integration apparently does not send events?
                    // tracing::error!(%e, "webhook delivery error");
                    span.record("error", &e as &dyn std::error::Error);
                    let tx = Token::<Write>::get().await.unwrap();
                    crate::model::repos::hook_set_last_response(
                        &tx, conf.id, 502,
                    );
                    tx.commit();
                }
            }
        }
    }
}

#[derive(Debug)]
struct GHError<'a> {
    error: Error<'a>,
    category: &'a str,
    section: &'a str,
    item: &'a str,
}
impl IntoResponse for GHError<'_> {
    fn into_response(self) -> Response {
        use either::{Left, Right};
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
            Error::NotFound(message) => (
                StatusCode::NOT_FOUND,
                Json(GithubError {
                    status: "404".into(),
                    message,
                    documentation_url,
                    errors: Right(&[]),
                    metadata: None,
                }),
            ),
            Error::Unauthenticated(message) => (
                StatusCode::UNAUTHORIZED,
                Json(GithubError {
                    status: "401".into(),
                    message: message.into(),
                    documentation_url,
                    errors: Right(&[]),
                    metadata: None,
                }),
            ),
            Error::Forbidden(message) => (
                StatusCode::FORBIDDEN,
                Json(GithubError {
                    status: "403".into(),
                    message: message.into(),
                    documentation_url,
                    errors: Right(&[]),
                    metadata: None,
                }),
            ),
            Error::Conflict(message, metadata) => (
                StatusCode::CONFLICT,
                Json(GithubError {
                    status: "409".into(),
                    message: message.into(),
                    documentation_url,
                    errors: Right(&[]),
                    metadata,
                }),
            ),
            Error::Unprocessable(message, errors) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(GithubError {
                    status: "422".into(),
                    message,
                    documentation_url,
                    errors: either::Either::Right(errors),
                    metadata: None,
                }),
            ),
            Error::UnprocessableValue(message, errors) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(GithubError {
                    status: "422".into(),
                    message,
                    documentation_url,
                    errors: Left(errors),
                    metadata: None,
                }),
            ),
        }
        .into_response()
    }
}

impl std::fmt::Display for GHError<'static> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match &self.error {
            Error::NotFound(c)
            | Error::Unprocessable(c, _)
            | Error::UnprocessableValue(c, _) => c,
            Error::Unauthenticated(m)
            | Error::Forbidden(m)
            | Error::Conflict(m, _) => m,
        })
    }
}
impl std::error::Error for GHError<'static> {}

#[derive(Debug)]
enum Error<'a> {
    NotFound(Cow<'a, str>),
    Unauthenticated(&'a str),
    Forbidden(&'a str),
    Conflict(&'a str, Option<serde_json::Value>),
    Unprocessable(Cow<'a, str>, &'a [GithubErrorDetails<'a>]),
    UnprocessableValue(Cow<'a, str>, serde_json::Value),
}
impl<'e> Error<'e> {
    const NOT_FOUND: Self = Self::NotFound(Cow::Borrowed("Not Found"));

    const fn unprocessable(
        m: &'e str,
        details: &'e [GithubErrorDetails<'e>],
    ) -> Self {
        Self::Unprocessable(Cow::Borrowed(m), details)
    }
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
    fn into_response(
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
            email: self.email.map(Into::into),
            login: self.login.into(),
            name: self.name.map(Into::into),
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
impl From<Type> for UserType {
    fn from(t: Type) -> Self {
        match t {
            Type::User => UserType::User,
            Type::Organization => UserType::Organization,
        }
    }
}
impl Repository {
    fn to_response<M>(&self, tx: &Token<M>, root: &str) -> RepositoryResponse {
        RepositoryResponse {
            id: *self.id,
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
            ..RepositoryResponse::new(root, &self.owner.login, &self.name)
        }
    }
}
type St = Arc<Config>;
fn auth_to_user<M>(
    tx: &Token<M>,
    auth: Authorization,
) -> Option<User<'static>> {
    find_current_user(tx, &auth.1)
}

#[derive(Debug)]
struct Authorization(Option<String>, String);
impl<S> OptionalFromRequestParts<S> for Authorization
where
    S: Send + Sync,
{
    type Rejection = GHError<'static>;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|h| {
                let h = h.to_str().ok()?;
                // auth-scheme SP data
                if let Some(h) = h.strip_prefix("token ") {
                    Some((None, h.to_string()))
                } else if let Some(h) = h
                    .strip_prefix("basic ")
                    .or_else(|| h.strip_prefix("Basic "))
                {
                    let v = String::from_utf8(BASE64_STANDARD.decode(h).ok()?)
                        .ok()
                        .filter(|v| !v.is_empty())?;
                    v.split_once(':')
                        .map_or_else(
                            || (None, v.to_string()),
                            |(user, key)| {
                                if key.is_empty() {
                                    // apparently `foo@bar.com` translates to
                                    // `basic foo:` rather than `basic foo`
                                    (None, user.to_string())
                                } else {
                                    (Some(user.to_string()), key.to_string())
                                }
                            },
                        )
                        .into()
                } else {
                    None
                }
            })
            .map(|(a, b)| Authorization(a, b)))
    }
}
impl<S> FromRequestParts<S> for Authorization
where
    S: Send + Sync,
{
    type Rejection = GHError<'static>;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        <Authorization as OptionalFromRequestParts<S>>::from_request_parts(
            parts, state,
        )
        .await
        .and_then(|r| match r {
            Some(r) => Ok(r),
            None => Err(Error::Unauthenticated("Requires authentication")
                .into_response("", "", "")),
        })
    }
}

#[rustfmt::skip]
pub fn routes(st: Config) -> Router {
    Router::new()
        .route("/user", get(get_current_user))
        .route("/user/emails", get(get_current_user_emails))
        .route("/user/repository_invitations", get(get_invitations))
        .route("/user/repository_invitations/{id}", patch(accept_invitation))
        .route("/users/{name}", get(get_user))
        .route("/orgs/{name}", get(get_org))
        .route("/user/repos", post(create_repository))
        .route("/orgs/{name}/repos", post(create_repository))
        .route("/rate_limit", get(rate_limit))
        .merge(graphql::routes())
        .merge(repos::routes())
        .fallback(|| async { Error::NOT_FOUND.into_response("reference", "", "") })
        .with_state(Arc::new(st))
}

#[allow(clippy::type_complexity)]
#[instrument(skip(tx))]
async fn get_current_user(
    auth: Authorization,
    tx: Token<Read>,
) -> Result<
    ([(&'static str, &'static str); 1], Json<PublicUser>),
    GHError<'static>,
> {
    auth_to_user(&tx, auth)
        .ok_or_else(|| {
            Error::Unauthenticated("Requires authentication").into_response(
                "users",
                "users",
                "get-the-authenticated-user",
            )
        })
        .map(|u| {
            (
                [("X-OAuth-Scopes", "user:email")],
                Json(PublicUser::from(u)),
            )
        })
}

#[instrument(skip(tx))]
async fn get_current_user_emails(
    auth: Authorization,
    tx: Token<Read>,
) -> Result<Json<Vec<Email>>, GHError<'static>> {
    auth_to_user(&tx, auth)
        .ok_or_else(|| {
            Error::Unauthenticated("Requires authentication").into_response(
                "users",
                "users",
                "get-the-authenticated-user",
            )
        })
        .map(|u| {
            Json(
                list_user_emails(&tx, u.id)
                    .into_iter()
                    .map(Email::from)
                    .collect(),
            )
        })
}

/// Returns the list of invitations for current user.
///
/// - id
/// - node_id
/// - permissions (write/push/...)
/// - created_at
/// - url
/// - html_url
/// - inviter
/// - invitee
/// - repository
#[instrument]
async fn get_invitations() -> impl IntoResponse {
    (StatusCode::OK, b"[]")
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
#[instrument]
async fn accept_invitation(Path(_invitation_id): Path<usize>) -> StatusCode {
    StatusCode::NO_CONTENT
}

#[instrument(skip(tx))]
async fn get_user(
    tx: Token<Read>,
    Path(username): Path<String>,
) -> Result<Json<PublicUser>, GHError<'static>> {
    crate::model::users::get_user(&tx, &username)
        .map(PublicUser::from)
        .map(Json)
        .ok_or_else(|| {
            Error::NOT_FOUND.into_response("users", "users", "get-a-user")
        })
}

#[instrument(skip(st, tx))]
async fn get_org(
    State(st): State<St>,
    tx: Token<Read>,
    Path(orgname): Path<String>,
) -> Result<Json<OrganizationFull>, GHError<'static>> {
    let _span = span!(Level::INFO, "get-org").entered();
    crate::model::users::get_user(&tx, &orgname)
        .filter(|u| matches!(u.r#type, Type::Organization))
        .ok_or_else(|| {
            Error::NOT_FOUND.into_response(
                "orgs",
                "orgs",
                "get-an-organization",
            )
        })
        .map(|u| {
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
                default_repository_branch: u.default_branch,
            })
        })
}

const NAME_TOO_LONG: Error = Error::unprocessable(
    "Repository creation failed.",
    &[Error::repo("name cannot be more than 100 characters")],
);
const REPO_CREATION_FAILED: Error = Error::unprocessable(
    "Repository creation failed.",
    &[Error::repo("name already exists on this account")],
);
#[instrument(skip(st, tx), err(Debug, level=Level::INFO))]
async fn create_repository(
    auth: Authorization,
    State(st): State<St>,
    tx: Token<Write>,
    owner: Option<Path<String>>,
    Json(request): Json<CreateRepositoryRequest>,
) -> Result<Response, GHError<'static>> {
    let owner = owner.as_deref().map_or("", |o| &**o);
    let endpoint = if owner.is_empty() {
        "create-a-repository-for-the-authenticated-user"
    } else {
        "create-an-organization-repository"
    };
    let Some(u) = auth_to_user(&tx, auth) else {
        return Err(Error::Unauthenticated("Requires authentication")
            .into_response("repos", "repos", endpoint));
    };

    // Repository name can only contain ASCII letters,
    // numbers, `-`, `_`, and `.`, get auto-fixed at creation.
    // NOTE: normalization only occurs on creation
    let name = regex::Regex::new("[^[:alnum:]_.-]+")
        .expect("Regex should be valid.")
        .replace_all(&request.name, "-");

    // Suffix stripping is also done before length check
    let mut name = &name[..];
    while let Some(n) = name.strip_suffix(".git") {
        name = n;
    }

    // apparently length check is after replacement (at least
    // conceptually)
    if name.len() > 100 {
        return Err(NAME_TOO_LONG.into_response("repos", "repos", endpoint));
    }

    let Some(owner) = owner
        .is_empty()
        .then(|| u.clone())
        .or_else(|| crate::model::users::get_user(&tx, owner))
    else {
        return Err(Error::NOT_FOUND.into_response("repos", "repos", endpoint));
    };

    let Some(repo) =
        crate::model::repos::create_repository(&tx, u.id, owner.id, name, None)
    else {
        return Err(
            REPO_CREATION_FAILED.into_response("repos", "repos", endpoint)
        );
    };

    if request.auto_init {
        let Ok(r) = gix_object::BlobRef::from_bytes(b"");
        let readme = crate::model::git::store(&tx, repo.network, r);
        let mut t = gix_object::TreeRef::empty();
        t.entries.push(gix_object::tree::EntryRef {
            mode: gix_object::tree::EntryKind::Blob.into(),
            filename: "README".into(),
            oid: &readme,
        });
        let mut time_buf = Default::default();
        let tree = crate::model::git::store(&tx, repo.network, t);
        let sig = gix_actor::SignatureRef {
            name: u.login.as_ref().into(),
            // FIXME: email for default signature?
            email: u
                .email
                .as_ref()
                .map_or("user@example.org", Cow::as_ref)
                .into(),
            time: gix_date::Time::now_utc().to_str(&mut time_buf),
        };
        let c = crate::model::git::store(
            &tx,
            repo.network,
            gix_object::CommitRef {
                tree: BString::from(tree.to_string()).as_ref(),
                parents: Default::default(),
                author: sig,
                committer: sig,
                encoding: None,
                message: BStr::new(b"Initial commit"),
                extra_headers: Vec::new(),
            },
        );
        // even when creating a repo from a template (which we don't support
        // anyway) github does not copy over branch protection and rules
        // (cf orgs/community#55200) so there's no way this can fail.
        assert!(crate::model::git::refs::create(
            &tx,
            &repo,
            &format!("refs/heads/{}", repo.default_branch),
            &c,
        ));
    }
    let r = Json(repo.to_response(&tx, &st.root)).into_response();
    tx.commit();
    Ok(r)
}

#[instrument]
async fn rate_limit() -> ([(&'static str, &'static str); 1], Json<RateLimit>) {
    (
        [(
            "X-OAuth-Scopes",
            "admin:repo_hook, delete_repo, public_repo, user:email",
        )],
        Json(RateLimit::default()),
    )
}

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

impl From<Visibility> for github_types::users::Visibility {
    fn from(vis: Visibility) -> Self {
        match vis {
            Visibility::Public => Self::Public,
            Visibility::Private => Self::Private,
        }
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
#[derive(Serialize, Deserialize)]
struct Pid(i64);
