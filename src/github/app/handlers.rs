use std::collections::HashMap;

use aws_lc_rs::encoding::AsDer as _;
use axum::{
    Form, Json,
    extract::{Path, Query, State},
    response::{IntoResponse as _, Response},
};
use base64::Engine as _;
use github_types::{
    app::Installation,
    users::SimpleUser,
    webhooks::{Hook, HookType, Webhook, WebhookEvent},
};
use serde::{Deserialize, Serialize};
use tracing::{Span, instrument};

use crate::{
    github::{
        HookConfig, St,
        auth::{ApplicationAuth, OAuthAuth, UserAuth},
    },
    model::{
        Read, Token, Write,
        users::{self, UserId},
    },
};

#[derive(Debug, Deserialize)]
pub(super) struct CreateParams {
    pub state: String,
}

#[derive(Debug, Deserialize)]
pub(super) struct CreateBody {
    pub manifest: String,
}

#[derive(Debug, Deserialize)]
struct Manifest {
    redirect_url: String,

    name: String,
    description: String,
    public: bool,

    url: String,
    hook_attributes: HookAttributes,
    default_events: Vec<String>,
    default_permissions: HashMap<String, Permission>,

    request_oauth_on_install: bool,
    callback_urls: Vec<String>,
    setup_url: String,
    setup_on_update: bool,
}

// TODO: is this a full HookConfig, but with more secure defaults than repo?
#[derive(Debug, Deserialize)]
struct HookAttributes {
    url: String,
    // #[serde(default = "set_true")]
    // active: bool
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Permission {
    Read,
    Write,
}

impl From<Permission> for super::db::Permission {
    fn from(value: Permission) -> Self {
        match value {
            Permission::Read => Self::Read,
            Permission::Write => Self::Write,
        }
    }
}
impl TryFrom<(UserId, Manifest)> for super::db::Manifest {
    type Error = ();

    fn try_from(
        (
            owner,
            Manifest {
                name,
                description,
                public,
                url,
                hook_attributes,
                default_events,
                default_permissions,
                request_oauth_on_install,
                mut callback_urls,
                setup_url,
                setup_on_update,
                ..
            },
        ): (UserId, Manifest),
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            owner,
            public,
            name,
            description: description.into(),
            url,
            request_oauth_on_install,
            setup_on_update,
            setup_url,
            callback_urls: if callback_urls.len() == 1 {
                callback_urls.pop().expect("")
            } else {
                return Err(());
            },
            webhook_url: hook_attributes.url,
            // TODO: validate events (?)
            events: default_events,
            permissions: default_permissions
                .into_iter()
                .map(|(scope, access)| (scope, access.into()))
                .collect(),
        })
    }
}

#[instrument(skip(auth, tx))]
pub async fn create_app(
    auth: UserAuth,
    State(_): State<St>,
    tx: Token<Write>,
    org: Option<Path<String>>,
    Query(CreateParams { state }): Query<CreateParams>,
    Form(form): Form<CreateBody>,
) -> Response {
    let mut manifest =
        serde_json::from_str::<Manifest>(&form.manifest).unwrap();

    let owner = if let Some(Path(org)) = org {
        let Some(u) = crate::model::users::get_user(&tx, &org).and_then(|u| {
            if let crate::model::users::Type::Organization = u.r#type {
                Some(u.id)
            } else {
                None
            }
        }) else {
            todo!()
        };
        u
    } else {
        auth.user
    };

    let redirect_url = std::mem::take(&mut manifest.redirect_url);
    let code = {
        let code = uuid::Uuid::new_v4();
        super::db::create_pending(
            &tx,
            code,
            &(owner, manifest).try_into().unwrap(),
        );
        code
    };

    tx.commit();
    let redir = url::Url::parse_with_params(
        &redirect_url,
        &[("code", &code.simple().to_string()), ("state", &state)],
    )
    .unwrap();
    axum::response::Redirect::to(redir.as_str()).into_response()
}

#[derive(Debug, Serialize)]
pub struct CreatedApp {
    id: i64,
    name: String,
    slug: String,
    description: String,
    // node_id: String,
    owner: SimpleUser,
    external_url: String,
    html_url: String,
    // created_at: String,
    // updated_at: String,
    permissions: HashMap<String, &'static str>,
    events: Vec<String>,
    client_id: String,
    client_secret: String,
    webhook_secret: String,
    pem: String,
}

pub async fn finalize_app(
    State(st): State<St>,
    tx: Token<Write>,
    Path(code): Path<String>,
) -> Json<CreatedApp> {
    let appinfo = uuid::Uuid::try_parse(&code)
        .ok()
        .and_then(|uuid| super::db::finalize(&tx, uuid))
        .unwrap();

    let user = crate::model::users::get_by_id(&tx, appinfo.owner);
    let hook = super::db::get_hook(&tx, appinfo.id);
    tx.commit();
    if let Some(crate::model::repos::Hook {
        id,
        active,
        content_type,
        url,
        events,
        insecure_ssl,
        ..
    }) = hook
    {
        let secret = "********".to_owned();
        st.webhooks
            .send((
                HookConfig {
                    id,
                    active,
                    url: url.clone(),
                    content_type: content_type.into(),
                    events: events.iter().copied().collect(),
                    secret: secret.clone(),
                    insecure_ssl,
                },
                Webhook {
                    sender: SimpleUser::default(),
                    repository: None,
                    event: WebhookEvent::Ping {
                        zen: String::new(),
                        hook_id: id,
                        hook: Hook {
                            r#type: HookType::App,
                            id,
                            app_id: Some(*appinfo.id),
                            name: github_types::webhooks::HookName::Web,
                            active,
                            events: events.clone(),
                            config: github_types::repos::CreateHookConfig {
                                url: url.clone(),
                                content_type: content_type.into(),
                                secret,
                                insecure_ssl,
                            },
                            created_at: String::new(),
                            updated_at: String::new(),
                            url: None,
                            test_url: None,
                            ping_url: None,
                            deliveries_url:
                                "https://api.github.com/app/hook/deliveries"
                                    .to_string(),
                            last_response: None,
                        },
                    },
                },
                Span::current(),
            ))
            .unwrap();
    }
    Json(CreatedApp {
        id: *appinfo.id,
        description: appinfo.description.unwrap_or_default(),
        owner: user.into_simple(&st.root),
        external_url: appinfo.url,
        html_url: format!("https://github.com/apps/{}", appinfo.slug),
        permissions: appinfo
            .permissions
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    match v {
                        crate::github::app::db::Permission::Read => "read",
                        crate::github::app::db::Permission::Write => "write",
                    },
                )
            })
            .collect(),
        events: appinfo.events,
        client_id: appinfo.client_id,
        client_secret: appinfo.client_secret,
        webhook_secret: appinfo.webhook_secret,
        pem: {
            // aws-lc always generates a PCKS#8 DER, so needs the right header
            // (no RSA mention, that's PCKS#1)
            let buffer = appinfo.key.as_der().expect("");
            let mut encoded_key = "-----BEGIN PRIVATE KEY-----\n".to_string();
            // PEM encoding is base64 of the entire key, split at exactly 64
            // characters
            for data in base64::prelude::BASE64_STANDARD
                .encode(buffer.as_ref())
                .as_bytes()
                .chunks(64)
            {
                encoded_key.push_str(
                    std::str::from_utf8(data)
                        .expect("base64 to always be valid text"),
                );
                encoded_key.push('\n');
            }
            encoded_key + "-----END PRIVATE KEY-----\n"
        },
        name: appinfo.name,
        slug: appinfo.slug,
    })
}

#[derive(Deserialize)]
pub struct InstallParams {
    // only allows this target (?)
    target_id: i64,
    // displays an account picker on gh, but highlights the suggested one
    // suggested_target_id: i64,
    // repository_ids: Option<Vec<String>>,
    // ? repository_id: Option<String> ?
}
pub async fn install_app(
    State(st): State<St>,
    tx: Token<Write>,
    auth: UserAuth,
    Path(appslug): Path<String>,
    Query(InstallParams { target_id }): Query<InstallParams>,
) -> Response {
    // FIXME: app visibility / acl
    let appid = super::db::id_by_slug(&tx, &appslug).unwrap();
    // FIXME: can only install an application into own account or into org
    //        account if owner
    let target = users::get_by_i64(&tx, target_id)
        .filter(|u| !matches!(u.r#type, users::Type::Bot))
        .unwrap();

    let installation_id = super::db::install_into(&tx, appid, target.id);

    let app = super::db::by_id(&tx, appid);

    if let Some(crate::model::repos::Hook {
        id,
        active,
        content_type,
        url,
        events,
        insecure_ssl,
        ..
    }) = super::db::get_hook(&tx, appid)
    {
        let user = users::get_by_id(&tx, auth.user);
        let target_id =
            super::db::get_installation(&tx, installation_id).unwrap();
        let target = users::get_by_id(&tx, target_id);
        st.webhooks
            .send((
                HookConfig {
                    id,
                    active,
                    url,
                    content_type: content_type.into(),
                    events,
                    secret: "******".into(),
                    insecure_ssl,
                },
                Webhook {
                    sender: user.into_simple(&st.root),
                    repository: None,
                    event: WebhookEvent::Installation(
                        github_types::webhooks::Installation::Created {
                            installation: Installation {
                                id: installation_id,
                                app_id: *appid,
                                target_id: *target_id,
                                target_type: target.r#type.into(),
                                account: target.into_simple(&st.root),
                                app_slug: app.slug,
                            },
                        },
                    ),
                },
                Span::current(),
            ))
            .unwrap();
    }

    let mut params = Vec::with_capacity(3);
    params.push(("setup_action", "install"));
    let iid = installation_id.to_string();
    params.push(("installation_id", &iid));
    let code;
    let url = if app.request_oauth_on_install {
        // immediately starts an oauth flow
        code = super::db::create_pending_authorization(&tx, appid, auth.user);
        tx.commit();
        params.push(("code", &code));
        &app.callback_urls
    } else {
        tx.commit();
        if app.setup_url.is_empty() {
            // if there is no setup_url, github redirects to the installation
            // page in the account and the app receives the info solely via
            // the installation.created webhook (which is what it should trust
            // anyway)
            params.clear();
            &format!("{}/settings/installations/{installation_id}", st.root)
        } else {
            &app.setup_url
        }
    };
    let redir = url::Url::parse_with_params(url, &params).unwrap();
    axum::response::Redirect::to(redir.as_str()).into_response()
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    client_id: String,
}
pub async fn authorize_app(
    auth: UserAuth,
    tx: Token<Write>,
    Query(q): Query<AuthorizeQuery>,
) -> axum::response::Redirect {
    let appid = super::db::id_by_client_id(&tx, &q.client_id).unwrap();
    let code = super::db::create_pending_authorization(&tx, appid, auth.user);
    let app = super::db::by_id(&tx, appid);
    tx.commit();
    let redir =
        url::Url::parse_with_params(&app.callback_urls, &[("code", &code)])
            .unwrap();
    axum::response::Redirect::to(redir.as_str())
}

#[derive(Debug, Deserialize)]
pub(super) struct AuthorizeParams {
    pub client_id: String,
    pub client_secret: String,
    pub code: String,
}
#[derive(Debug, Serialize)]
pub struct AuthorizeResponse {
    access_token: String,
    expires_in: u32,
    refresh_token: String,
    refresh_token_expires_in: u32,
}
pub async fn finalize_authorize(
    tx: Token<Write>,
    Query(q): Query<AuthorizeParams>,
) -> Form<AuthorizeResponse> {
    let appid =
        super::db::id_by_secret(&tx, &q.client_id, &q.client_secret).unwrap();
    let auth =
        super::db::validate_pending_authorization(&tx, appid, q.code).unwrap();
    tx.commit();
    Form(AuthorizeResponse {
        access_token: format!("ghu_{}", auth.access_token.as_simple()),
        expires_in: 8 * 3600,
        refresh_token: format!("ghr_{}", auth.refresh_token.as_simple()),
        refresh_token_expires_in: 184 * 24 * 3600,
    })
}

#[derive(Debug, Deserialize)]
pub(super) struct AccessToken {
    pub access_token: String,
}
#[derive(Serialize)]
pub struct TokenResponse {
    id: i64,
    app: ShortApp,
    created_at: String,
    updated_at: String,
    expires_at: String,
    fingerprint: Option<()>,
    note: Option<String>,
    note_url: Option<String>,
    // dead for gh apps
    scopes: Vec<String>,
    token: String,
    token_last_eight: String,
    url: String,
    user: SimpleUser,
}
#[derive(Serialize)]
pub struct ShortApp {
    client_id: String,
    name: String,
    url: String,
}
pub async fn check_token(
    State(st): State<St>,
    tx: Token<Read>,
    auth: OAuthAuth,
    Path(_): Path<String>,
    Json(AccessToken { access_token }): Json<AccessToken>,
) -> Result<Json<TokenResponse>, http::StatusCode> {
    let Some(raw_token) = access_token.strip_prefix("ghu_") else {
        return Err(http::StatusCode::UNPROCESSABLE_ENTITY);
    };
    // TODO: test what happens if the client_id from the auth and path differ
    super::db::get_authorization(&tx, auth.appid, raw_token)
        .map(|auth| {
            let app = super::db::by_id(&tx, auth.application);
            let user = users::get_by_id(&tx, auth.user);
            Json(TokenResponse {
                id: auth.id,
                app: ShortApp {
                    client_id: app.client_id,
                    name: app.name,
                    url: app.url,
                },
                created_at: String::new(),
                updated_at: String::new(),
                expires_at: chrono::DateTime::from_timestamp(
                    auth.expires_at,
                    0,
                )
                .unwrap()
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                fingerprint: None,
                note: None,
                note_url: None,
                scopes: Vec::new(),
                token_last_eight: access_token[access_token.len() - 8..]
                    .to_owned(),
                token: access_token,
                url: format!("{}/authorizations/{}", &st.root, auth.id),
                user: user.into_simple(&st.root),
            })
        })
        .ok_or(http::StatusCode::NOT_FOUND)
}

pub async fn delete_authorization(
    State(st): State<St>,
    tx: Token<Write>,
    auth: OAuthAuth,
    Path(_): Path<String>,
    Json(AccessToken { access_token }): Json<AccessToken>,
) -> http::StatusCode {
    let Some(raw_token) = access_token.strip_prefix("ghu_") else {
        return http::StatusCode::UNPROCESSABLE_ENTITY;
    };
    // TODO: test what happens if the client_id from the auth and path differ
    if let Some(target_id) =
        super::db::delete_authorization(&tx, auth.appid, raw_token)
    {
        if let Some(crate::model::repos::Hook {
            id,
            active,
            content_type,
            url,
            events,
            insecure_ssl,
            ..
        }) = super::db::get_hook(&tx, auth.appid)
        {
            // when the application revokes an authorization, the auth target
            // is still the sender so can't differentiate between a user
            // revoking an authorization and the app doing that, but since
            // the sender is the only metadata it does allow nuking the auth
            // record
            let target = users::get_by_id(&tx, target_id);
            st.webhooks
                .send((
                    HookConfig {
                        id,
                        active,
                        url,
                        content_type: content_type.into(),
                        events,
                        secret: "******".into(),
                        insecure_ssl,
                    },
                    Webhook {
                        sender: target.into_simple(&st.root),
                        repository: None,
                        event: WebhookEvent::Authorization(
                            github_types::webhooks::Authorization::Revoked,
                        ),
                    },
                    Span::current(),
                ))
                .unwrap();
        }
        tx.commit();
        // TODO: token info
        http::StatusCode::OK
    } else {
        http::StatusCode::UNPROCESSABLE_ENTITY
    }
}

pub async fn list_installations(
    State(st): State<St>,
    auth: ApplicationAuth,
    tx: Token<Read>,
) -> Json<Vec<Installation>> {
    let accounts = super::db::list_installations(&tx, auth.appid);
    let app = super::db::by_id(&tx, auth.appid);

    Json(
        accounts
            .into_iter()
            .map(|(id, uid)| {
                let user = users::get_by_id(&tx, uid);
                Installation {
                    id,
                    app_id: *app.id,
                    target_id: *uid,
                    target_type: user.r#type.into(),
                    account: user.into_simple(&st.root),
                    app_slug: app.slug.clone(),
                }
            })
            .collect(),
    )
}
pub async fn delete_installation(
    State(st): State<St>,
    tx: Token<Write>,
    auth: ApplicationAuth,
    Path(installation_id): Path<i64>,
) -> http::StatusCode {
    if let Some((iid, target_id)) =
        super::db::delete_installation(&tx, auth.appid, installation_id)
    {
        if let Some(crate::model::repos::Hook {
            id,
            active,
            content_type,
            url,
            events,
            insecure_ssl,
            ..
        }) = super::db::get_hook(&tx, auth.appid)
        {
            let app = super::db::by_id(&tx, auth.appid);
            // when the application deletes an installation, the owner of the
            // app is the sender (I'd kinda have expected the app itself)
            let owner = users::get_by_id(&tx, app.owner);
            let target = users::get_by_id(&tx, target_id);
            st.webhooks
                .send((
                    HookConfig {
                        id,
                        active,
                        url,
                        content_type: content_type.into(),
                        events,
                        secret: "******".into(),
                        insecure_ssl,
                    },
                    Webhook {
                        sender: owner.into_simple(&st.root),
                        repository: None,
                        event: WebhookEvent::Installation(
                            github_types::webhooks::Installation::Deleted {
                                installation: Installation {
                                    id: iid,
                                    app_id: *auth.appid,
                                    target_id: *target_id,
                                    target_type: target.r#type.into(),
                                    account: target.into_simple(&st.root),
                                    app_slug: app.slug,
                                },
                            },
                        ),
                    },
                    Span::current(),
                ))
                .unwrap();
        }
        tx.commit();
        http::StatusCode::ACCEPTED
    } else {
        http::StatusCode::NOT_FOUND
    }
}

#[derive(Serialize, Debug)]
pub struct InstallationToken {
    token: String,
    expires_at: String,
    // permissions: Permissions
    // repository_selection: enum  { Selected, ??? }
    // repositories: Vec<looks like RepositoryResponse but doesn't match>
}
#[derive(Deserialize, Debug)]
pub struct InstallationTokenRequest {
    #[serde(default)]
    repositories: Vec<String>,
    #[serde(default)]
    repository_ids: Vec<i64>,
    #[serde(default)]
    permissions: HashMap<String, Permission>,
}
pub async fn create_iat(
    tx: Token<Write>,
    auth: ApplicationAuth,
    Path(installation_id): Path<i64>,
    Json(_): Json<InstallationTokenRequest>,
) -> Json<InstallationToken> {
    let token = uuid::Uuid::new_v4();
    let Some(expiry) =
        super::db::installation_token(&tx, auth.appid, installation_id, token)
    else {
        todo!();
    };
    tx.commit();
    Json(InstallationToken {
        token: format!("ghs_{}", token.as_simple()),
        expires_at: chrono::DateTime::from_timestamp(expiry, 0)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    })
}
