/*!
 * OAuth app authentication is *not* oauth authentication. Instead it is the
 * authentication used by oauth apps when interacting with the authorizations
 * they obtain.
 *
 * - <https://docs.github.com/en/rest/apps/oauth-applications>
 * - <https://docs.github.com/en/rest/apps/apps#create-a-scoped-access-token>
 *   (just that one endpoint for creating scoped tokens, as they're sub-tokens
 *   of access tokens, which are part of the oauth app remit)
 *
 * OAuth app authentication is just basic auth off of an application's
 * `client_id` and `client_secret`, and can be used by both oauth apps
 * (which DC does not support) and github apps (which DC aims to support).
 */

use std::sync::Arc;

use axum::extract::FromRequestParts;
use headers::{Authorization, HeaderMapExt as _, authorization::Basic};
use http::request::Parts;

use crate::model::{Read, Token};

pub use super::app::AppId;

/// Interaction is auhenticated as an application
#[derive(Debug)]
pub struct Auth {
    pub appid: AppId,
}
impl<S> FromRequestParts<S> for Auth
where
    S: AuthState,
{
    type Rejection = http::StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let header: Authorization<Basic> = parts
            .headers
            .typed_get()
            .ok_or(http::StatusCode::UNAUTHORIZED)?;

        state
            .app_by_secret(header.username(), header.password())
            .await
            .ok_or(http::StatusCode::UNAUTHORIZED)
            .map(|appid| Auth { appid })
    }
}

pub trait AuthState: Sync + Send {
    fn app_by_secret(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> impl Future<Output = Option<AppId>> + Send;
}

impl AuthState for Arc<crate::github::Config> {
    async fn app_by_secret(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> Option<AppId> {
        Token::<Read>::get()
            .await
            .ok()?
            .query_one(
                "
                SELECT id
                FROM applications
                JOIN application_secrets ON (application = id)
                WHERE client_id = ? AND value = ?
                ",
                (client_id, client_secret),
                |row| row.get(0).map(AppId),
            )
            .ok()
    }
}
