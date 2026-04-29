/*!
 * User auth comes in 3 different variations:
 *
 * - classic Personal Access Tokens (PAT), composed of the prefix `ghp_`
 *   followed by a 22 bytes (30 bytes base62) random payload and
 *   a CRC32 (6 bytes base62), these use broad (oauth) scopes and
 *   otherwise gives access to the entire account
 * - fine-grained (FGT) PATs, composed of the the prefix `github_pat_`
 *   and a weird and long payload, these tokens are bound to an owner
 *   and possibly restricted to a whitelist of repositories (can only
 *   read public resources aside from that), they use fine-grained
 *   permissions
 * - user access tokens (UATs), composed of the prefix `ghu_` and
 *   the same structure as classic PATs.
 *
 *   If they are created by oauth apps they use oauth scopes and are
 *   essentially the same thing as PATs, if they are created by
 *   github apps they use fine-grained permissions and can only
 *   interact with the intersection of repositories the application
 *   and the user have access to (via installations for the app).
 *   UATs are the only way for github apps to perform cross-owner
 *   operations between private repositories (and even then some
 *   don't work, iirc forking requires a PAT).
 *
 *   UATs can be restricted to *scoped tokens*, these are similar
 *   to FGTs and UATs in that they use fine-grained permissions but can
 *   only act within a `target` owner. Scoped tokens don't have their
 *   own identification (prefixed by `ghu_` and same apparent payload
 *   and schema TODO: check if scoped tokens have the same expiry date).
 *
 * These are *usually* interchangeable (limitations aside) and all provide
 * for impersonating an actual github user, but there are a few endpoints
 * which only work with classic PATs or UATs.
 */

use std::sync::Arc;

use axum::extract::FromRequestParts;
use http::request::Parts;

use crate::model::{Read, Token, users::UserId};

use super::utils::Error;

/// Interaction is authenticated as a user, with restrictions
#[derive(Debug)]
pub struct Auth {
    pub user: UserId,
    // TODO: restrictions
}

impl<S> FromRequestParts<S> for Auth
where
    S: AuthState,
{
    type Rejection = Error;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let token = super::utils::auth_for_schemes(
            &[b"Bearer", b"Token"],
            &parts.headers,
        )
        .ok_or(Error::unauthorized())?;
        if token.starts_with(b"ghp_") {
            state
                .user_by_pat(&token[4..])
                .await
                .map(|user| Auth { user })
                .ok_or(Error::unauthorized())
        } else if token.starts_with(b"ghu_") {
            state
                .user_by_uat(&token[4..])
                .await
                .map(|user| Auth { user })
                .ok_or(Error::unauthorized())
        } else if token.starts_with(b"github_pat_") {
            todo!("implement FGT")
        } else {
            Err(Error::unauthorized())
        }
    }
}

pub trait AuthState: Sync + Send {
    fn user_by_pat(
        &self,
        token: &[u8],
    ) -> impl Future<Output = Option<UserId>> + Send;
    fn user_by_uat(
        &self,
        token: &[u8],
    ) -> impl Future<Output = Option<UserId>> + Send;
}

impl AuthState for Arc<crate::github::Config> {
    async fn user_by_pat(&self, token: &[u8]) -> Option<UserId> {
        let tx = Token::<Read>::get().await.ok()?;
        let token = std::str::from_utf8(token)
            .expect("github token payloads should be ascii");
        tx.query_one(
            "SELECT user FROM tokens WHERE token = ?",
            [token],
            |row| row.get(0).map(UserId),
        )
        .ok() // FIXME: should probably be `.optional()` separating "no token" from an SQL error
    }
    async fn user_by_uat(&self, token: &[u8]) -> Option<UserId> {
        let tx = Token::<Read>::get().await.ok()?;
        let uuid = uuid::Uuid::try_parse_ascii(token).ok()?;
        tx.query_one(
            "SELECT user FROM authorizations WHERE access_token = ?",
            [uuid.as_bytes()],
            |row| row.get(0).map(UserId),
        )
        .ok() // FIXME: should probably be `.optional()` separating "no token" from an SQL error
    }
}
