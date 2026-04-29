/*!
 * Installation Access Tokens (IATs) can be used for a few installation-related
 * operations, but they're mostly used for general-purpose API access, in which
 * case they identify the current actor as a `user.type: Bot`, whose
 * interactions a generally marked by postfixing the app's name with `[Bot]`,
 * or a little `(bot)` pill in the web UI ([e.g. bors][bors]). If the
 * application gets deleted, the bot user [is ghostified][].
 *
 * IATs respect the fine-grained permissions of the application (siloed to the
 * installation they are bound to), and can be further restricted on creation
 * (to a subset of repositories and permissions).
 *
 * IATs can be provided using a `Bearer` or `Token` scheme, followed by a value
 * with the prefix `ghs_` (IATs are also called server-to-server tokens).
 *
 * Historically IATs were composed of 22 bytes of random data (encoded to 30
 * bytes of base62) followed by a CRC32 (encoded to 6 bytes of base62,
 * 0-padded) but starting April 27th 2026 a [new format][] is rolling out which
 * instead contains the appid and a JWT, joined by an `_` (maybe, TBD). So
 * either way the only thing which should be considered stable about IATs (and
 * other non-JWT tokens to be honest) is the prefix, neither the payload nor the
 * length should be assumed / limited.
 *
 * [bors]: https://github.com/rust-lang/rust/pull/155909#issuecomment-4333983745
 * [is ghostified]: https://github.com/odoo-mergebot-testing-org/testrepo/pull/11#issuecomment-4260466482
 * [new format]: https://github.blog/changelog/2026-04-24-notice-about-upcoming-new-format-for-github-app-installation-tokens/
 */

use std::sync::Arc;

use axum::extract::FromRequestParts;
use http::request::Parts;

use crate::{
    github::auth::schemes::utils::Error,
    model::{Read, Token, users::InstallationId},
};

/// Interaction is authenticated as an installation, with restrictions
#[derive(Debug)]
pub struct Auth {
    pub installation: InstallationId,
    // restrictions (repositories, permissions)
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
        if !token.starts_with(b"ghs_") {
            return Err(Error::unauthorized());
        }
        state
            .installation_by_token(&token[4..])
            .await
            .map(|installation| Auth { installation })
            .ok_or(Error::unauthorized())
    }
}

pub trait AuthState: Sync + Send {
    fn installation_by_token(
        &self,
        token: &[u8],
    ) -> impl Future<Output = Option<InstallationId>> + Send;
}

impl AuthState for Arc<crate::github::Config> {
    async fn installation_by_token(
        &self,
        token: &[u8],
    ) -> Option<InstallationId> {
        let tx = Token::<Read>::get().await.ok()?;
        let uuid = uuid::Uuid::try_parse_ascii(token).ok()?;
        tx.query_one(
            "SELECT installation FROM installation_tokens WHERE value = ?",
            [uuid.as_bytes()],
            |row| row.get(0).map(InstallationId),
        ) // FIXME: should probably be `.optional()` separating "no token" from an SQL error
        .ok()
    }
}
