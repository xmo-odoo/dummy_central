/*!
 * When interacting with a github git repository over http(s), the auth
 * has to be done via basic (unless it's just fetching from a public
 * repository obviously). There are a few possible scenarios:
 *
 * - for PATs, `{token}` (empty password) or `{login}:{token}` both work
 * - for UATs, ??? assume it works like PATs I guess...
 * - for IATs, the user has to be `x-auth-token`
 */

use std::sync::Arc;

use axum::extract::{FromRequestParts, OptionalFromRequestParts};
use headers::{Authorization, HeaderMapExt as _, authorization::Basic};
use http::{header::AUTHORIZATION, request::Parts};

#[derive(Debug)]
pub struct Auth(pub super::actor::Auth);
impl std::ops::Deref for Auth {
    type Target = super::actor::Auth;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
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
        let (username, token) = if header.password().is_empty() {
            (None, header.username())
        } else {
            (Some(header.username()), header.password())
        };
        if token.starts_with("ghs_") {
            if username != Some("x-access-token") {
                return Err(http::StatusCode::UNAUTHORIZED);
            }
            let iat = state
                .installation_by_token(&token.as_bytes()[4..])
                .await
                .ok_or(http::StatusCode::UNAUTHORIZED)?;
            Ok(Auth(super::actor::Auth { actor: iat.into() }))
        } else if token.starts_with("ghp_") {
            let user = state
                .user_by_pat(&token.as_bytes()[4..])
                .await
                .ok_or(http::StatusCode::UNAUTHORIZED)?;
            // TODO: if `username`, check that it matches the user's login
            Ok(Auth(super::actor::Auth { actor: user.into() }))
        } else if token.starts_with("ghu_") {
            let user = state
                .user_by_uat(&token.as_bytes()[4..])
                .await
                .ok_or(http::StatusCode::UNAUTHORIZED)?;
            // TODO: if `username`, check that it matches the user's login
            Ok(Auth(super::actor::Auth { actor: user.into() }))
        } else {
            // TODO: FTGs
            Err(http::StatusCode::UNAUTHORIZED)
        }
    }
}
trait AuthState: super::install::AuthState + super::user::AuthState {}
impl AuthState for Arc<crate::github::Config> {}

impl<S> OptionalFromRequestParts<S> for Auth
where
    S: AuthState,
{
    type Rejection = <Auth as FromRequestParts<S>>::Rejection;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        // TODO: what is supposed to happen if there is a token but it's
        //       invalid? Is it like no auth?
        if parts.headers.contains_key(AUTHORIZATION) {
            <Auth as FromRequestParts<S>>::from_request_parts(parts, state)
                .await
                .map(Some)
        } else {
            Ok(None)
        }
    }
}
