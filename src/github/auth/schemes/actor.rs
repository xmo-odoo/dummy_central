/*!
 * "Actor" auth is just install | user.
 */
use std::sync::Arc;

use axum::extract::FromRequestParts;
use http::request::Parts;

use crate::model::users::ActorId;

use super::install;
use super::user;

use super::utils::Error;

/// Interaction is authenticated as an *actor*, which can be a user or an
/// installation (a bot).
///
/// The source auths are not retained because it doesn't have much value: if
/// authorization gets implemented, UserId can have both scopes (cPAT, oauth
/// app UAT) and permissions (FGT, git app UAT), so wouldn't make sense to
/// keep them down into the sub-auth anyway.
#[derive(Debug)]
pub struct Auth {
    pub actor: ActorId,
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
        if let Ok(auth) =
            <install::Auth>::from_request_parts(parts, state).await
        {
            Ok(Auth {
                actor: auth.installation.into(),
            })
        } else if let Ok(auth) =
            <user::Auth>::from_request_parts(parts, state).await
        {
            Ok(Auth {
                actor: auth.user.into(),
            })
        } else {
            Err(Error::unauthorized())
        }
    }
}

trait AuthState: user::AuthState + install::AuthState {}
impl AuthState for Arc<crate::github::Config> {}
