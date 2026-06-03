/*!
 * App authentication is used by the github app management endpoints, this is
 * mostly related to managing an app's configuration and its installations:
 * <https://docs.github.com/en/rest/apps/apps> (except "Get an app" and
 * "Create a scoped access token")
 *
 * App authentication works off of a JWT signed with one of the application's
 * private keys being sent as a `Bearer` token. Unlike most other github
 * tokens it has no specific identification beyond that, but because an
 * endpoint knows that it want that scheme specifically it doesn't really
 * matter.
 */

use std::sync::Arc;

use aws_lc_rs::signature::VerificationAlgorithm as _;
use axum::extract::FromRequestParts;
use base64::{Engine as _, prelude::BASE64_URL_SAFE_NO_PAD};
use gix_actor::bstr::ByteSlice as _;
use http::request::Parts;
use serde::Deserialize;

use crate::model::{Read, Token};

pub use crate::github::app::db::AppId;

/// Interaction is authenticated as an application
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
        let jwt = super::utils::auth_for_schemes(&[b"Bearer"], &parts.headers)
            .ok_or(http::StatusCode::UNAUTHORIZED)?;
        state
            .app_by_jwt(jwt)
            .await
            .map(|appid| Auth { appid })
            .ok_or(http::StatusCode::UNAUTHORIZED)
    }
}

pub trait AuthState: Sync + Send {
    fn app_by_jwt(
        &self,
        jwt: &[u8],
    ) -> impl Future<Output = Option<AppId>> + Send;
}

#[derive(Debug, Deserialize)]
enum Typ {
    Jwt,
}

#[derive(Debug, Deserialize)]
enum Alg {
    RS256,
}

#[derive(Debug, Deserialize)]
struct JoseHeader {
    typ: Typ,
    alg: Alg,
}

#[derive(Debug, Deserialize)]
struct Jwt {
    iat: i64,
    exp: i64,
    iss: String,
}

impl AuthState for Arc<crate::github::Config> {
    async fn app_by_jwt(&self, jwt: &[u8]) -> Option<AppId> {
        let (payload, signature) = jwt.rsplit_once_str(b".")?;
        let (header, claims) = payload.rsplit_once_str(b".")?;
        let _: JoseHeader = BASE64_URL_SAFE_NO_PAD
            .decode(header)
            .ok()
            .and_then(|h| serde_json::from_slice(&h).ok())?;
        let claims: Jwt = BASE64_URL_SAFE_NO_PAD
            .decode(claims)
            .ok()
            .and_then(|h| serde_json::from_slice(&h).ok())?;

        let now = chrono::Utc::now().timestamp();
        if (claims.iat..claims.exp).count() > 12 * 60 {
            // github recommends the iat be 60 seconds in the past, and
            // requires the exp to be no more than 10mn in the future, which
            // is an 11mn window, allow for some rounding and fail tokens with
            // a validity window more than 12.
            return None;
        }
        if !(claims.iat..claims.exp).contains(&now) {
            // jwt not yet issued, or expired, invalid
            return None;
        }
        let signature = BASE64_URL_SAFE_NO_PAD.decode(signature).ok()?;

        let tx = Token::<Read>::get().await.ok()?;
        let appid = crate::github::app::db::id_by_client_id(&tx, &claims.iss)?;
        let mut stmt = tx
            .prepare(
                "SELECT pubkey FROM application_keys WHERE application = ?",
            )
            .ok()?;
        let mut rows = stmt.query([*appid]).ok()?;

        while let Some(row) = rows.next().ok()? {
            let pubkey = row.get_ref(0).ok()?.as_bytes().ok()?;
            if aws_lc_rs::signature::RSA_PKCS1_2048_8192_SHA256
                .verify_sig(pubkey, payload, &signature)
                .is_ok()
            {
                return Some(appid);
            }
        }
        // if no pubkey able to validate the signature was found, bail
        None
    }
}
