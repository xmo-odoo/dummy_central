/*!
 * Github has a number of ways to auth, as a combination of historical
 * happenstance and bespoke needs. There are broadly 5 classes of
 * authentication, with 4.5 use cases:
 *
 * # [`app`]
 *
 * App authentication is used to interact with github app endpoints,
 * either configuring the application or managing app installations.
 *
 * # [`oauth_app`]
 *
 * Oauth app authentication is used to manage *oauth authorizations*
 * (oauth grants to act as a user), and is used by both oauth apps
 * and github apps.
 *
 * The creation of the authorizations goes through an oauth workflow
 * which is separate from this, and works off of session authentication
 * (which is not really in scope).
 *
 * # [`install`]
 *
 * Installation authentication, as sole allowed autentication method it's
 * mostly for querying the current installation.
 *
 * # [`user`]
 *
 * User authentication broadly consists of accessing the API to behave
 * as a github user (an actual one with `type: User`). Most endpoints
 * use [`actor`] authentication, but a few requiring working with an
 * actual concrete users will be limited to [`user`] auth instead.
 *
 * # [`actor`]
 *
 * Actor authentication combines [`user`] authentication and [`install`]
 * authentication, the latter is a form of actor which is only available
 * to github apps (`type: Bot`).
 *
 * # [`git`]
 *
 * Finally git authentication is kind-of its own thing, used for all git
 * operations (as in interactions between `git` and the git repository
 * hosted by github).
 *
 * Technically there's also a few endpoints which specifically require a UAT
 * but we'll ignore those for now...
 */
mod app;
pub use app::Auth as ApplicationAuth;
mod oauth_app;
pub use oauth_app::Auth as OAuthAuth;
mod user;
pub use user::Auth as UserAuth;
mod install;
pub use install::Auth as InstallAuth;
mod actor;
pub use actor::Auth as ActorAuth;
mod git;
pub use git::Auth as GitAuth;

mod utils;
// #[derive(Deserialize)]
// #[serde(untagged)]
// enum UserAccessTokenRequest {
//     Code {
//         client_id: String,
//         client_secret: String,
//         code: String,
//         /// URLs to send user to after auth, matched against the application's (?)
//         #[serde(default)]
//         redirect_uri: Option<String>,
//         /// PKCE verifier, required if auth was initialised with a `code_challenge`
//         #[serde(default)]
//         code_verifier: Option<String>,
//     },
//     Refresh {
//         client_id: String,
//         client_secret: String,
//         refresh_token: String,
//         grant_type: RefreshToken,
//     },
// }
// #[derive(Deserialize)]
// #[serde(rename_all = "snake_case")]
// enum RefreshToken {
//     RefreshToken,
// }

// struct AccessTokenResponse {
//     access_token: String,
//     refresh_token: Option<String>,
// }
// /// Manual implementation of [`Serialize`] as 3 (4) of the 4 (6) fields are
// /// constant.
// impl Serialize for AccessTokenResponse {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: serde::Serializer,
//     {
//         let mut s = serializer.serialize_struct(
//             "AccessTokenResponse",
//             4 + if self.refresh_token.is_some() { 2 } else { 0 },
//         )?;
//         s.serialize_field("access_token", &self.access_token)?;
//         s.serialize_field("expires_in", &28800)?;
//         if let Some(r) = &self.refresh_token {
//             s.serialize_field("refresh_token", r)?;
//             s.serialize_field("refresh_token_expires_in", &15897600)?;
//         }
//         s.serialize_field("scope", "")?;
//         s.serialize_field("token_type", "bearer")?;
//         s.end()
//     }
// }

// Exchange temporary auth code (ttl 10mn) for the user access token,
// and refresh token if configured for that
// Endpoint for generating access tokens, either from a temporary code or from an existing token
// async fn generate_uat<T: AppState + ActorState>(
//     State(st): State<T>,
//     Query(info): Query<UserAccessTokenRequest>,
// ) -> Result<Form<AccessTokenResponse>, http::StatusCode> {
//     let (access_token, refresh_token) = match info {
//         UserAccessTokenRequest::Code {
//             client_id,
//             client_secret,
//             code,
//             ..
//         } => st
//             .find_by_client_id(&client_id, &client_secret)
//             .and_then(|app| st.finalize_access_token(app, &code))
//             .ok_or(http::StatusCode::BAD_REQUEST)?,
//         UserAccessTokenRequest::Refresh {
//             client_id,
//             client_secret,
//             refresh_token,
//             ..
//         } => st
//             .find_by_client_id(&client_id, &client_secret)
//             .and_then(|app| st.refresh_access_token(app, &refresh_token))
//             .ok_or(http::StatusCode::BAD_REQUEST)?,
//     };

//     Ok(Form(AccessTokenResponse {
//         access_token,
//         refresh_token,
//     }))
// }
