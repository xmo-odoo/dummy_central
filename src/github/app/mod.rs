use axum::{
    Router,
    routing::{delete, get, post},
};

pub mod db;
mod handlers;

#[rustfmt::skip]
pub fn routes() -> Router<super::St> {
    Router::new()
        .route("/settings/apps/new", post(handlers::create_app))
        .route("/organizations/{org}/settings/apps/new", post(handlers::create_app))
        .route("/app-manifests/{code}/conversions", post(handlers::finalize_app))
        .route("/apps/{slug}/installations/new/permissions", get(handlers::install_app))
        .route("/login/oauth/authorize", get(handlers::authorize_app))
        .route("/login/oauth/access_token", post(handlers::finalize_authorize))
        .route("/app/installations", get(handlers::list_installations))
        .route("/app/installations/{installation_id}", delete(handlers::delete_installation))
        .route("/app/installations/{installation_id}/access_tokens", post(handlers::create_iat))
        .route("/applications/{client_id}/token", post(handlers::check_token))
        .route("/applications/{client_id}/grant", delete(handlers::delete_authorization))
}
