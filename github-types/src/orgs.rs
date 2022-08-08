use super::users::UserType;
use serde::Serialize;

// not actually full, there's a bunch of fields which are only for
// logged users with enough rights but that's not really reflected in
// the schema (except in that they're not required)
#[derive(Serialize)]
pub struct OrganizationFull {
    pub id: i64,
    pub node_id: String,
    pub login: String,
    pub name: Option<String>,
    // company: Option<String>,
    // description: Option<String>,
    // location: Option<String>,
    // email: Option<String>,
    pub r#type: UserType,
    // twitter_username: Option<String>,
    pub is_verified: bool,
    pub has_organization_projects: bool,
    pub has_repository_projects: bool,
    pub public_repos: usize,
    pub public_gists: usize,
    pub followers: usize,
    pub following: usize,
    // created_at: String,
    // updated_at: String,
    // blog: Option<String>,
    pub url: String,
    // html_url: String,
    // avatar_url: String,
    // repos_url: String,
    // events_url: String,
    // hooks_url: String,
    // issues_url: String,
    // members_url: String,
    // public_members_url: String,
}
