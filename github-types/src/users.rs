use std::borrow::Cow;

use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum UserType {
    User,
    Organization,
    // TODO: Enterprise?
}
impl Default for UserType {
    fn default() -> Self {
        Self::User
    }
}
#[derive(Serialize, Default)]
pub struct PublicUser {
    pub login: String,
    pub id: i64,
    pub node_id: String,
    pub avatar_url: String,
    pub gravatar_id: Option<String>,
    pub url: String,
    pub html_url: String,
    pub followers_url: String,
    pub following_url: String,
    pub gists_url: String,
    pub starred_url: String,
    pub subscriptions_url: String,
    pub organizations_url: String,
    pub repos_url: String,
    pub events_url: String,
    pub received_events_url: String,
    pub r#type: UserType,
    pub site_admin: bool,
    pub name: Option<String>,
    pub company: Option<String>,
    pub blog: Option<String>,
    pub location: Option<String>,
    pub email: Option<String>,
    pub hireable: Option<bool>,
    pub bio: Option<String>,
    pub public_repos: usize,
    pub public_gists: usize,
    pub followers: usize,
    pub following: usize,
    pub created_at: String,
    pub updated_at: String,
}

// name and email are both nullable: true and !required...
#[derive(Serialize, Default, Clone, Debug)]
pub struct SimpleUser {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub login: String,
    //    pub id: u64,
    //    pub node_id: String,
    //    pub avatar_url: String,
    //    pub gravatar_id: Option<String>,
    pub url: String,
    //    pub html_url: String,
    //    pub followers_url: String,
    //    pub following_url: String,
    //    pub gists_url: String,
    //    pub starred_url: String,
    //    pub subscriptions_url: String,
    //    pub organizations_url: String,
    //    pub repos_url: String,
    //    pub events_url: String,
    //    pub received_events_url: String,
    pub r#type: UserType,
    //    pub site_admin: bool,
}
impl SimpleUser {
    pub fn url(root: &str, login: &str) -> String {
        format!("{root}/users/{login}")
    }
    pub fn for_login(root: &str, login: Cow<'_, str>) -> Self {
        Self {
            url: Self::url(root, &login),
            login: login.into_owned(),
            ..Self::default()
        }
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Email {
    pub email: String,
    pub verified: bool,
    pub primary: bool,
    pub visibility: Visibility,
}
#[derive(Serialize, Deserialize, Copy, Clone)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Public,
    Private,
}
impl Default for Visibility {
    fn default() -> Self {
        Self::Public
    }
}
