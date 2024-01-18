use serde::{Deserialize, Serialize};

use crate::users::SimpleUser;

#[derive(Debug, Serialize, Deserialize, Copy, Clone)]
#[serde(rename_all = "snake_case")]
pub enum IssueState {
    Open,
    Closed,
}
impl IssueState {
    pub fn from(s: &str) -> Self {
        match s {
            "open" => Self::Open,
            "closed" => Self::Closed,
            _ => panic!("invalid issue state {s}"),
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorAssociation {
    Collaborator,
    Contributor,
    // reason why this can't easily be computed on the fly for serialisation
    FirstTimer,
    // ?? what's the difference between previous
    FirstTimeContributor,
    // ???
    Mannequin,
    // what's the distinction between that and collaborator?
    Member,
    // ?????
    None,
    Owner,
}

#[derive(Serialize, Debug)]
pub struct Label {
    pub id: i64,
    pub url: String,
    pub name: String,
    pub description: Option<String>,
    pub color: String,
}

#[derive(Serialize, Debug)]
pub struct IssueResponse {
    pub id: i64,
    pub node_id: String,
    pub number: usize,
    pub state: IssueState,
    pub locked: bool,
    //active_lock_reason: see above
    pub title: String,
    pub body: Option<String>,
    // body_html, body_text
    // creator?
    pub user: Option<SimpleUser>,
    // labels: Vec<LabelsResponse>,
    // milestone: Option<Milestone>
    // created_at: String, // or datetime formatted by serde using ISO?
    // updated_at: String,
    // closed_at: Option<String>,
    // closed_by: Option<SimpleUser>,
    // is this just the first of assignees?
    // assignee: Option<SimpleUser>,
    // assignees: Vec<SimpleUser>, // FIXME: these lists are all marked nullable, why?
    // requested_reviewers: Vec<SimpleUser>,
    // requested_teams: Vec<SimpleTeam>,
    pub author_association: AuthorAssociation,
    pub comments: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pull_request: Option<super::pulls::PullRequestResponse>,
    // repository: whatever
    // timeline_url???
}

#[derive(Deserialize, Debug)]
pub struct IssueCreate {
    // TODO: or number, wtf does that do?
    pub title: String,
    #[serde(default)]
    pub body: Option<String>,
    // deprecated
    // #[serde(default)]
    // assignee: Option<String>,
    // TODO: see how that combines with assignee
    // #[serde(default)]
    // assignees: Vec<String>
    // #[serde(default)]
    // milestone: Option<usize | String>,
    // unclear if any property of a label is required, but according to the ts file... nope
    // #[serde(default)]
    // labels: Vec<String | {id, name, description?, color?}>
}

#[derive(Deserialize)]
pub struct IssueUpdate {
    pub body: String,
}

#[derive(Serialize, Debug)]
pub struct IssueCommentResponse {
    pub body: String, // in what situation would it go missing? also maybe just &str?
    // body_text: String, // ???
    // body_html: String,
    pub user: Option<SimpleUser>,
    pub id: i64,
    // node_id: String,
    pub url: String,
    pub html_url: String,
    pub created_at: String,
    pub updated_at: String,
    // issue_url: String, // weird that there's no issue id
    // author_association: AuthorAssociation,
    // reactions: Reactions,
}

#[derive(Deserialize, Debug)]
pub struct CommentCreate {
    pub body: String,
}
