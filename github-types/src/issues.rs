use serde::{Deserialize, Deserializer, Serialize};

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
    pub default: bool,
}

#[derive(Serialize, Debug)]
pub struct IssueResponse {
    pub id: i64,
    pub node_id: String,
    #[serde(flatten)]
    pub _urls: IssueResponseUrls,
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
    // assignees: Vec<SimpleUser>,
    // requested_reviewers: Vec<SimpleUser>,
    // requested_teams: Vec<SimpleTeam>,
    pub author_association: AuthorAssociation,
    pub comments: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pull_request: Option<super::pulls::PullRequestResponse>,
    // repository: whatever
    // timeline_url???
}

#[derive(Serialize, Debug)]
pub struct IssueResponseUrls {
    pub url: String,
}

fn number_or_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrInt {
        String(String),
        Number(i64),
    }

    match StringOrInt::deserialize(deserializer)? {
        StringOrInt::String(s) => Ok(s),
        StringOrInt::Number(i) => Ok(i.to_string()),
    }
}
#[derive(Deserialize, Debug)]
pub struct IssueCreate {
    #[serde(deserialize_with = "number_or_string")]
    pub title: String,
    #[serde(default)]
    pub body: Option<String>,
    /// Issue types, stringly typed, configured at the organisation level.
    #[serde(default)]
    pub r#type: Option<String>,
    /// Deprecated assignee field, q: how does it combine with assignees?
    #[serde(default)]
    pub assignee: Option<String>,
    #[serde(default)]
    pub assignees: Vec<String>,
    #[serde(default)]
    pub milestone: Option<Milestone>,
    // unclear if any property of a label is required, but according to the ts file... nope
    #[serde(default)]
    pub labels: Vec<CreateIssueLabel>,
}
#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum Milestone {
    Int(usize),
    String(String),
}
#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum CreateIssueLabel {
    String(String),
    Label {
        id: i64,
        name: String,
        #[serde(default)]
        description: Option<String>,
        #[serde(default)]
        color: Option<String>,
    },
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
pub struct IssueUpdate {
    pub title: Option<String>,
    #[serde(deserialize_with = "crate::utils::unset")]
    pub body: Option<Option<String>>,
    //#[serde(deserialize_with = "state_ignore_invalid")]
    pub state: Option<IssueState>,
    // pub assignee: Option<String> // deprecated?
    // pub state_reason: Option<ClosingReason>
    // pub milestone: Option<Either<String, i64>>
    // pub labels: Vec<???>
    // pub assignees: Vec<String>,
}

#[derive(Deserialize)]
pub struct IssueCommentUpdate {
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
    #[serde(default, deserialize_with = "crate::utils::unset")]
    pub body: Option<serde_json::Value>,
}
