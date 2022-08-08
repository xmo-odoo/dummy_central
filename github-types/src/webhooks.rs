use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::pulls as p;
use crate::repos::MinimalRepository;
use crate::users::SimpleUser;

#[derive(Serialize, Debug)]
pub struct Webhook {
    pub sender: SimpleUser,
    pub repository: MinimalRepository,
    // TODO orgs without this?
    // organisation: MinimalOrganization
    // #[serde(skip_serializing_if = "Option::is_none")]
    // installation: Installation,
    #[serde(flatten)]
    pub event: WebhookEvent,
}

#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Debug)]
#[serde(untagged)]
pub enum WebhookEvent {
    Ping {
        zen: String,
        hook_id: i64,
        hook: Hook,
    },
    Status(Status),
    IssueComment(IssueComment),
    PullRequest(PullRequest),
    PullRequestReview(PullRequestReview),
}
impl WebhookEvent {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ping { .. } => "ping",
            Self::Status(_) => "status",
            Self::IssueComment(_) => "issue_comment",
            Self::PullRequest(_) => "pull_request",
            Self::PullRequestReview(_) => "pull_request_review",
        }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct Hook {
    pub r#type: String, // Repository
    pub id: i64,
    pub name: String, // web
    pub active: bool,
    pub events: BTreeSet<super::repos::HookEvent>,
    pub config: super::repos::CreateHookConfig,
    pub created_at: String,
    pub updated_at: String,
    pub url: String,
    pub test_url: String,
    pub ping_url: String,
    pub deliveries_url: String,
    pub last_response: LastResponse,
}

#[derive(Serialize, Clone, Debug)]
pub struct LastResponse {
    pub code: Option<u16>,
    pub status: Option<String>,
    pub message: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct Status {
    pub sha: String,
    pub state: super::repos::StatusState,
    pub context: String,
    pub description: Option<String>,
    pub target_url: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct IssueComment {
    #[serde(flatten)]
    pub action: IssueCommentAction,
    pub issue: super::issues::IssueResponse,
    // TODO: maybe? event example is missing reactions
    pub comment: super::issues::IssueCommentResponse,
}

#[derive(Serialize, Debug)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum IssueCommentAction {
    Created,
    Edited { changes: IssueCommentChange },
    Deleted,
}
#[derive(Serialize, Debug)]
pub struct IssueCommentChange {
    body: Change<String>,
}
impl From<String> for IssueCommentChange {
    fn from(s: String) -> Self {
        Self { body: s.into() }
    }
}

#[derive(Serialize, Debug)]
pub struct PullRequest {
    #[serde(flatten)]
    pub action: PullRequestAction,
    pub number: usize,
    pub pull_request: super::pulls::PullRequestResponse,
}

#[derive(Serialize, Debug)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum PullRequestAction {
    Closed,
    ConvertedToDraft,
    Edited { changes: PrEdition },
    Opened,
    ReadyForReview,
    Reopened,
    Synchronize,
}

#[derive(Serialize, Debug)]
pub struct Change<T> {
    from: T,
}
impl<T> From<T> for Change<T> {
    fn from(from: T) -> Self {
        Self { from }
    }
}
#[derive(Serialize, Debug)]
pub struct PrEdition {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<Change<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<Change<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<PrBaseChange>,
}

#[derive(Serialize, Debug)]
pub struct PrBaseChange {
    pub r#ref: Change<String>,
    pub sha: Change<String>,
}

#[derive(Serialize, Debug)]
pub struct PullRequestReview {
    #[serde(flatten)]
    pub action: ReviewAction,
    pub pull_request: super::pulls::PullRequestResponse,
    pub review: ReviewResponse,
}

#[derive(Serialize, Debug)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ReviewAction {
    Submitted,
    Edited,
    Dismissed,
}
// because OF COURSE the API can't be coherent, and the PR review
// object must differ just enough from the normal one to be a pain in
// the ass
#[derive(Serialize, Debug)]
pub struct ReviewResponse {
    pub id: i64,
    pub node_id: String,
    pub user: Option<SimpleUser>,
    pub body: String,
    // pub body_text: Option<String>,
    // pub body_html: Option<String>,
    pub state: ReviewState,

    pub submitted_at: String,
    pub commit_id: String,

    // pub author_association: AuthorAssociation,
    pub html_url: String,
    pub pull_request_url: String,
    // pub _links:  ???
}
impl From<p::ReviewResponse> for ReviewResponse {
    fn from(
        p::ReviewResponse {
            id,
            node_id,
            user,
            body,
            state,
            commit_id,
            html_url,
            pull_request_url,
            submitted_at,
        }: p::ReviewResponse,
    ) -> Self {
        Self {
            id,
            node_id,
            user,
            body,
            state: state.into(),
            commit_id,
            html_url,
            pull_request_url,
            submitted_at,
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ReviewState {
    Pending,
    Approved,
    ChangesRequested,
    Commented,
}
impl From<p::ReviewState> for ReviewState {
    fn from(s: p::ReviewState) -> Self {
        match s {
            p::ReviewState::Pending => Self::Pending,
            p::ReviewState::Approved => Self::Approved,
            p::ReviewState::ChangesRequested => Self::ChangesRequested,
            p::ReviewState::Commented => Self::Commented,
        }
    }
}
