use serde::{Deserialize, Serialize};

// FIXME: circular dependency
use super::issues::{AuthorAssociation, IssueState, Label};
use crate::users::SimpleUser;

#[derive(Serialize, Debug)]
pub struct PullRequestResponse {
    pub id: i64, // ??? wtf?
    pub node_id: String,
    #[serde(flatten)]
    pub _urls: PullRequestUrls,
    pub number: usize,
    pub state: IssueState,
    pub locked: bool,
    //active_lock_reason: see above
    pub title: String,
    pub body: Option<String>,
    // creator?
    pub user: Option<SimpleUser>,
    pub labels: Vec<Label>,
    // milestone: Option<Milestone>
    pub created_at: String, // or datetime formatted by serde using ISO?
    pub updated_at: String,
    pub closed_at: Option<String>,
    pub merged_at: Option<String>,
    pub merge_commit_sha: String,
    // is this just the first of assignees?
    pub assignee: Option<SimpleUser>,
    pub assignees: Vec<SimpleUser>, // FIXME: these lists are all marked nullable, why?
    pub requested_reviewers: Vec<SimpleUser>,
    // requested_teams: Vec<SimpleTeam>,
    pub head: PullRequestHead,
    pub base: PullRequestBase,
    pub author_association: AuthorAssociation,
    pub draft: bool, // why is this optional?
    pub merged: bool,
    pub mergeable: bool,  // why is this nullable?
    pub rebaseable: bool, // why is this nullable *and* optional?
    // ??? graphql API has CONFLICTING, MERGEABLE, UNKNOWN,
    // alternatively MergeStateStatus is BEHIND, BLOCKED, CLEAN,
    // DIRTY, DRAFT, HAS_HOOKS, UNKNOWN, UNSTABLE which matches
    // example
    pub mergeable_state: String,
    pub merged_by: Option<SimpleUser>,
    pub comments: usize,
    pub review_comments: usize,
    pub maintainer_can_modify: bool,
    pub commits: usize,
    pub additions: usize,
    pub deletions: usize,
    pub changed_files: usize,
}
#[derive(Serialize, Debug)]
pub struct PullRequestUrls {
    pub url: String,
    pub html_url: String,
    pub diff_url: String,
    pub patch_url: String,
    pub issue_url: String,
    pub commits_url: String,
    pub review_comments_url: String,
    pub review_comment_url: String,
    pub comments_url: String,
    pub statuses_url: String,
}
impl PullRequestUrls {
    pub fn new(repo: &str, number: usize) -> Self {
        Self {
            url: format!("{repo}/pulls/{number}"),
            html_url: String::new(),
            diff_url: String::new(),
            patch_url: String::new(),
            issue_url: format!("{repo}/issues/{number}"),
            commits_url: format!("{repo}/pulls/{number}/commits"),
            review_comments_url: format!("{repo}/pulls/{number}/comments"),
            review_comment_url: format!(
                "{repo}/pulls/{number}/comment{{/number}}",
            ),
            comments_url: format!("{repo}/issues/{number}/comments"),
            statuses_url: String::new(), // {number}/statuses/{head.sha}
        }
    }
}

// FIXME: in reality these are identical but for:
//
// - the license field doesn't have an optional html_url in the head variant (why???)
// - the head's repo is nullable (almost certainly because it could have been deleted)
// also not sure whether the repos match one of the other repo types (normal, full, minimal)
#[derive(Serialize, Debug)]
pub struct PullRequestHead {
    pub sha: String,
    pub label: String,
    pub r#ref: String,
    pub repo: Option<crate::repos::RepositoryResponse>,
    // pub user: User
}
#[derive(Serialize, Debug)]
pub struct PullRequestBase {
    pub sha: String,
    pub label: String,
    pub r#ref: String,
    pub repo: crate::repos::RepositoryResponse,
    // pub user: User
}

#[derive(Deserialize)]
pub struct PullRequestCreate {
    pub head: String,
    pub base: String,
    #[serde(flatten)]
    pub _source: PullRequestSource,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub draft: bool,
    // TODO: is this true by default? (seems like from the graphql)
    // note: always false for same-repo PRs, need to test between org and
    #[serde(default)]
    pub maintainer_can_modify: Option<bool>,
}
#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum PullRequestSource {
    FromTitle { title: String },
    FromIssue { issue: usize },
}

#[derive(Deserialize, Default, Debug)]
#[serde(default)]
pub struct PullRequestUpdate {
    pub title: Option<String>,
    #[serde(deserialize_with = "unset")]
    pub body: Option<Option<String>>,
    #[serde(deserialize_with = "state_ignore_invalid")]
    pub state: Option<IssueState>,
    pub base: Option<String>,
}

fn unset<'de, D, T>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    // if we find the field at all, wrap it in a `Some`, this way:
    // - unset => None
    // - set to null => Some(None)
    // - set to a value => Some(Some(v))
    Ok(Some(Option::<T>::deserialize(de)?))
}

fn state_ignore_invalid<'de, D>(de: D) -> Result<Option<IssueState>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let opt = Option::<&str>::deserialize(de)?;
    Ok(opt.and_then(|s| match s {
        "open" => Some(IssueState::Open),
        "closed" => Some(IssueState::Closed),
        _ => None,
    }))
}

#[derive(Deserialize)]
pub struct CreateReviewRequest {
    pub body: String,
    #[serde(default)]
    pub event: Option<CreateReviewState>,
    #[serde(default)]
    pub commit_id: Option<String>,
    // TODO: can't be in reply to
    #[serde(default)]
    pub comments: Vec<ReviewComment>,
}
#[derive(Serialize, Deserialize, Copy, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CreateReviewState {
    Approve,
    RequestChanges,
    Comment,
}

#[derive(Serialize, Clone)]
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

#[derive(Serialize, Deserialize, Copy, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReviewState {
    Pending,
    Approved,
    ChangesRequested,
    Commented,
}
impl From<Option<CreateReviewState>> for ReviewState {
    fn from(s: Option<CreateReviewState>) -> Self {
        match s {
            None => Self::Pending,
            Some(CreateReviewState::Approve) => Self::Approved,
            Some(CreateReviewState::RequestChanges) => Self::ChangesRequested,
            Some(CreateReviewState::Comment) => Self::Commented,
        }
    }
}
impl From<&ReviewState> for &'static str {
    fn from(s: &ReviewState) -> &'static str {
        match s {
            ReviewState::Pending => "pending",
            ReviewState::Approved => "approve",
            ReviewState::ChangesRequested => "request_changes",
            ReviewState::Commented => "comment",
        }
    }
}
impl TryFrom<&str> for ReviewState {
    type Error = &'static str;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "pending" => Ok(Self::Pending),
            "approve" => Ok(Self::Approved),
            "request_changes" => Ok(Self::ChangesRequested),
            "comment" => Ok(Self::Commented),
            _ => Err("Invalid review state"),
        }
    }
}
impl TryFrom<&String> for ReviewState {
    type Error = &'static str;
    fn try_from(s: &String) -> Result<Self, Self::Error> {
        s.as_str().try_into()
    }
}

#[derive(Deserialize)]
pub struct ReviewComment {
    pub body: String,
    // FIXME: should only be optional for in_reply_to
    #[serde(default)]
    pub path: Option<String>,
    #[serde(flatten)]
    pub _position: ReviewCommentPosition,
}
#[derive(Deserialize)]
#[serde(untagged)]
pub enum ReviewCommentPosition {
    /// Comment is a reply to an existing comment rather than a top-level
    InReplyTo { in_reply_to: usize },
    /// This gives the positioning of the line in the patch hunk
    InHunk { position: usize },
    /// This gives the positioning (possibly span) of the comment in
    /// the *blobs*
    InBlob {
        position: ReviewCommentSide,
        line: usize,
        #[serde(flatten)]
        _start: Option<ReviewCommentStart>,
    },
}
#[derive(Deserialize)]
pub struct ReviewCommentStart {
    // TODO: what happens if this is different than `position`
    #[serde(rename = "start_position")]
    pub position: ReviewCommentSide,
    #[serde(rename = "start_line")]
    pub line: usize,
}
#[derive(Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReviewCommentSide {
    Left,
    Right,
}

#[derive(Deserialize)]
pub struct CreateReviewCommentRequest {
    // does this really make sense if `InReplyTo`?
    #[serde(default)]
    pub commit_id: Option<String>,
    #[serde(flatten)]
    pub _comment: ReviewComment,
}
#[derive(Serialize)]
pub struct ReviewCommentResponse {
    pub id: i64,
    pub pull_request_review_id: Option<i64>,
    pub url: String,
    pub body: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_reply_to_id: Option<i64>,
    pub created_at: String,
    pub updated_at: String,
}
#[derive(Deserialize)]
pub struct UpdateReviewCommentRequest {
    pub body: String,
}
