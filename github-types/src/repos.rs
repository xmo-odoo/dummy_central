use serde::{Deserialize, Serialize};

use super::git::Authorship;
use super::users::SimpleUser;

pub type License = ();
#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Public,
    Private,
    // Internal, // GHE only
}
#[derive(Serialize, Default, Clone, Debug)]
pub struct RepositoryResponse {
    /// Unique identifier of the repository
    pub id: i64,
    pub node_id: String,
    /// The name of the repository.
    pub name: String,
    pub full_name: String,
    pub license: Option<License>,
    pub organization: Option<SimpleUser>,
    pub forks: usize,
    pub owner: SimpleUser,
    /// Whether the repository is private or public.
    pub private: bool,
    pub html_url: String,
    pub description: Option<String>,
    pub fork: bool,
    // FIXME: those should be non-full-repositories, and only in
    //        FullRepository (?)
    pub parent: Option<Box<RepositoryResponse>>,
    pub source: Option<Box<RepositoryResponse>>,
    pub url: String,
    pub archive_url: String,
    pub assignees_url: String,
    pub blobs_url: String,
    pub branches_url: String,
    pub collaborators_url: String,
    pub comments_url: String,
    pub commits_url: String,
    pub compare_url: String,
    pub contents_url: String,
    pub contributors_url: String,
    pub deployments_url: String,
    pub downloads_url: String,
    pub events_url: String,
    pub forks_url: String,
    pub git_commits_url: String,
    pub git_refs_url: String,
    pub git_tags_url: String,
    pub git_url: String,
    pub issue_comment_url: String,
    pub issue_events_url: String,
    pub issues_url: String,
    pub keys_url: String,
    pub labels_url: String,
    pub languages_url: String,
    pub merges_url: String,
    pub milestones_url: String,
    pub notifications_url: String,
    pub pulls_url: String,
    pub releases_url: String,
    pub ssh_url: String,
    pub stargazers_url: String,
    pub statuses_url: String,
    pub subscribers_url: String,
    pub subscription_url: String,
    pub tags_url: String,
    pub teams_url: String,
    pub trees_url: String,
    pub clone_url: String,
    pub mirror_url: Option<String>,
    pub hooks_url: String,
    pub svn_url: String,
    pub homepage: Option<String>,
    pub language: Option<String>,
    pub forks_count: usize,
    pub stargazers_count: usize,
    pub watchers_count: usize,
    pub size: usize,
    /// The default branch of the repository.
    pub default_branch: String,
    pub open_issues_count: usize,
    /// Whether this repository acts as a template that can be used to generate new repositories.
    pub is_template: Option<bool>,
    pub topics: Option<Vec<String>>,
    /// Whether issues are enabled.
    pub has_issues: bool,
    /// Whether projects are enabled.
    pub has_projects: bool,
    /// Whether the wiki is enabled.
    pub has_wiki: bool,
    pub has_pages: bool,
    /// Whether downloads are enabled.
    pub has_downloads: bool,
    /// Whether the repository is archived.
    pub archived: bool,
    /// Returns whether or not this repository disabled.
    pub disabled: bool,
    /// The repository visibility: public, private, or internal.
    /// optional field, remove entirely?
    pub visibility: Option<Visibility>,
    pub pushed_at: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    // template_repository removed
    /// ???? (also field is optional, and so is every Option field afterwards)
    pub temp_clone_token: Option<String>,
    /// Whether to allow squash merges for pull requests.
    pub allow_squash_merge: Option<bool>,
    /// Whether to allow Auto-merge to be used on pull requests.
    pub allow_auto_merge: Option<bool>,
    /// Whether to delete head branches when pull requests are merged
    pub delete_branch_on_merge: Option<bool>,
    /// Whether to allow merge commits for pull requests.
    pub allow_merge_commit: Option<bool>,
    /// Whether to allow forking this repo
    pub allow_forking: Option<bool>,
    pub subscribers_count: Option<usize>,
    pub network_count: Option<usize>,
    pub open_issues: usize,
    pub watchers: usize,
    pub master_branch: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct CreateRepositoryRequest {
    pub name: String,
    #[serde(default)]
    pub auto_init: bool,
}

#[derive(Deserialize)]
pub struct UpdateRepository {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub default_branch: Option<String>,
}
#[derive(Deserialize)]
pub struct CreateFork {
    pub organization: Option<String>,
    pub name: Option<String>,
    #[serde(default)]
    pub default_branch_only: bool,
}

#[derive(Serialize)]
pub struct CombinedCommitStatus {
    pub sha: String,
    pub state: CombinedCommitStatusState,
    // officially a different type from [`CommitStatusResponse`]` but... who care?
    pub statuses: Vec<CreateStatusResponse>,
    pub total_count: usize,
    pub repository: RepositoryResponse,
    pub url: String,
    pub commit_url: String,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CombinedCommitStatusState {
    /// If there are no statuses or any context is [``StatusState::Pending`].
    Pending,
    /// If the latest status for all contexts is [`StatusState::Success`].
    Success,
    /// If any of the contexts is [`StatusState::Error`] or [`StatusState::Failure`].
    Failure,
}
#[derive(Deserialize)]
pub struct CreateContentsRequest {
    /// The commit message.
    pub message: String,
    /// The new file content, using Base64 encoding.
    pub content: String,
    /// **Required if you are updating a file**. The blob SHA of the
    /// file being replaced.
    #[serde(default)]
    pub sha: Option<String>,
    /// The branch name. Default: the repository’s default branch
    /// (usually `master`)
    #[serde(default)]
    pub branch: Option<String>, // TODO: what if we pass in an explicit empty name?
    /// The person that committed the file. Default: the authenticated user.
    pub committer: Option<Authorship>,
    /// ** The author of the file. Default: The `committer` or the
    /// authenticated user if you omit `committer`. */
    pub author: Option<Authorship>,
}
// NOTE: `content` is null in response to a DELETE. No idea why all
// the fields or content and commit are optional and makes no sense to
// me, so made them mandatory (except for the URLs because can't be
// arsed to handle them yet)
#[derive(Serialize)]
pub struct FileCommit {
    pub content: Content,
    pub commit: Commit,
}
// when GET-ing content, the type can alternatively be symlink,
// submodule, or dir, but the top-level type is different so...
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentType {
    File,
}
#[derive(Serialize)]
pub struct Content {
    pub name: String,
    pub path: String,
    pub sha: String,
    pub size: usize,
    pub r#type: ContentType,
    pub url: Option<String>,
    pub html_url: Option<String>,
    pub git_url: Option<String>,
    pub download_url: Option<String>,
}
#[derive(Serialize)]
pub struct Tree {
    pub sha: String,
    pub url: Option<String>,
}
#[derive(Serialize)]
pub struct CommitLink {
    // FIXME: not actually nullable?
    pub url: Option<String>,
    pub html_url: Option<String>,
    pub sha: String,
}
#[derive(Serialize)]
pub struct Commit {
    pub sha: String,
    pub node_id: Option<String>,
    pub url: String,
    pub html_url: Option<String>,
    pub author: Option<Authorship>,
    pub committer: Option<Authorship>,
    pub message: String,
    pub tree: Tree,
    // FIXME: is option necessary?
    pub parents: Option<Vec<CommitLink>>,
}

// I really only care about the `commit` bit anyway
#[derive(Serialize)]
pub struct CommitsResponse {
    pub url: String,
    pub sha: String,
    pub node_id: String,
    pub html_url: String,
    pub comments_url: String,
    pub commit: CommitsResponseCommit,
    // is this empty for unknown users?
    pub author: Option<SimpleUser>,
    pub committer: Option<SimpleUser>,
    pub parents: Vec<CommitLink>,
    // stats: Option<struct Stats {additions: Option<usize>, deletions: Option<usize>, total: Option<usize>>},
    // literally every field is marked as optional and I don't understand why, or why files itself is
    /*
    diff-entry
    files: Option<Vec<{
        filename: Option<String>,
        additions: Option<usize>,
        deletions: Option<usize>,
        changes: Option<usize>,
        status: Option<String>, // TODO: seems to really be an enum, find cases
        raw_url: Option<String>,
        blob_url: Option<String>,
        patch: Option<String>, // patch data
        sha: Option<String>,
        contents_url: Option<String>,
        previous_filename: Option<String>, // in case file is renamed by commit?
    }>>,
    */
}

#[derive(Serialize)]
pub struct CommitsResponseCommit {
    pub url: String,
    pub author: Option<Authorship>,
    pub committer: Option<Authorship>,
    pub message: String,
    pub tree: Tree,
    pub comments_count: usize,
    // verification: Option<Verification> ?
}

fn default_hook_name() -> String {
    String::from("web")
}
fn default_true() -> bool {
    true
}
#[derive(Deserialize)]
pub struct CreateHook {
    /// Use `web` to create a webhook. This parameter
    /// only accepts the value `web`.
    #[serde(default = "default_hook_name")]
    pub name: String,
    pub config: CreateHookConfig,
    /// Determines what events the hook is triggered for.
    #[serde(default = "HookEvent::default")]
    pub events: Vec<HookEvent>,
    /// Determines if notifications are sent when the webhook is
    /// triggered. Set to `true` to send notifications.
    #[serde(default = "default_true")]
    pub active: bool,
}
#[derive(Deserialize)]
pub struct UpdateHook {
    // FIXME: config (nb: url is probably optional), events (nothing if
    // empty?), add/remove (what happens if all events, add, and remove?)
    #[serde(default)]
    pub active: Option<bool>, // TODO: is this the correct default?
    #[serde(default)]
    pub config: Option<UpdateHookConfig>,
}
#[derive(Deserialize)]
pub struct UpdateHookConfig {
    #[serde(default)]
    pub secret: Option<String>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash, Debug, Copy, Clone)]
#[serde(rename_all = "snake_case")]
pub enum HookEvent {
    Push,
    PullRequest,
    IssueComment,
    Status,
    PullRequestReview,
}

impl HookEvent {
    fn default() -> Vec<Self> {
        vec![Self::Push]
    }
    // FIXME: serde_variant::to_variant_name?
    pub fn as_str(&self) -> &'static str {
        match self {
            HookEvent::Push => "push",
            HookEvent::PullRequest => "pull_request",
            HookEvent::IssueComment => "issue_comment",
            HookEvent::Status => "status",
            HookEvent::PullRequestReview => "pull_request_review",
        }
    }
}

impl std::str::FromStr for HookEvent {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "push" => Ok(HookEvent::Push),
            "pull_request" => Ok(HookEvent::PullRequest),
            "issue_comment" => Ok(HookEvent::IssueComment),
            "status" => Ok(HookEvent::Status),
            "pull_request_review" => Ok(HookEvent::PullRequestReview),
            _ => Err(()),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CreateHookConfig {
    /// URL to which the payloads will be delivered
    pub url: String,
    /// The default media type used to serialize the payloads,
    /// supported values include json and form.
    #[serde(default)]
    pub content_type: HookContentType,
    #[serde(default)]
    pub secret: String,
    /// Determines whether the SSL certificate of the host `url` will
    /// be verified when delivering payloads, can be configured using
    /// a number (0 or 1) or a string ('0' or '1')
    #[serde(default = "default_true", deserialize_with = "boolish")]
    pub insecure_ssl: bool,
}
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
#[serde(rename_all = "snake_case")]
pub enum HookContentType {
    /// JSON payload set as the `payload` key of an
    /// application/x-www-form-urlencoded
    Form,
    /// JSON payload as-is
    Json,
}
impl Default for HookContentType {
    fn default() -> Self {
        Self::Form
    }
}
impl HookContentType {
    pub fn as_str(&self) -> &'static str {
        match self {
            HookContentType::Form => "form",
            HookContentType::Json => "json",
        }
    }
}

/// Deserialize insecure_ssl which is semantically a boolean flag but
/// can be set via an integer or a string
fn boolish<'de, D>(d: D) -> Result<bool, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    use serde_json::value::Value;
    match Value::deserialize(d) {
        Ok(Value::Number(n)) => match n.as_i64() {
            Some(0) => Ok(false),
            Some(1) => Ok(true),
            _ => Err(()),
        },
        Ok(Value::String(s)) if s == "0" => Ok(false),
        Ok(Value::String(s)) if s == "1" => Ok(true),
        _ => Err(()),
    }
    .map_err(|_| {
        serde::de::Error::custom("Failed to deserialize boolean-ish (0 or 1)")
    })
}

#[derive(Debug)]
pub struct Status {
    pub state: StatusState,
    pub target_url: String,
    pub description: String,
}
#[derive(Deserialize)]
pub struct CreateStatus {
    pub state: StatusState,
    pub target_url: Option<String>,
    pub description: Option<String>,
    #[serde(default = "default_context")]
    pub context: String,
}
// FIXME: find out how to trigger custom error responses when
//        deserialization fails: we need specific validation errors on
//        empty (but not missing!) context as well as invalid state
#[derive(Deserialize)]
pub struct CreateStatusGarbage {
    #[serde(default)]
    pub state: String,
    pub target_url: Option<String>,
    pub description: Option<String>,
    #[serde(default = "default_context")]
    pub context: String,
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
#[serde(try_from = "&str", rename_all = "snake_case")]
pub enum StatusState {
    Success,
    Pending,
    Error,
    Failure,
}
fn default_context() -> String {
    "default".into()
}
impl From<StatusState> for &'static str {
    fn from(s: StatusState) -> &'static str {
        match s {
            StatusState::Success => "success",
            StatusState::Pending => "pending",
            StatusState::Error => "error",
            StatusState::Failure => "failure",
        }
    }
}
impl<'a> std::convert::TryFrom<&'a str> for StatusState {
    type Error = String;
    fn try_from(v: &'a str) -> Result<Self, String> {
        Ok(match v {
            "success" => Self::Success,
            "pending" => Self::Pending,
            "error" => Self::Error,
            "failure" => Self::Failure,
            _ => return Err(String::new()),
        })
    }
}
impl std::convert::TryFrom<String> for StatusState {
    type Error = String;
    fn try_from(v: String) -> Result<Self, String> {
        Self::try_from(v.as_str())
    }
}

#[derive(Serialize)]
pub struct CreateStatusResponse {
    // url: String,
    // avatar_url: Option<String>
    // FIXME: StatusId?
    pub id: i64,
    // node_id: String,
    pub state: StatusState,
    pub description: Option<String>,
    pub target_url: Option<String>,
    pub context: String,
    // created_at: String,
    // updated_at: String,
    // TODO: creator is not set for combined statuses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creator: Option<SimpleUser>,
}

// FIXME: there are at least 3 different representations of the repo
pub type MinimalRepository = RepositoryResponse;

#[derive(Deserialize)]
pub struct CreateBranchMerge {
    pub base: String,
    pub head: String,
    #[serde(default)]
    pub commit_message: Option<String>,
}

#[derive(Serialize)]
pub struct Deployment {
    pub id: i64,
}

#[derive(Serialize)]
pub struct RepositoryInvitation {
    pub id: i64,
}

#[derive(Serialize)]
pub struct Collaborator {
    pub login: String,
}
