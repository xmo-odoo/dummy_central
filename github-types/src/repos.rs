use std::collections::BTreeSet;

use serde::{Deserialize, Serialize, Serializer};

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
impl RepositoryResponse {
    pub fn new(root: &str, owner: &str, name: &str) -> Self {
        let full_name = format!("{owner}/{name}");
        let url = format!("{root}/repos/{full_name}");
        Self {
            name: name.to_string(),
            html_url: format!("{root}/{full_name}"),
            archive_url: format!("{url}/{{archive_format}}{{/ref}}"),
            assignees_url: format!("{url}/assignees{{/user}}"),
            blobs_url: format!("{url}/git/blobs{{/sha}}"),
            branches_url: format!("{url}/branches{{/branch}}"),
            clone_url: format!("{root}/{full_name}"),
            collaborators_url: format!("{url}/collaborators{{/collaborator}}"),
            comments_url: format!("{url}/comments{{/number}}"),
            commits_url: format!("{url}/commits{{/sha}}"),
            compare_url: format!("{url}/compare/{{base}}...{{head}}"),
            contents_url: format!("{url}/contents/{{+path}}"),
            contributors_url: format!("{url}/contributors"),
            deployments_url: format!("{url}/deployments"),
            downloads_url: format!("{url}/downloads"),
            events_url: format!("{url}/events"),
            forks_url: format!("{url}/forks"),
            git_commits_url: format!("{url}/git/commits{{/sha}}"),
            git_refs_url: format!("{url}/git/refs{{/sha}}"),
            git_tags_url: format!("{url}/git/tags{{/sha}}"),
            git_url: format!("git:github.com/{full_name}.git"),
            hooks_url: format!("{url}/hooks"),
            issue_comment_url: format!("{url}/issues/comments{{/number}}"),
            issue_events_url: format!("{url}/issues/events{{/number}}"),
            issues_url: format!("{url}/issues{{/number}}"),
            keys_url: format!("{url}/keys{{/key_id}}"),
            labels_url: format!("{url}/labels{{/name}}"),
            languages_url: format!("{url}/languages"),
            merges_url: format!("{url}/merges"),
            milestones_url: format!("{url}/milestones{{/number}}"),
            notifications_url: format!(
                "{url}/notifications{{?since,all,participating}}"
            ),
            pulls_url: format!("{url}/pulls{{/number}}"),
            releases_url: format!("{url}/releases{{/id}}"),
            ssh_url: format!("git@github.com:{full_name}.git"),
            stargazers_url: format!("{url}/stargazers"),
            statuses_url: format!("{url}/statuses/{{sha}}"),
            subscribers_url: format!("{url}/subscribers"),
            subscription_url: format!("{url}/subscription"),
            tags_url: format!("{url}/tags"),
            teams_url: format!("{url}/teams"),
            trees_url: format!("{url}/git/trees{{/sha}}"),

            full_name,
            url,
            ..Self::default()
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct CreateRepositoryRequest {
    pub name: String,
    #[serde(default)]
    pub auto_init: bool,
}

#[derive(Deserialize, Debug)]
pub struct UpdateRepository {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub default_branch: Option<String>,
}
#[derive(Deserialize, Default)]
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
#[derive(Deserialize, Debug)]
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
    pub branch: Option<String>,
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
#[derive(Serialize, Debug)]
pub struct Tree {
    pub sha: String,
    pub url: Option<String>,
}
#[derive(Serialize, Debug)]
pub struct CommitLink {
    pub url: String,
    #[serde(default)]
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
    pub parents: Vec<CommitLink>,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum DiffEntryStatus {
    Added,
    Modified,
    Removed,
    Renamed,
    Copied,
    Changed,
    Unchanged,
}
#[derive(Serialize, Debug)]
pub struct DiffEntry {
    sha: String,
    filename: String,
    status: DiffEntryStatus,
    additions: usize,
    deletions: usize,
    changes: usize,
    blob_url: String,
    raw_url: String,
    contents_url: String,
    /// unifified diff text for the change (TODO: when's it left out?
    /// Should this be skip_serializing_if = String::is_empty?)
    patch: Option<String>,
    /// the previous filename, if the file was renamed (TODO: check)
    previous_filename: Option<String>,
}
// I really only care about the `commit` bit anyway
#[derive(Serialize, Debug)]
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<DiffEntry>,
}

#[derive(Serialize, Debug)]
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
#[derive(Deserialize, Debug)]
pub struct CreateHook {
    /// Use `web` to create a webhook. This parameter
    /// only accepts the value `web`.
    #[serde(default = "default_hook_name")]
    pub name: String,
    pub config: CreateHookConfig,
    /// Determines what events the hook is triggered for.
    #[serde(default = "HookEvent::default")]
    pub events: BTreeSet<HookEvent>,
    /// Determines if notifications are sent when the webhook is
    /// triggered. Set to `true` to send notifications.
    #[serde(default = "default_true")]
    pub active: bool,
}

/// .paths."/repos/{owner}/{repo}/hooks/{hook_id}".patch
///     .requestBody.content."application/json".schema.properties
#[derive(Deserialize, Debug, Default)]
#[serde(default)]
pub struct UpdateHook {
    /// Determines if notifications are sent when the webhook is triggered.
    /// Set to `true` to send notifications.
    ///
    /// NB: default = true?
    pub active: Option<bool>,
    /// Webhook Configuration
    pub config: Option<UpdateHookConfig>,
    /// Determines what [events](https://docs.github.com/webhooks/event-payloads)
    /// the hook is triggered for. This replaces the entire array of events.
    ///
    /// NB: default = ["push"]???
    pub events: BTreeSet<HookEvent>,
    /// Determines a list of events to be added to the list of events that
    /// the Hook triggers for.
    pub add_events: Vec<HookEvent>,
    /// Determines a list of events to be removed from the list of events
    /// that the Hook triggers for.
    pub remove_events: BTreeSet<HookEvent>,
}

/// #/components/schemas/webhook-config
#[derive(Deserialize, Debug, Default)]
#[serde(default)]
pub struct UpdateHookConfig {
    /// The URL to which the payloads will be delivered.
    pub url: Option<String>,
    /// The media type used to serialize the payloads.
    /// Supported values include `json` and `form`.
    /// The default is `form`.
    pub content_type: Option<HookContentType>,
    /// If provided, the `secret` will be used as the `key` to
    /// generate the HMAC hex digest value for
    /// [delivery signature headers](https://docs.github.com/webhooks/event-payloads/#delivery-headers).
    pub secret: Option<String>,
    /// Determines whether the SSL certificate of the host for `url` will be
    /// verified when delivering payloads. Supported values include `0`
    /// (verification is performed) and `1` (verification is not performed).
    /// The default is `0`. **We strongly recommend not setting this to `1` as
    /// you are subject to man-in-the-middle and other attacks.**
    #[serde(default = "default_true", deserialize_with = "boolish")]
    pub insecure_ssl: bool,
}

// note: enum needs to be kept in order so the sorting works
#[derive(
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    Debug,
    Copy,
    Clone,
    PartialOrd,
    Ord,
)]
#[serde(rename_all = "snake_case")]
pub enum HookEvent {
    IssueComment,
    PullRequest,
    PullRequestReview,
    Push,
    Status,
}

impl HookEvent {
    fn default() -> BTreeSet<Self> {
        [Self::Push].into()
    }
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
    #[serde(default)] // defaulting so the error can be checked server side
    pub url: String,
    /// The default media type used to serialize the payloads,
    /// supported values include json and form.
    #[serde(default)]
    pub content_type: HookContentType,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret: String,
    /// Determines whether the SSL certificate of the host `url` will
    /// be verified when delivering payloads, can be configured using
    /// a number (0 or 1) or a string ('0' or '1')
    #[serde(
        default,
        deserialize_with = "boolish",
        serialize_with = "dumbbool"
    )]
    pub insecure_ssl: bool,
}
fn dumbbool<S>(&v: &bool, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if v {
        s.serialize_str("1")
    } else {
        s.serialize_str("0")
    }
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
        Ok(Value::Bool(b)) => Some(b),
        Ok(Value::Number(n)) => match n.as_i64() {
            Some(0) => Some(false),
            Some(1) => Some(true),
            _ => None,
        },
        Ok(Value::String(s)) if s == "0" => Some(false),
        Ok(Value::String(s)) if s == "1" => Some(true),
        _ => None,
    }
    .ok_or_else(|| {
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

#[derive(Deserialize, Debug)]
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

#[derive(Deserialize, Debug)]
pub struct CreateRepositoryRuleset {
    pub name: String,
    pub target: RulesetTarget,
    pub enforcement: RulesetEnforcement,
    //pub bypass_actors: Vec<CreateRepositoryRulesetBypassActor>,
    pub conditions: RulesetConditions,
    pub rules: Vec<RulesetRule>,
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
#[serde(rename_all = "snake_case")]
pub enum RulesetTarget {
    Branch,
    // Tag,
    // Push,
}
#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
#[serde(rename_all = "snake_case")]
pub enum RulesetEnforcement {
    Active,
    Disabled,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct RulesetConditions {
    pub ref_name: RuleSetConditionsRefName,
}
#[derive(Deserialize, Serialize, Debug)]
pub struct RuleSetConditionsRefName {
    // NOTE: magic values ~DEFAULT_BRANCH and ~ALL
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RulesetBypassActor {
    // FIXME: custom deserialize?
    //        - default None if DeployKey
    //        - default 1 if OrganizationAdmin
    //        - required and id of the actor otherwise
    pub actor_id: Option<i64>,
    pub actor_type: CreateRepositoryRulesetBypassActorType,
    #[serde(default)]
    pub bypass_mode: CreateRepositoryRulesetBypassActorMode,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum CreateRepositoryRulesetBypassActorType {
    Integration,
    OrganizationAdmin,
    RepositoryRole,
    Team,
    DeployKey,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
pub enum CreateRepositoryRulesetBypassActorMode {
    Allow,
    // only applicable for branches, not applicable for DeployKey
    PullRequest,
}
impl Default for CreateRepositoryRulesetBypassActorMode {
    fn default() -> Self {
        Self::Allow
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RulesetRuleDeserializerType {
    Creation,
    Update,
}
#[derive(Deserialize, Serialize)]
struct RulesetRuleDeserializer {
    r#type: RulesetRuleDeserializerType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parameters: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(
    // Needed because serde doesn't support optional `content`,
    // so if it's not specified we get an unhelpful 422
    try_from = "RulesetRuleDeserializer",
    into = "RulesetRuleDeserializer",
)]
pub enum RulesetRule {
    Creation,
    Update(RulesetRuleUpdate),
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct RulesetRuleUpdate {
    // TODO: find out what the fuck this does
    pub update_allows_fetch_and_merge: bool,
}

impl From<RulesetRule> for RulesetRuleDeserializer {
    fn from(value: RulesetRule) -> Self {
        match value {
            RulesetRule::Creation => Self {
                r#type: RulesetRuleDeserializerType::Creation,
                parameters: None,
            },
            RulesetRule::Update(update) => Self {
                r#type: RulesetRuleDeserializerType::Update,
                parameters: Some(
                    serde_json::to_value(update)
                        .expect("serialization to always succeed"),
                ),
            },
        }
    }
}

impl TryFrom<RulesetRuleDeserializer> for RulesetRule {
    type Error = serde_json::Error;

    fn try_from(value: RulesetRuleDeserializer) -> Result<Self, Self::Error> {
        Ok(match value.r#type {
            RulesetRuleDeserializerType::Creation => RulesetRule::Creation,
            RulesetRuleDeserializerType::Update => RulesetRule::Update(
                if let Some(parameters) = value.parameters {
                    serde_json::from_value(parameters)?
                } else {
                    RulesetRuleUpdate::default()
                },
            ),
        })
    }
}

#[derive(Serialize)]
pub struct RulesetResponseShort {
    pub id: i64,
    pub node_id: String,
    pub created_at: String,
    pub updated_at: String,
    pub name: String,
    pub target: RulesetTarget,
    pub source_type: RulesetSourceType,
    pub source: String,
    pub enforcement: RulesetEnforcement,
    #[serde(rename = "_links")]
    pub links: RulesetLinks,
}

#[derive(Serialize)]
pub struct RulesetResponse {
    #[serde(flatten)]
    pub _short: RulesetResponseShort,
    pub bypass_actors: Vec<RulesetBypassActor>,
    pub conditions: RulesetConditions,
    pub rules: Vec<RulesetRule>,
}

#[derive(Serialize)]
pub enum RulesetSourceType {
    Repository,
}

#[derive(Serialize)]
pub struct RulesetLinks {
    pub html: super::Link,
    #[serde(rename = "self")]
    pub self_: super::Link,
}

#[derive(Serialize)]
pub struct RulesetRuleResponse {
    pub ruleset_id: i64,
    pub ruleset_source_type: RulesetSourceType,
    pub ruleset_source: String,
    #[serde(flatten)]
    pub rule: RulesetRule,
}
