use axum::extract::{Json, Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::Router;
use git_hash::ObjectId;
use hex::ToHex;
use rusqlite::OptionalExtension as _;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::sync::{Arc, RwLock, RwLockReadGuard};

use github_types::repos::{CommitsResponse, HookEvent};
use github_types::users::SimpleUser;
use github_types::{issues::*, pulls::*, webhooks};

use crate::github::repos::send_hook;
use crate::github::{Authorization, Config, Error, GHError, St};
use crate::model::repos::id_by_name;
use crate::model::users::User;
use crate::model::{prs, Source, Token};
use prs::{find_pr, reviews, PullRequestId};

#[derive(Debug)]
pub struct Issue {
    pub number: usize,
    // created_at: datetime
    // updated_at: datetime
    // closed_at: Option<datetime>
    // closed_by: Option<SimpleUser> // apparently not returned for PRs for some reason
    pub state: IssueState,
    // locked: bool,
    // active_lock_reason: Option<enum {'off-topic' | 'too heated' | 'resolved' | 'spam'}>
    pub title: String,
    pub body: Option<String>,
    pub user: Option<User<'static>>, // unset if user has been deleted?
    pub labels: Vec<Label>,
    // reactions: just a struct recounting the number of a specific list of reactions
    // is that useful?
    pub author_association: AuthorAssociation,
    // milestone: (),
    // assignee: Option<SimpleUser>
    // assignees: Option<Vec<SimpleUser>>
    pub comments: Vec<IssueComment<'static>>,
    // indicates whether this is a PR, and contains the PR-specific info
    pub pull_request: Option<()>, // FIXME: Option<PullRequest>,
}

#[derive(Debug, Clone)]
pub struct IssueComment<'a> {
    pub id: i64,
    pub issue_number: usize,
    pub body: String,
    pub user: Option<Cow<'a, User<'static>>>,
    pub created_at: String,
    pub updated_at: String,
}
impl IssueComment<'_> {
    fn into_response(
        self,
        root: &str,
        owner: &str,
        name: &str,
    ) -> IssueCommentResponse {
        IssueCommentResponse {
            id: self.id,
            body: self.body,
            user: self.user.map(|u| u.to_simple(root)),
            created_at: self.created_at,
            updated_at: self.updated_at,
            url: format!(
                "{}/repos/{}/{}/issues/comments/{}",
                root, owner, name, self.id
            ),
            html_url: format!(
                "{}/{}/{}/issues/{}#issuecomment-{}",
                root, owner, name, self.issue_number, self.id,
            ),
        }
    }
}
type PrRow = (usize, String, String, Option<String>, Vec<u8>, String);

impl Issue {
    fn from_row(r: PrRow) -> Self {
        Self {
            number: r.0,
            state: if r.1 == "open" {
                IssueState::Open
            } else {
                IssueState::Closed
            },
            title: r.2,
            body: r.3,
            user: None,
            labels: Vec::new(),
            author_association: AuthorAssociation::None,
            comments: Vec::new(),
            pull_request: None,
            //pull_request: Some(PullRequest {
            //    base: r.5,
            //    head: Head {
            //        sha: r.4.encode_hex(),
            //       r#ref: String::new(),
            //        Path(owner): Path<String>::new(),
            //         repo: Arc::new
            //    }
            //})
        }
    }
    fn to_response(&self) -> IssueResponse {
        IssueResponse {
            id: 0,
            node_id: String::new(),
            number: self.number,
            state: IssueState::Open,
            title: self.title.clone(),
            body: self.body.clone(),
            locked: false,
            user: None,
            author_association: AuthorAssociation::None,
            comments: 0,
            pull_request: None,
        }
    }
}

#[derive(Debug)]
pub struct ReviewComment {
    id: usize,
    body: String,
    pr_id: usize,
    review_id: Option<usize>,
}
#[derive(Debug)]
pub struct ReviewComments {
    next_id: usize,
    comments: HashMap<usize, ReviewComment>,
}
impl ReviewComments {
    pub fn new() -> Self {
        ReviewComments {
            next_id: 1,
            comments: Default::default(),
        }
    }
    pub fn create_comment(
        &mut self,
        pr_id: usize,
        body: String,
    ) -> &mut ReviewComment {
        let id = self.next_id;
        self.next_id += 1;
        self.comments.entry(id).or_insert(ReviewComment {
            id,
            pr_id,
            body,
            review_id: None,
        })
    }
}

#[rustfmt::skip]
pub fn routes() -> Router<St> {
    Router::new()
        .nest("/issues", issues_router())
        .nest("/pulls", pr_router())
}

#[rustfmt::skip]
fn issues_router() -> Router<St> {
    Router::new()
        .route("/", post(create_issue))
        .route("/:number", get(get_issue))
        .route("/:number/labels", get(get_issue_labels).put(replace_issue_labels).post(add_issue_labels))
        .route("/:number/labels/:name", delete(delete_issue_label))
        .route("/:number/comments", get(get_issue_comments).post(create_issue_comment))
        .route("/comments/:id", get(get_issue_comment).patch(update_issue_comment).delete(delete_issue_comment))
}

#[rustfmt::skip]
fn pr_router() -> Router<St> {
    Router::new()
        .route("/", post(create_pull_request))
        .route("/:number", get(get_pull_request).patch(update_pull_request))
        .route("/:number/commits", get(get_pull_request_commits))
        .route("/:number/reviews", get(list_reviews).post(create_review))
        .route("/:number/reviews/:id/comments", get(list_review_comments))
        .route("/:number/comments", get(list_pr_comments).post(create_review_comment))
        .route("/comments/:id", get(get_review_comment).patch(update_review_comment).delete(delete_review_comment))
}

pub fn pr_response(
    tx: &Token,
    st: &Config,
    pr: PullRequestId,
) -> PullRequestResponse {
    let pr = prs::get_pr(tx, pr);
    let issue = pr.issue;

    let repo = &issue.repository;
    let network = repo.network;
    let base_head = crate::model::git::refs::resolve(
        tx,
        repo.id,
        &format!("refs/heads/{}", pr.base),
    )
    .unwrap();

    // FIXME: probably should not traverse both branches in their entirety
    let base_commits: HashSet<_> =
        crate::model::git::log(tx, network, &base_head)
            .unwrap()
            .collect();
    let commits = crate::model::git::log(tx, network, &pr.head)
        .unwrap()
        .filter(|oid| !base_commits.contains(oid))
        .count();
    let number = issue.number;
    PullRequestResponse {
        id: *pr.id,
        node_id: serde_json::to_string(&crate::github::Pid(*pr.id)).unwrap(),
        number,
        _urls: PullRequestUrls::new(
            &format!("{}/repos/{}/{}", st.root, repo.owner.login, repo.name),
            number,
        ),
        user: issue.user.map(|u| u.to_simple(&st.root)),
        state: match issue.state {
            prs::State::Open => IssueState::Open,
            prs::State::Closed => IssueState::Closed,
        },
        locked: false,
        title: issue.title,
        body: issue.body,
        labels: Vec::new(),
        created_at: String::new(),
        updated_at: String::new(),
        closed_at: None,
        merged_at: None,
        merge_commit_sha: String::new(),
        assignee: None,
        assignees: Vec::new(),
        requested_reviewers: Vec::new(),
        head: PullRequestHead {
            sha: pr.head.to_hex().to_string(),
            label: pr.label,
            r#ref: pr.source_branch,
            repo: pr.source.map(|r| r.to_response(tx, &st.root)),
        },
        base: PullRequestBase {
            sha: base_head.to_hex().to_string(),
            label: String::new(),
            r#ref: pr.base,
            repo: repo.to_response(tx, &st.root),
        },
        author_association: AuthorAssociation::None,
        draft: pr.draft,
        merged: false,
        mergeable: true,
        rebaseable: true,
        mergeable_state: "clean".into(),
        merged_by: None,
        comments: 0,
        review_comments: 0,
        maintainer_can_modify: true,
        commits,
        additions: 0,
        deletions: 0,
        changed_files: 0,
    }
}

async fn get_pull_request(
    State(st): State<St>,
    Path((owner, name, pull_number)): Path<(String, String, usize)>,
) -> Result<Json<PullRequestResponse>, GHError<'static>> {
    let mut db = Source::get();
    let tx = &db.token();

    let Some(pr_id) = prs::find_id(tx, &owner, &name, pull_number) else {
        return Err(Error::NotFound.into_response("pulls", "get-a-pull-request"));
    };

    Ok(Json(pr_response(tx, &st, pr_id)))
}

async fn get_pull_request_commits(
    State(st): State<St>,
    Path((owner, name, pull_number)): Path<(String, String, usize)>,
) -> Result<Json<Vec<CommitsResponse>>, GHError<'static>> {
    let mut db = Source::get();
    let tx = &db.token();
    let Some(pr) = prs::find_pr(tx, &owner, &name, pull_number) else {
        return Err(Error::NotFound.into_response("pulls", "list-commits-on-a-pull-request"));
    };

    // not entirely sure how traversal is supposed to work so... just
    // brute-force it since our repos are unlikely to be any sort of large
    let base_commits = {
        let mut commits = HashSet::new();
        let mut to_check = HashSet::with_capacity(5);
        // git repo uses full ref, not just branchname
        let base = format!("refs/heads/{}", pr.base);
        to_check.insert(
            crate::model::git::refs::resolve(tx, pr.issue.repository.id, &base)
                .unwrap(),
        );

        // rust-lang/rust#27804
        while let Some(h) = to_check.iter().next().copied() {
            to_check.remove(&h);

            let c =
                crate::model::git::load(tx, pr.issue.repository.network, &h)
                    .expect("commit not found")
                    .into_commit();
            commits.insert(h);
            to_check
                .extend(c.parents.into_iter().filter(|p| !commits.contains(p)));
        }
        commits
    };

    let mut pr_commits = {
        let mut oids = vec![pr.head];
        let mut commits: Vec<CommitsResponse> = Vec::new();

        let mut commit_buf = Vec::new();
        // TODO: does github traverse this breadth-first or depth-first?
        for i in 0.. {
            let Some(oid) = oids.get(i).copied() else {
                break;
            };

            commit_buf.clear();
            let (kind, data) = crate::model::git::get_in(
                tx,
                pr.issue.repository.network,
                &oid,
                &mut commit_buf,
            )
            .unwrap();
            assert_eq!(kind, git_object::Kind::Commit);
            let commit = git_object::CommitRef::from_bytes(data).unwrap();
            // we're doing breadth-first, bois
            for p in commit.parents() {
                if !base_commits.contains(&p) && !oids.contains(&p) {
                    oids.push(p);
                }
            }
            commits
                .push(super::Bundle(&st, &owner, &name, &oid, &commit).into());
        }
        commits
    };
    pr_commits.reverse();

    Ok(Json(pr_commits))
}

async fn create_pull_request(
    auth: Option<Authorization>,
    State(st): State<St>,
    Path((owner, name)): Path<(String, String)>,
    Json(req): Json<PullRequestCreate>,
) -> Result<(http::StatusCode, Json<PullRequestResponse>), Response> {
    let mut db = Source::get();
    let tx = db.token_eager();

    let Some(user) = auth.and_then(|auth| crate::github::auth_to_user(&tx, auth)) else {
        return Err(Error::NotFound.into_response("pulls", "create-a-pull-request").into_response());
    };
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NotFound.into_response("pulls", "create-a-pull-request").into_response());
    };

    let base_ref = format!("refs/heads/{}", req.base);
    let base = crate::model::git::refs::resolve(&tx, repo.id, &base_ref);
    let base_error = Error::details("PullRequest", "base", "invalid", "");

    let _head_repo;
    // If `head` is of the form {owner}:{branch} it's a cross-repo PR, in
    // that case we need to find the head's repository
    let (head_repo, head_branch) =
        if let Some((owner_, branch)) = req.head.split_once(':') {
            let repo_p = crate::model::users::get_user(&tx, owner_)
                .and_then(|owner| {
                    crate::model::repos::find_fork(&tx, repo.id, owner.id)
                })
                .map(|repo_id| crate::model::repos::by_id(&tx, repo_id));
            if let Some(fork) = repo_p {
                _head_repo = fork;
                (&_head_repo, branch)
            } else {
                return Err(Error::Unprocessable(
                    "Validation Failed",
                    &[Error::details("PullRequest", "head", "invalid", "")],
                )
                .into_response("pulls", "create-a-pull-request")
                .into_response());
            }
        } else {
            (&repo, req.head.as_str())
        };
    let head_ref = format!("refs/heads/{head_branch}");
    let head = crate::model::git::refs::resolve(&tx, head_repo.id, &head_ref);
    let head_error = Error::details("PullRequest", "head", "invalid", "");

    fn validation_failed<'a>(
        es: &'a [crate::github::GithubErrorDetails<'_>],
    ) -> GHError<'a> {
        Error::Unprocessable("Validation Failed", es)
            .into_response("pulls", "create-a-pull-request")
    }

    let (base, head) = match (base, head) {
        (None, None) => {
            return Err(
                validation_failed(&[base_error, head_error]).into_response()
            )
        }
        (None, Some(_)) => {
            return Err(validation_failed(&[base_error]).into_response())
        }
        (Some(_), None) => {
            return Err(validation_failed(&[head_error]).into_response())
        }
        (Some(a), Some(b)) => (a, b),
    };

    let issue_id = match req._source {
        PullRequestSource::FromTitle { title } => prs::issue_create(
            &tx,
            repo.id,
            user.id,
            &title,
            req.body.as_deref().filter(|b| !b.is_empty()),
        ),
        PullRequestSource::FromIssue { issue } => {
            let res = match (
                prs::find_issue_id(&tx, &owner, &name, issue),
                prs::find_id(&tx, &owner, &name, issue)
            ) {
                (Some(id), None) => Ok(id),
                (None, _) => Err("The specified issue does not exist."),
                (Some(_), Some(_)) => Err("The specified issue is already attached to a pull request."),
            };
            match res {
                Ok(issue) => issue,
                Err(err) => {
                    let mut deets =
                        Error::details("PullRequest", "issue", "invalid", "");
                    deets.value = Some(issue);
                    return Err(Error::Unprocessable(err, &[deets])
                        .into_response("pulls", "create-a-pull-request")
                        .into_response());
                }
            }
        }
    };
    let pr_id = prs::create_pr(
        &tx,
        issue_id,
        head,
        &req.base,
        head_repo,
        head_branch,
        req.draft,
    );
    let number = prs::get_pr(&tx, pr_id).issue.number;

    crate::model::git::refs::create(
        &tx,
        repo.id,
        &format!("refs/pull/{number}/head"),
        &head,
    );

    crate::github::repos::send_hook(
        &tx,
        repo,
        &st,
        HookEvent::PullRequest,
        &user,
        || {
            webhooks::WebhookEvent::PullRequest(webhooks::PullRequest {
                action: webhooks::PullRequestAction::Opened,
                number,
                pull_request: pr_response(&tx, &st, pr_id),
            })
        },
    );
    let pr = pr_response(&tx, &st, pr_id);
    tx.commit();
    Ok((http::StatusCode::CREATED, Json(pr)))
}

async fn update_pull_request(
    auth: Authorization,
    State(st): State<St>,
    Path((owner, name, number)): Path<(String, String, usize)>,
    Json(update): Json<PullRequestUpdate>,
) -> Result<Json<PullRequestResponse>, Response> {
    let mut db = Source::get();
    let tx = db.token_eager();
    let user = crate::github::auth_to_user(&tx, auth).unwrap();
    let Some(repo_id) = id_by_name(&tx, &owner, &name) else {
        return Err(Error::NotFound.into_response("pulls", "update-a-pull-request").into_response());
    };

    let Some(pr) = find_pr(&tx, &owner, &name, number) else {
        return Err(Error::NotFound.into_response("pulls", "update-a-pull-request").into_response());
    };

    // PR creator can edit pr, repo writers can edit PR as well
    if !prs::can_write(&tx, user.id, pr.id) {
        return Err(Error::Forbidden("No write acces to the PR")
            .into_response("pulls", "update-a-pull-request")
            .into_response());
    }

    let title = if let Some(t) = update.title {
        if t.is_empty() {
            return Err(Error::Unprocessable(
                "Validation Failed",
                &[Error::details("PullRequest", "title", "missing_field", "")],
            )
            .into_response("pulls", "update-a-pull-request")
            .into_response());
        }
        Some(t)
    } else {
        None
    }
    .filter(|t| t != &pr.issue.title);

    // Some(None) | Some('') => unset, otherwise set
    let body = update
        .body
        .map(|b| b.filter(|s| !s.is_empty()))
        .filter(|b| b != &pr.issue.body);

    // TODO: invalid state?
    let state = update
        .state
        .map(|s| match s {
            IssueState::Open => prs::State::Open,
            IssueState::Closed => prs::State::Closed,
        })
        .filter(|s| s != &pr.issue.state);

    if title.is_none()
        && body.is_none()
        && state.is_none()
        && update.base.is_none()
    {
        return Ok(Json(pr_response(&tx, &st, pr.id)));
    }

    // TODO: test actual message
    // TODO: what if we open & retarget in the same call, is it fine then?
    // TODO: test case, apparently closing & rebasing a PR in the same call
    //       performs the closing first, which fails the base change
    if update.base.is_some() && matches!(pr.issue.state, prs::State::Closed) {
        return Err(Error::Unprocessable(
            "Validation Failed",
            &[Error::details(
                "PullRequest",
                "base",
                "invalid",
                "Cannot change the base branch of a closed pull request.",
            )],
        )
        .into_response("pulls", "update-a-pull-request")
        .into_response());
    }

    // TODO: test actual message
    // TODO: test edge behaviours of updating closed PRs e.g. when hooks occur exactly
    if state == Some(prs::State::Open) && pr.dead {
        return Err(Error::Unprocessable(
            "can not reopen a force-pushed PR",
            &[],
        )
        .into_response("pulls", "update-a-pull-request")
        .into_response());
    }

    prs::update(
        &tx,
        pr.id,
        title.as_deref(),
        body.as_ref().map(|b| b.as_deref()),
        state,
    );

    let new_base = update.base.as_ref();
    if let Some(base) = new_base {
        if crate::model::git::refs::resolve(
            &tx,
            pr.issue.repository.id,
            &format!("refs/heads/{base}"),
        )
        .is_some()
        {
            prs::set_base(&tx, pr.id, base);
        } else {
            return Err(Error::Unprocessable(
                "Validation Failed",
                &[Error::details(
                    "PullRequest",
                    "base",
                    "invalid",
                    &format!("Proposed base branch '{base}' was not found"),
                )],
            )
            .into_response("pulls", "update-a-pull-request")
            .into_response());
        }
    }

    // TODO: what happens if a sync happened while the PR was closed?
    if let Some(s) = state {
        // necessarily different from pr state
        send_hook(
            &tx,
            pr.issue.repository.clone(),
            &st,
            HookEvent::PullRequest,
            &user,
            || {
                webhooks::WebhookEvent::PullRequest(webhooks::PullRequest {
                    action: if s == prs::State::Open {
                        webhooks::PullRequestAction::Reopened
                    } else {
                        webhooks::PullRequestAction::Closed
                    },
                    number,
                    pull_request: pr_response(&tx, &st, pr.id),
                })
            },
        );
    }
    if title.is_some() || body.is_some() || update.base.is_some() {
        let old_sha = crate::model::git::refs::resolve(
            &tx,
            repo_id,
            &format!("refs/heads/{}", pr.base),
        )
        .unwrap()
        .to_hex()
        .to_string();

        send_hook(
            &tx,
            pr.issue.repository,
            &st,
            HookEvent::PullRequest,
            &user,
            || {
                // FIXME: revert to previous correct code, github is a dum dum and
                //        does *not* send a change if `old_body` is null
                webhooks::WebhookEvent::PullRequest(webhooks::PullRequest {
                    action: webhooks::PullRequestAction::Edited {
                        changes: webhooks::PrEdition {
                            title: title.as_ref().map(|_| {
                                webhooks::Change::from(pr.issue.title.clone())
                            }),
                            body: body.as_ref().and_then(|_| {
                                pr.issue
                                    .body
                                    .clone()
                                    .map(webhooks::Change::from)
                            }),
                            base: new_base.filter(|&b| b != &pr.base).map(
                                |_| webhooks::PrBaseChange {
                                    r#ref: pr.base.clone().into(),
                                    sha: old_sha.clone().into(),
                                },
                            ),
                        },
                    },
                    number,
                    pull_request: pr_response(&tx, &st, pr.id),
                })
            },
        );
    }
    let pr = pr_response(&tx, &st, pr.id);
    tx.commit();
    Ok(Json(pr))
}

async fn create_review(
    auth: Authorization,
    State(st): State<St>,
    Path((owner, name, pr)): Path<(String, String, usize)>,
    Json(req): Json<CreateReviewRequest>,
) -> Result<(http::StatusCode, Json<ReviewResponse>), GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token_eager();

    let Some(user) = crate::github::auth_to_user(&tx, auth) else {
        return Err(Error::NotFound.into_response("reviews", "create-a-review-for-a-pull-request"));
    };
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NotFound.into_response("reviews", "create-a-review-for-a-pull-request"));
    };
    let Some(pr) = prs::find_id(&tx, &owner, &name, pr) else {
        return Err(Error::NotFound.into_response("reviews", "create-a-review-for-a-pull-request"));
    };

    let commit_id = if let Some(cid) = req.commit_id {
        // TODO: what response for invalid id?
        let oid = git_hash::ObjectId::from_hex(cid.as_bytes())
            .expect("invalid oid format");
        // TODO: what if commit_id is a well-formed hash but not valid for the repo?
        crate::model::git::get(&tx, repo.network, &oid)
    } else {
        None
    };
    let state = match req.event {
        None => reviews::State::Pending,
        Some(CreateReviewState::Approve) => reviews::State::Approved,
        Some(CreateReviewState::RequestChanges) => {
            reviews::State::ChangesRequested
        }
        Some(CreateReviewState::Comment) => reviews::State::Commented,
    };
    let review_id =
        reviews::create_review(&tx, pr, &req.body, state, commit_id, user.id);
    let r = reviews::get_review(&tx, review_id);
    let review = ReviewResponse {
        id: *r.id,
        node_id: String::new(),
        user: Some(user.to_simple(&st.root)),
        body: r.body,
        state: ReviewState::from(req.event),
        commit_id: crate::model::git::deref(&tx, r.commit_id)
            .to_hex()
            .to_string(),
        html_url: String::new(),
        pull_request_url: String::new(),
        submitted_at: r.submitted_at,
    };
    // FIXME: insert at correct location, get path correctly
    reviews::add_review_comments(
        &tx,
        review_id,
        req.comments.into_iter().map(|c| c.body),
    );

    tx.commit();

    let tx = &db.token();
    let repository = crate::model::repos::by_name(tx, &owner, &name).unwrap();
    send_hook(
        tx,
        repository,
        &st,
        HookEvent::PullRequestReview,
        &user,
        || {
            webhooks::WebhookEvent::PullRequestReview(
                webhooks::PullRequestReview {
                    // FIXME: wut?
                    action: webhooks::ReviewAction::Submitted,
                    pull_request: pr_response(tx, &st, pr),
                    review: review.clone().into(),
                },
            )
        },
    );

    Ok((http::StatusCode::CREATED, Json(review)))
}

async fn list_reviews(
    State(st): State<St>,
    Path((owner, name, pr)): Path<(String, String, usize)>,
) -> Result<Json<Vec<ReviewResponse>>, GHError<'static>> {
    let mut db = Source::get();
    let tx = &db.token();

    let Some(pr) = prs::find_id(tx, &owner, &name, pr) else {
        return Err(Error::NotFound.into_response("reviews", "list-reviews-for-a-pull-request"));
    };

    // TODO: pagination
    let reviews = prs::reviews::list(tx, pr, |r| {
        let author = crate::model::users::get_by_id(tx, r.author);
        ReviewResponse {
            id: *r.id,
            node_id: String::new(),
            user: Some(author.to_simple(&st.root)),
            body: r.body,
            state: match r.state {
                reviews::State::Pending => ReviewState::Pending,
                reviews::State::Approved => ReviewState::Approved,
                reviews::State::ChangesRequested => {
                    ReviewState::ChangesRequested
                }
                reviews::State::Commented => ReviewState::Commented,
            },
            commit_id: crate::model::git::deref(tx, r.commit_id)
                .to_hex()
                .to_string(),
            html_url: String::new(),
            pull_request_url: String::new(),
            submitted_at: r.submitted_at,
        }
    });
    Ok(Json(reviews))
}

fn comment_to_response(
    root: &str,
    owner: &str,
    name: &str,
    c: reviews::ReviewComment,
) -> ReviewCommentResponse {
    ReviewCommentResponse {
        id: *c.id,
        body: c.body,
        url: format!(
            "{}/repos/{}/{}/pulls/comments/{}",
            root, owner, name, *c.id
        ),

        pull_request_review_id: c.review.map(|id| *id),
        in_reply_to_id: c.in_reply_to.map(|id| *id),

        created_at: c.created_at,
        updated_at: c.updated_at,
    }
}

async fn list_review_comments(
    State(st): State<St>,
    Path((owner, name, pr_number, review_id)): Path<(
        String,
        String,
        usize,
        i64,
    )>,
) -> Result<Json<Vec<ReviewCommentResponse>>, GHError<'static>> {
    let mut db = Source::get();
    let tx = &db.token();

    let Some(pr_id) = prs::find_id(tx, &owner, &name, pr_number) else {
        return Err(Error::NotFound.into_response(
            "reviews",
            "list-comments-for-a-pull-request-review",
        ));
    };
    let Some(review) = reviews::get_by_i64(tx, review_id) else {
        return Err(Error::NotFound.into_response(
            "reviews",
            "list-comments-for-a-pull-request-review",
        ));
    };
    // TODO: what if the review is not on the PR?
    assert_eq!(pr_id, review.pull_request);

    let comments = reviews::list_comments(tx, review.id, |c| {
        comment_to_response(&st.root, &owner, &name, c)
    });

    Ok(Json(comments))
}

async fn list_pr_comments(
    State(st): State<St>,
    Path((owner, name, pr_number)): Path<(String, String, usize)>,
) -> Result<Json<Vec<ReviewCommentResponse>>, GHError<'static>> {
    let mut db = Source::get();
    let tx = &db.token();

    let Some(pr_id) = prs::find_id(tx, &owner, &name, pr_number) else {
        return Err(Error::NotFound.into_response(
            "reviews",
            "list-review-comments-on-a-pull-request",
        ));
    };

    let comments = reviews::list_pr_comments(tx, pr_id, |c| {
        comment_to_response(&st.root, &owner, &name, c)
    });

    Ok(Json(comments))
}

async fn create_review_comment(
    State(st): State<St>,
    Path((owner, name, pr_number)): Path<(String, String, usize)>,
    Json(req): Json<CreateReviewCommentRequest>,
) -> Result<(http::StatusCode, Json<ReviewCommentResponse>), GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token();

    let Some(pr_id) = prs::find_id(&tx, &owner, &name, pr_number) else {
        return Err(Error::NotFound.into_response(
            "pulls",
            "update-a-review-comment-for-a-pull-request",
        ));
    };

    let comments =
        reviews::add_pr_comments(&tx, pr_id, [req._comment.body].into_iter());

    let comment = reviews::get_comment(&tx, comments[0]);

    tx.commit();

    Ok((
        http::StatusCode::CREATED,
        Json(comment_to_response(&st.root, &owner, &name, comment)),
    ))
}

// TODO: what happens for review comments of reviews?
async fn get_review_comment(
    State(st): State<St>,
    Path((owner, name, comment_id)): Path<(String, String, i64)>,
) -> Result<Json<ReviewCommentResponse>, GHError<'static>> {
    let mut db = Source::get();
    let tx = &db.token();

    let Some(repo_id) = id_by_name(tx, &owner, &name) else {
    return Err(Error::NotFound.into_response(
        "pulls",
        "get-a-review-comment-for-a-pull-request",
    ));
    };

    let Some(comment) = reviews::comment_by_i64(tx, repo_id, comment_id)
            .map(|cid| reviews::get_comment(tx, cid)) else {
        return Err(Error::NotFound.into_response(
            "pulls",
            "get-a-review-comment-for-a-pull-request",
        ));
    };

    Ok(Json(comment_to_response(&st.root, &owner, &name, comment)))
}

async fn update_review_comment(
    State(st): State<St>,
    Path((owner, name, comment_id)): Path<(String, String, i64)>,
    Json(req): Json<UpdateReviewCommentRequest>,
) -> Result<Json<ReviewCommentResponse>, GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token();

    let Some(repo_id) = id_by_name(&tx, &owner, &name) else {
        return Err(Error::NotFound.into_response(
            "pulls",
            "create-a-review-comment-for-a-pull-request",
        ));
    };
    let Some(comment_id) = reviews::comment_by_i64(&tx, repo_id, comment_id) else {
        return Err(Error::NotFound.into_response(
            "pulls",
            "create-a-review-comment-for-a-pull-request",
        ));
    };

    reviews::update_comment(&tx, comment_id, &req.body);

    let comment = reviews::get_comment(&tx, comment_id);

    tx.commit();

    Ok(Json(comment_to_response(&st.root, &owner, &name, comment)))
}

async fn delete_review_comment(
    State(st): State<St>,
    Path((owner, name, comment_id)): Path<(String, String, i64)>,
) -> Result<http::StatusCode, GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token();

    let Some(repo_id) = id_by_name(&tx, &owner, &name) else {
        return Err(Error::NotFound.into_response(
            "pulls",
            "delete-a-review-comment-for-a-pull-request",
        ));
    };
    let Some(comment_id) = reviews::comment_by_i64(&tx, repo_id, comment_id) else {
        return Err(Error::NotFound.into_response(
            "pulls",
            "delete-a-review-comment-for-a-pull-request",
        ));
    };

    if reviews::delete_comment(&tx, comment_id) {
        tx.commit();
        Ok(http::StatusCode::NO_CONTENT)
    } else {
        Err(Error::NotFound.into_response(
            "pulls",
            "delete-a-review-comment-for-a-pull-request",
        ))
    }
}

async fn get_issue(
    State(st): State<St>,
    Path((owner, name, number)): Path<(String, String, usize)>,
) -> Result<Json<IssueResponse>, GHError<'static>> {
    let mut db = Source::get();
    let tx = &db.token();

    let Some(issue_id) = prs::find_issue_id(tx, &owner, &name, number) else {
        return Err(Error::NotFound.into_response("issues", "get-an-issue"));
    };

    let issue = prs::get_issue(tx, issue_id);

    let response = IssueResponse {
        id: *issue.id,
        node_id: String::new(),
        number: issue.number,
        state: match issue.state {
            prs::State::Open => IssueState::Open,
            prs::State::Closed => IssueState::Closed,
        },
        title: issue.title,
        body: issue.body,
        locked: false,
        user: issue.user.map(|u| u.to_simple(&st.root)),
        author_association: AuthorAssociation::None,
        comments: 0,
        pull_request: prs::find_id(tx, &owner, &name, number)
            .map(|p| pr_response(tx, &st, p)),
    };

    Ok(Json(response))
}

async fn create_issue(
    auth: Authorization,
    State(st): State<St>,
    Path((owner, name)): Path<(String, String)>,
    Json(req): Json<IssueCreate>,
) -> Result<(http::StatusCode, Json<IssueResponse>), GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token();

    let Some(user) = crate::github::auth_to_user(&tx, auth) else {
        return Err(Error::Unauthenticated("").into_response("issues", "create-an-issue"));
    };

    let Some(repo_id) = id_by_name(&tx, &owner, &name) else {
        return Err(Error::NotFound.into_response("issues", "create-an-issue"));
    };

    let issue_id = prs::issue_create(
        &tx,
        repo_id,
        user.id,
        &req.title,
        req.body.as_deref(),
    );
    let issue = prs::get_issue(&tx, issue_id);
    tx.commit();

    let tx = &db.token();
    Ok((
        http::StatusCode::CREATED,
        Json(IssueResponse {
            id: *issue.id,
            node_id: String::new(),
            number: issue.number,
            state: match issue.state {
                prs::State::Open => IssueState::Open,
                prs::State::Closed => IssueState::Closed,
            },
            title: issue.title,
            body: issue.body,
            locked: false,
            user: issue.user.map(|u| u.to_simple(&st.root)),
            author_association: AuthorAssociation::None,
            comments: 0,
            pull_request: None,
        }),
    ))
}

fn label_to_label(
    root: &str,
    owner: &str,
    name: &str,
    label: prs::Label,
) -> Label {
    Label {
        id: *label.id,
        url: format!("{}/repos/{}/{}/labels/{}", root, owner, name, label.name),
        name: label.name,
        description: label.description,
        color: label.color,
    }
}
async fn get_issue_labels(
    State(st): State<St>,
    Path((owner, name, issue_number)): Path<(String, String, usize)>,
) -> Result<Json<Vec<Label>>, GHError<'static>> {
    let mut db = Source::get();
    let tx = &db.token();

    let Some(issue_id) = prs::find_issue_id(tx, &owner, &name, issue_number) else {
        return Err(Error::NotFound.into_response("labels", "list-labels-for-an-issue"));
    };

    let labels = prs::get_labels(tx, issue_id, |l| {
        label_to_label(&st.root, &owner, &name, l)
    });
    Ok(Json(labels))
}

#[derive(Deserialize)]
struct Labels {
    labels: Vec<String>,
}
async fn replace_issue_labels(
    State(st): State<St>,
    Path((owner, name, issue_number)): Path<(String, String, usize)>,
    Json(labels): Json<Labels>,
) -> Result<Json<Vec<Label>>, GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token();

    let Some(issue) = prs::find_issue_id(&tx, &owner, &name, issue_number) else {
        return Err(Error::NotFound.into_response("labels", "add-labels-to-an-issue"));
    };

    for label in prs::get_labels(&tx, issue, |l| l.id) {
        prs::remove_label(&tx, issue, label);
    }
    for label in labels
        .labels
        .into_iter()
        .map(|name| prs::ensure_label_exists(&tx, &name))
    {
        prs::add_label(&tx, issue, label);
    }

    let labels = prs::get_labels(&tx, issue, |l| {
        label_to_label(&st.root, &owner, &name, l)
    });
    tx.commit().unwrap();

    Ok(Json(labels))
}

// fixme: does this return just the new labels, or all the labels?
async fn add_issue_labels(
    State(st): State<St>,
    Path((owner, name, issue_number)): Path<(String, String, usize)>,
    Json(labels): Json<Labels>,
) -> Result<Json<Vec<Label>>, GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token();

    let Some(issue) = prs::find_issue_id(&tx, &owner, &name, issue_number) else {
        return Err(Error::NotFound.into_response("labels", "add-labels-to-an-issue"));
    };

    for label in labels
        .labels
        .into_iter()
        .map(|name| prs::ensure_label_exists(&tx, &name))
    {
        prs::add_label(&tx, issue, label);
    }

    let labels = prs::get_labels(&tx, issue, |l| {
        label_to_label(&st.root, &owner, &name, l)
    });
    tx.commit().unwrap();

    Ok(Json(labels))
}

async fn delete_issue_label(
    State(st): State<St>,
    Path((owner, name, issue_number)): Path<(String, String, usize)>,
    Path(label): Path<String>,
) -> Result<Json<Vec<Label>>, GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token();

    let Some(issue) = prs::find_issue_id(&tx, &owner, &name, issue_number) else {
        return Err(Error::NotFound.into_response("labels", "add-labels-to-an-issue"));
    };

    if let Some(existing) = prs::get_labels(&tx, issue, |l| l)
        .into_iter()
        .find(|l| l.name == label)
    {
        prs::remove_label(&tx, issue, existing.id);
    }

    let labels = prs::get_labels(&tx, issue, |l| {
        label_to_label(&st.root, &owner, &name, l)
    });
    tx.commit().unwrap();

    Ok(Json(labels))
}

async fn get_issue_comments(
    State(st): State<St>,
    Path((owner, name, issue_number)): Path<(String, String, usize)>,
) -> Result<Json<Vec<IssueCommentResponse>>, GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token();

    let Some(issue) = prs::find_issue_id(&tx, &owner, &name, issue_number) else {
        return Err(Error::NotFound.into_response("labels", "add-labels-to-an-issue"));
    };

    let comments = prs::get_comments(&tx, issue, |c| {
        IssueComment {
            id: *c.id,
            issue_number,
            body: c.body,
            user: c
                .author
                .map(|uid| crate::model::users::get_by_id(&tx, uid))
                .map(Cow::Owned),
            created_at: c.created_at,
            updated_at: c.updated_at,
        }
        .into_response(&st.root, &owner, &name)
    });

    Ok(Json(comments))
}

async fn create_issue_comment(
    auth: Authorization,
    State(st): State<St>,
    Path((owner, name, issue_number)): Path<(String, String, usize)>,
    Json(req): Json<CommentCreate>,
) -> Result<(http::StatusCode, Json<IssueCommentResponse>), GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token_eager();

    let Some(user) = crate::github::auth_to_user(&tx, auth) else {
        return Err(Error::Unauthenticated("").into_response("issues", "create-an-issue-response"));
    };
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NotFound.into_response("issues", "create-an-issue-comments"));
    };
    let Some(issue) = prs::find_issue_id(&tx, &owner, &name, issue_number)
            .map(|id| prs::get_issue(&tx, id)) else {
        return Err(Error::NotFound.into_response("issues", "create-an-issue-comments"));
    };

    let comment_id = prs::create_comment(&tx, user.id, issue.id, &req.body);
    let comment = prs::get_comment(&tx, comment_id);

    send_hook(&tx, repo, &st, HookEvent::IssueComment, &user, || {
        let mut issue_response = Issue {
            number: issue.number,
            user: issue.user.clone(),
            state: match issue.state {
                prs::State::Open => IssueState::Open,
                prs::State::Closed => IssueState::Closed,
            },
            author_association: AuthorAssociation::None,
            title: issue.title.clone(),
            body: issue.body.clone(),
            comments: Vec::new(),
            labels: Vec::new(),
            pull_request: None,
        }
        .to_response();
        issue_response.pull_request = prs::find_by_id(&tx, *issue.id)
            .map(|pr| pr_response(&tx, &st, pr.id));
        webhooks::WebhookEvent::IssueComment(webhooks::IssueComment {
            action: webhooks::IssueCommentAction::Created,
            issue: issue_response,
            comment: IssueComment {
                id: *comment.id,
                issue_number,
                body: comment.body.clone(),
                user: Some(Cow::Borrowed(&user)),
                created_at: comment.created_at.clone(),
                updated_at: comment.updated_at.clone(),
            }
            .into_response(&st.root, &owner, &name),
        })
    });
    tx.commit();

    // should have a comment id, but how can I know what it is?
    Ok((
        http::StatusCode::CREATED,
        Json(
            IssueComment {
                id: *comment.id,
                issue_number: issue.number,
                body: comment.body,
                user: Some(Cow::Borrowed(&user)),
                created_at: comment.created_at,
                updated_at: comment.updated_at,
            }
            .into_response(&st.root, &owner, &name),
        ),
    ))
}

async fn get_issue_comment(
    State(st): State<St>,
    Path((owner, name, comment_id)): Path<(String, String, i64)>,
) -> Result<Json<IssueCommentResponse>, GHError<'static>> {
    let mut db = Source::get();
    let tx = &db.token();

    let Some(repo_id) = id_by_name(tx, &owner, &name) else {
        return Err(Error::NotFound.into_response("issues", "get-an-issue-comment"));
    };
    let Some(comment) = prs::get_comment_by_i64(tx, repo_id, comment_id) else {
        return Err(Error::NotFound.into_response("issues", "get-an-issue-comment"));
    };
    let issue = prs::get_issue(tx, comment.issue);

    Ok(Json(
        IssueComment {
            id: *comment.id,
            issue_number: issue.number,
            body: comment.body,
            user: comment
                .author
                .map(|uid| crate::model::users::get_by_id(tx, uid))
                .map(Cow::Owned),
            created_at: comment.created_at,
            updated_at: comment.updated_at,
        }
        .into_response(&st.root, &owner, &name),
    ))
}

async fn update_issue_comment(
    auth: Authorization,
    State(st): State<St>,
    Path((owner, name, comment_id)): Path<(String, String, i64)>,
    Json(IssueUpdate { body }): Json<IssueUpdate>,
) -> Result<Json<IssueCommentResponse>, GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token();

    let Some(user) = crate::github::auth_to_user(&tx, auth) else {
        return Err(Error::Unauthenticated("").into_response("issues", "update-an-issue-comment"));
    };
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NotFound.into_response("issues", "update-an-issue-comment"));
    };
    let Some(comment) = prs::get_comment_by_i64(&tx, repo.id, comment_id) else {
        return Err(Error::NotFound.into_response("issues", "update-an-issue-comment"));
    };

    let issue = prs::get_issue(&tx, comment.issue);
    let author = comment
        .author
        .map(|uid| crate::model::users::get_by_id(&tx, uid));

    prs::update_comment(&tx, comment.id, &body);

    let issue_comment = IssueComment {
        id: *comment.id,
        issue_number: issue.number,
        body,
        user: author.as_ref().map(Cow::Borrowed),
        created_at: comment.created_at.clone(),
        updated_at: comment.updated_at.clone(),
    };
    send_hook(&tx, repo, &st, HookEvent::IssueComment, &user, || {
        let mut issue_response = Issue {
            number: issue.number,
            user: issue.user.clone(),
            state: match issue.state {
                prs::State::Open => IssueState::Open,
                prs::State::Closed => IssueState::Closed,
            },
            author_association: AuthorAssociation::None,
            title: issue.title.clone(),
            body: issue.body.clone(),
            comments: Vec::new(),
            labels: Vec::new(),
            pull_request: None,
        }
        .to_response();
        issue_response.pull_request = prs::find_by_id(&tx, *issue.id)
            .map(|pr| pr_response(&tx, &st, pr.id));
        webhooks::WebhookEvent::IssueComment(webhooks::IssueComment {
            action: webhooks::IssueCommentAction::Edited {
                changes: comment.body.clone().into(),
            },
            issue: issue_response,
            comment: issue_comment
                .clone()
                .into_response(&st.root, &owner, &name),
        })
    });
    tx.commit();

    Ok(Json(issue_comment.into_response(&st.root, &owner, &name)))
}

async fn delete_issue_comment(
    auth: Authorization,
    State(st): State<St>,
    Path((owner, name, comment_id)): Path<(String, String, i64)>,
) -> Result<http::StatusCode, GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token();

    let Some(user) = crate::github::auth_to_user(&tx, auth) else {
        return Err(Error::Unauthenticated("").into_response("issues", "delete-an-issue-comment"));
    };
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NotFound.into_response("issues", "delete-an-issue-comment"));
    };
    let Some(comment) = prs::get_comment_by_i64(&tx, repo.id, comment_id) else {
        return Err(Error::NotFound.into_response("issues", "delete-an-issue-comment"));
    };

    let issue = prs::get_issue(&tx, comment.issue);
    let author = comment
        .author
        .map(|uid| crate::model::users::get_by_id(&tx, uid));

    prs::delete_comment(&tx, comment.id);

    send_hook(&tx, repo, &st, HookEvent::IssueComment, &user, || {
        let mut issue_response = Issue {
            number: issue.number,
            user: issue.user.clone(),
            state: match issue.state {
                prs::State::Open => IssueState::Open,
                prs::State::Closed => IssueState::Closed,
            },
            author_association: AuthorAssociation::None,
            title: issue.title.clone(),
            body: issue.body.clone(),
            comments: Vec::new(),
            labels: Vec::new(),
            pull_request: None,
        }
        .to_response();
        issue_response.pull_request = prs::find_by_id(&tx, *issue.id)
            .map(|pr| pr_response(&tx, &st, pr.id));
        webhooks::WebhookEvent::IssueComment(webhooks::IssueComment {
            action: webhooks::IssueCommentAction::Deleted,
            issue: issue_response,
            comment: IssueComment {
                id: *comment.id,
                issue_number: issue.number,
                body: comment.body.clone(),
                user: author.as_ref().map(Cow::Borrowed),
                created_at: comment.created_at.clone(),
                updated_at: comment.updated_at.clone(),
            }
            .into_response(&st.root, &owner, &name),
        })
    });
    tx.commit();
    Ok(http::StatusCode::NO_CONTENT)
}
