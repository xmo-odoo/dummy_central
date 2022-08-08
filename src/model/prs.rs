use git_hash::{oid, ObjectId};
use rusqlite::{types::FromSqlError, OptionalExtension as _};

use super::{
    git::ObjectDbId,
    repos::{Repository, RepositoryId},
    users::UserId,
    Token,
};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PullRequestId(i64);
// FIXME
impl PullRequestId {
    pub fn unsafe_from(i: i64) -> Self {
        Self(i)
    }
}
impl std::ops::Deref for PullRequestId {
    type Target = i64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone)]
pub struct PullRequest {
    pub id: PullRequestId,
    pub issue: Issue,
    pub head: git_hash::ObjectId,
    pub draft: bool,

    /// target branch
    pub base: String,
    /// <owner>:<branch>, remains accessible even if the other fields are emptied
    pub label: String,
    // source branch information
    /// Source repository, contains owner info
    // TODO: check if both owner & repo disappear when the repo is deleted
    pub source: Option<super::repos::Repository>,
    pub source_branch: String, // does it also get removed?
    /// If a PR's source branch was (force?) pushed while it was closed, the PR
    /// can not be reopened
    pub dead: bool,
}

#[derive(Copy, Clone, Debug)]
pub struct IssueId(i64);
impl std::ops::Deref for IssueId {
    type Target = i64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
/// A PR id is always an issue id (?)
// TODO: or should PullRequestId just deref to an IssueId? That means
//       PullRequestId(IssueId(i64)) tho
impl From<PullRequestId> for IssueId {
    fn from(pid: PullRequestId) -> Self {
        Self(*pid)
    }
}
#[derive(Clone)]
pub struct Issue {
    pub id: IssueId,
    pub number: usize,
    /// repository the issue / pr was opened into
    pub repository: super::repos::Repository,
    /// creator of the issue / PR, probs
    pub user: Option<super::users::User<'static>>,
    pub title: String,
    pub body: Option<String>,
    pub state: State,
}
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum State {
    Open,
    Closed,
}
impl State {
    pub fn as_str(&self) -> &'static str {
        match self {
            State::Open => "open",
            State::Closed => "closed",
        }
    }
}
impl rusqlite::types::FromSql for State {
    fn column_result(
        value: rusqlite::types::ValueRef<'_>,
    ) -> rusqlite::types::FromSqlResult<Self> {
        match value.as_str()? {
            "open" => Ok(State::Open),
            "closed" => Ok(State::Closed),
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

pub fn issue_create(
    tx: &Token,
    repo: RepositoryId,
    creator: UserId,
    title: &str,
    body: Option<&str>,
) -> IssueId {
    let number: usize = tx.query_row(
        "UPDATE repositories SET issue_seq = issue_seq + 1 WHERE id = ? RETURNING issue_seq",
        [*repo],
        |row| row.get(0)
    ).unwrap();
    tx.query_row(
        "
        INSERT INTO issues (repository, number, user, state, title, body)
        VALUES (?, ?, ?, 'open', ?, ?)
        RETURNING id
    ",
        (*repo, number, *creator, title, body),
        |row| row.get("id").map(IssueId),
    )
    .unwrap()
}

pub fn find_issue_id(
    tx: &Token,
    owner: &str,
    repo: &str,
    number: usize,
) -> Option<IssueId> {
    tx.query_row(
        "
        select i.id
        from issues i
        left join repositories r on (r.id = i.repository)
        left join users u on (u.id = r.owner)
        where u.login = ? AND r.name = ? AND i.number = ?
    ",
        (owner, repo, number),
        |row| row.get("id").map(IssueId),
    )
    .optional()
    .unwrap()
}

pub fn get_issue(tx: &Token, id: IssueId) -> Issue {
    tx.query_row(
        "
    SELECT number, state, title, body, repository, user
    FROM issues WHERE id = ?
    ",
        [*id],
        |row| {
            let user = row
                .get::<_, Option<i64>>("user")?
                .map(|id| super::users::get_by_id(tx, UserId(id)));
            let repository =
                super::repos::by_id(tx, RepositoryId(row.get("repository")?));

            Ok(Issue {
                id,
                number: row.get("number")?,
                title: row.get("title")?,
                body: row.get("body")?,
                state: row.get("state")?,
                repository,
                user,
            })
        },
    )
    .unwrap()
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct LabelId(i64);
impl std::ops::Deref for LabelId {
    type Target = i64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub struct Label {
    pub id: LabelId,
    pub name: String,
    pub description: Option<String>,
    pub color: String, // TODO: should probably be a [u8;3]
}
pub fn get_labels<T, F>(tx: &Token, id: IssueId, f: F) -> Vec<T>
where
    F: Fn(Label) -> T,
{
    tx.prepare(
        "
        SELECT l.id, l.name, l.description, l.color
        FROM labels l
        JOIN issue_labels il ON (il.label = l.id)
        WHERE il.issue = ?
    ",
    )
    .unwrap()
    .query_map([*id], |row| {
        Ok(f(Label {
            id: row.get("id").map(LabelId)?,
            name: row.get("name")?,
            description: row.get("description")?,
            color: row.get("color")?,
        }))
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

pub fn ensure_label_exists(tx: &Token, name: &str) -> LabelId {
    // TODO: single query? apparently can't UNION
    // fixme: label color
    tx.query_row(
        "
        INSERT INTO labels (name, color) VALUES (?, '#ffffff')
        ON CONFLICT DO NOTHING
        RETURNING id
    ",
        [name],
        |row| row.get("id").map(LabelId),
    )
    .optional()
    .and_then(|id| {
        id.map_or_else(
            || {
                tx.query_row(
                    "SELECT id FROM labels WHERE name = ?",
                    [name],
                    |r| r.get("id").map(LabelId),
                )
            },
            Ok,
        )
    })
    .unwrap()
}

pub fn add_label(tx: &Token, issue: IssueId, label: LabelId) {
    tx.execute(
        "INSERT INTO issue_labels (issue, label) VALUES (?, ?)",
        (*issue, *label),
    )
    .unwrap();
}

pub fn remove_label(tx: &Token, issue: IssueId, label: LabelId) {
    tx.execute(
        "DELETE FROM issue_labels WHERE issue = ? AND label = ?",
        (*issue, *label),
    )
    .unwrap();
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct CommentId(i64);
impl std::ops::Deref for CommentId {
    type Target = i64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
pub struct Comment {
    pub id: CommentId,
    pub body: String,
    pub issue: IssueId,
    pub author: Option<UserId>,

    pub created_at: String,
    pub updated_at: String,
}

pub fn get_comment_by_i64(
    tx: &Token,
    repo: RepositoryId,
    comment: i64,
) -> Option<Comment> {
    // fixme: repo
    tx.query_row(
        "SELECT id FROM issue_comments WHERE id = ?",
        [comment],
        |row| row.get("id").map(CommentId),
    )
    .optional()
    .unwrap()
    .map(|cid| get_comment(tx, cid))
}

pub fn get_comment(tx: &Token, comment: CommentId) -> Comment {
    tx.query_row(
        "
        SELECT issue, user, body, created_at, updated_at
        FROM issue_comments
        WHERE id = ?
    ",
        [*comment],
        |row| {
            Ok(Comment {
                id: comment,
                body: row.get("body")?,
                issue: row.get("issue").map(IssueId)?,
                author: row.get::<_, Option<_>>("user")?.map(UserId),
                created_at: row.get("created_at")?,
                updated_at: row.get("updated_at")?,
            })
        },
    )
    .unwrap()
}

pub fn get_comments<T, F>(tx: &Token, issue: IssueId, f: F) -> Vec<T>
where
    F: Fn(Comment) -> T,
{
    // TODO: ordering?
    tx.prepare(
        "
        SELECT id, body, user, created_at, updated_at
        FROM issue_comments
        WHERE issue = ?
        ORDER BY id
    ",
    )
    .unwrap()
    .query_map([*issue], |row| {
        Ok(f(Comment {
            id: row.get("id").map(CommentId)?,
            body: row.get("body")?,
            issue,
            author: row.get::<_, Option<_>>("user")?.map(UserId),
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        }))
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

pub fn create_comment(
    tx: &Token,
    author: UserId,
    issue: IssueId,
    body: &str,
) -> CommentId {
    tx.query_row(
        "
        INSERT INTO issue_comments (issue, user, body)
        VALUES (?, ?, ?)
        RETURNING id
    ",
        (*issue, *author, body),
        |row| row.get("id").map(CommentId),
    )
    .unwrap()
}

pub fn update_comment(tx: &Token, comment: CommentId, body: &str) {
    tx.execute(
        "UPDATE issue_comments SET body = ?, updated_at = datetime() WHERE id = ?",
        (body, *comment),
    ).unwrap();
}

pub fn delete_comment(tx: &Token, comment: CommentId) {
    tx.execute("DELETE FROM issue_comments WHERE id = ?", [*comment])
        .unwrap();
}

pub fn create_pr(
    tx: &Token,
    issue: IssueId,
    head: ObjectId,
    base: &str,
    source: &Repository,
    source_branch: &str,
    draft: bool,
) -> PullRequestId {
    // FIXME: do we actually need the HEAD? can't we retrieve it via the branch / ref?
    let head_id: i64 = tx
        .query_row(
            "
        SELECT o.id
        FROM objects o
        LEFT JOIN network n ON (n.id = o.network)
        LEFT JOIN repositories r ON (r.network = n.id)
        WHERE r.id = ? AND o.sha = ?
    ",
            (*source.id, head.as_bytes()),
            |row| row.get("id"),
        )
        .unwrap();

    tx.query_row("
        INSERT INTO pull_requests (issue, head, base, repository, branch, label, owner, draft)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING issue
    ", (
        *issue,
        head_id,
        base,
        *source.id,
        source_branch,
        format!("{}:{}", source.owner.login, source_branch),
        *source.owner.id,
        draft
    ), |row| row.get(0).map(PullRequestId))
        .unwrap()
}

pub fn find_by_id(tx: &Token, id: i64) -> Option<PullRequest> {
    tx.query_row(
        "select issue from pull_requests where issue = ?",
        [id],
        |row| row.get(0).map(PullRequestId).map(|id| get_pr(tx, id)),
    )
    .optional()
    .unwrap()
}

pub fn find_id(
    tx: &Token,
    owner: &str,
    repo: &str,
    number: usize,
) -> Option<PullRequestId> {
    tx.query_row(
        "
        select p.issue
        from pull_requests p
        left join issues i on (i.id = p.issue)
        left join repositories r on (r.id = i.repository)
        left join users u on (u.id = r.owner)
        where u.login = ? AND r.name = ? AND i.number = ?
    ",
        (owner, repo, number),
        |row| row.get(0).map(PullRequestId),
    )
    .optional()
    .unwrap()
}

pub fn find_pr(
    tx: &Token,
    owner: &str,
    repo: &str,
    number: usize,
) -> Option<PullRequest> {
    // todo: efficient version?
    find_id(tx, owner, repo, number).map(|pid| get_pr(tx, pid))
}

pub fn get_pr(tx: &Token, id: PullRequestId) -> PullRequest {
    // can't be arsed to do 15 joins in the same query (repo, repo parent,
    // repo source, the 3 owners, then PR source, *its* parent and source, and
    // their owners, and the PR / issue creator) (well except as of this the
    // ancestors are just linked as ids so no join there), so just sequentially
    // fetch a bunch of crap
    tx.query_row(
        "
        SELECT
            i.id, i.number, i.state, i.title, i.body,
            o.sha as head, p.label, p.base, p.draft, p.branch, p.dead,

            i.repository as target, p.repository as source, i.user

        FROM pull_requests p
        LEFT JOIN issues i ON (i.id = p.issue)
        LEFT JOIN objects o ON (o.id = p.head)
        WHERE p.issue = ?
    ",
        [*id],
        |row| {
            let creator = row
                .get::<_, Option<i64>>("user")?
                .map(|id| super::users::get_by_id(tx, UserId(id)));
            let repository =
                super::repos::by_id(tx, RepositoryId(row.get("target")?));
            let source = row
                .get::<_, Option<i64>>("source")?
                .map(|id| super::repos::by_id(tx, RepositoryId(id)));

            Ok(PullRequest {
                id,
                head: oid::from_bytes_unchecked(
                    row.get_ref("head")?.as_bytes()?,
                )
                .to_owned(),
                draft: row.get("draft")?,
                base: row.get("base")?,
                label: row.get("label")?,
                issue: Issue {
                    id: id.into(),
                    number: row.get("number")?,
                    title: row.get("title")?,
                    body: row.get("body")?,
                    state: row.get("state")?,
                    repository,
                    user: creator,
                },
                source,
                source_branch: row.get("branch")?,
                dead: row.get("dead")?,
            })
        },
    )
    .unwrap()
}

// FIXME: maybe objects should have views based on ACL?
pub fn can_write(
    tx: &Token,
    user: super::users::UserId,
    pr: PullRequestId,
) -> bool {
    // a user can write on a PR if they're the creator of the PR, or they have
    // write access to the repository
    tx.query_row(
        "
        SELECT EXISTS(
          SELECT 1
            FROM issues i
       LEFT JOIN repositories r ON (r.id = i.repository)
       LEFT JOIN collaborators c ON (c.repository = r.id AND c.user = ?1)
           WHERE i.id = ?2
             AND (i.user = ?1 OR c.role >= 3)
       )
    ",
        [user.0, pr.0],
        |row| row.get(0),
    )
    .unwrap()
}

/// Returns whether the PR was updated
pub fn set_draft(tx: &Token, pr: PullRequestId, draft: bool) -> bool {
    0 != tx
        .execute(
            "
        UPDATE pull_requests AS p SET draft = ?2
        FROM issues i
       WHERE i.id = ?1
         AND p.draft != ?2
         AND i.id = p.issue
    ",
            (*pr, draft),
        )
        .unwrap()
}

pub fn update(
    tx: &Token,
    pr: PullRequestId,
    title: Option<&str>,
    body: Option<Option<&str>>,
    state: Option<State>,
) {
    tx.execute(
        "
UPDATE issues
SET title = coalesce(?, title),
    body = iif(?, ?, body),
    state = coalesce(?, state)
FROM pull_requests p
WHERE p.issue = ? AND id = p.issue
    ",
        (
            title,
            body.is_some(),
            body.unwrap_or(None),
            state.map(|s| s.as_str()),
            *pr,
        ),
    )
    .unwrap();
}

pub fn set_base(tx: &Token, pr: PullRequestId, base: &str) {
    tx.execute(
        "UPDATE pull_requests SET base = ? WHERE issue = ?",
        (base, *pr),
    )
    .unwrap();
}

pub mod reviews {
    use rusqlite::{
        types::{FromSqlError, ToSqlOutput, ValueRef},
        OptionalExtension,
    };

    use crate::model::Token;

    #[derive(Copy, Clone)]
    pub struct ReviewId(i64);
    impl std::ops::Deref for ReviewId {
        type Target = i64;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    #[derive(Copy, Clone, PartialEq, Eq)]
    pub enum State {
        Pending,
        Approved,
        ChangesRequested,
        Commented,
    }
    impl rusqlite::types::FromSql for State {
        fn column_result(
            value: rusqlite::types::ValueRef<'_>,
        ) -> rusqlite::types::FromSqlResult<Self> {
            match value.as_str()? {
                "pending" => Ok(State::Pending),
                "approve" => Ok(State::Approved),
                "request_changes" => Ok(State::ChangesRequested),
                "comment" => Ok(State::Commented),
                _ => Err(FromSqlError::InvalidType),
            }
        }
    }
    impl rusqlite::types::ToSql for State {
        fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
            match self {
                State::Pending => Ok("pending".into()),
                State::Approved => Ok("approve".into()),
                State::ChangesRequested => Ok("request_changes".into()),
                State::Commented => Ok("comment".into()),
            }
        }
    }

    pub struct Review {
        pub id: ReviewId,
        pub state: State,
        pub author: crate::model::users::UserId,
        pub body: String,
        pub commit_id: super::ObjectDbId,
        pub submitted_at: String,
        pub pull_request: super::PullRequestId,
    }

    pub fn create_review(
        tx: &Token,
        pr: super::PullRequestId,
        body: &str,
        state: State,
        commit: Option<super::ObjectDbId>,
        author: crate::model::users::UserId,
    ) -> ReviewId {
        tx.query_row("
            INSERT INTO reviews (pull_request, body, state, commit_id, author) \
            VALUES (?, ?, ?, coalesce(?, (select head from pull_requests where issue = ?)), ?)\
            RETURNING id
        ", (*pr, body, state, commit.map(|c| *c), *pr, *author),
        |row| row.get(0).map(ReviewId)
        ).unwrap()
    }

    pub fn get_by_i64(tx: &Token, id: i64) -> Option<Review> {
        tx.query_row("
            SELECT id, state, author, body, commit_id, submitted_at, pull_request
            FROM reviews
            WHERE id = ?
        ", [id], |row| Ok(Review {
            id: row.get("id").map(ReviewId)?,
            state: row.get("state")?,
            author: row.get("author").map(crate::model::users::UserId)?,
            body: row.get("body")?,
            commit_id: row.get("commit_id").map(super::ObjectDbId)?,
            submitted_at: row.get("submitted_at")?,
            pull_request: row.get("pull_request").map(super::PullRequestId)?,
        })).optional().unwrap()
    }

    pub fn get_review(tx: &Token, id: ReviewId) -> Review {
        tx.query_row(
            "
            SELECT state, author, body, commit_id, submitted_at, pull_request
            FROM reviews
            WHERE id = ?
        ",
            [*id],
            |row| {
                Ok(Review {
                    id,
                    state: row.get("state")?,
                    author: row
                        .get("author")
                        .map(crate::model::users::UserId)?,
                    body: row.get("body")?,
                    commit_id: row.get("commit_id").map(super::ObjectDbId)?,
                    submitted_at: row.get("submitted_at")?,
                    pull_request: row
                        .get("pull_request")
                        .map(super::PullRequestId)?,
                })
            },
        )
        .unwrap()
    }

    pub fn list<T, F>(tx: &Token, id: super::PullRequestId, f: F) -> Vec<T>
    where
        F: Fn(Review) -> T,
    {
        tx.prepare("
            SELECT id, state, author, body, commit_id, submitted_at, pull_request
            FROM reviews WHERE pull_request = ?"
        ).unwrap()
        .query_map([*id], |row| Ok(f(Review {
            id: row.get("id").map(ReviewId)?,
            state: row.get("state")?,
            author: row.get("author").map(crate::model::users::UserId)?,
            body: row.get("body")?,
            commit_id: row.get("commit_id").map(super::ObjectDbId)?,
            submitted_at: row.get("submitted_at")?,
            pull_request: row.get("pull_request").map(super::PullRequestId)?,
        }))).unwrap()
        .map(Result::unwrap)
        .collect()
    }

    #[derive(Copy, Clone)]
    pub struct ReviewCommentId(i64);
    impl std::ops::Deref for ReviewCommentId {
        type Target = i64;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    pub struct ReviewComment {
        pub id: ReviewCommentId,
        pub body: String,

        pub pull_request: super::PullRequestId,
        pub review: Option<ReviewId>,
        pub in_reply_to: Option<ReviewCommentId>,

        pub created_at: String,
        pub updated_at: String,
    }

    fn row_to_comment(row: &rusqlite::Row) -> rusqlite::Result<ReviewComment> {
        Ok(ReviewComment {
            id: row.get("id").map(ReviewCommentId)?,
            body: row.get("body")?,

            pull_request: row.get("pull_request").map(super::PullRequestId)?,
            review: row.get::<_, Option<_>>("review")?.map(ReviewId),
            in_reply_to: row
                .get::<_, Option<_>>("in_reply_to")?
                .map(ReviewCommentId),

            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
        })
    }

    pub fn comment_by_i64(
        tx: &Token,
        repo_id: crate::model::repos::RepositoryId,
        comment_id: i64,
    ) -> Option<ReviewCommentId> {
        tx.query_row(
            "SELECT id FROM review_comments WHERE id = ?",
            [comment_id],
            |row| row.get(0).map(ReviewCommentId),
        )
        .optional()
        .unwrap()
    }

    pub fn get_comment(
        tx: &Token,
        comment_id: ReviewCommentId,
    ) -> ReviewComment {
        tx.query_row(
            "
            SELECT id, body, created_at, updated_at,
                pull_request, review, in_reply_to
            FROM review_comments
            WHERE id = ?
        ",
            [*comment_id],
            row_to_comment,
        )
        .unwrap()
    }

    // TODO: same methods for pr comments and review comments?
    pub fn list_comments<T, F>(tx: &Token, review_id: ReviewId, f: F) -> Vec<T>
    where
        F: Fn(ReviewComment) -> T,
    {
        tx.prepare(
            "
            SELECT id, body, created_at, updated_at,
                   pull_request, review, in_reply_to
              FROM review_comments
             WHERE review = ?
             ORDER BY id
        ",
        )
        .unwrap()
        .query_map([*review_id], |row| row_to_comment(row).map(&f))
        .unwrap()
        .map(Result::unwrap)
        .collect()
    }

    pub fn list_pr_comments<T, F>(
        tx: &Token,
        pr_id: super::PullRequestId,
        f: F,
    ) -> Vec<T>
    where
        F: Fn(ReviewComment) -> T,
    {
        tx.prepare(
            "
            SELECT id, body, created_at, updated_at,
                   pull_request, review, in_reply_to
              FROM review_comments
             WHERE pull_request = ?
             ORDER BY id
        ",
        )
        .unwrap()
        .query_map([*pr_id], |row| row_to_comment(row).map(&f))
        .unwrap()
        .map(Result::unwrap)
        .collect()
    }

    pub fn add_review_comments(
        tx: &Token,
        id: ReviewId,
        comments: impl Iterator<Item = String>,
    ) {
        let mut ins = tx
            .prepare(
                "INSERT INTO \
                 review_comments (pull_request, review, body, position, path) \
                 VALUES (
                    (SELECT pull_request FROM reviews WHERE id = ?1),
                    ?1,
                    ?2,
                    1,
                    ''
                )",
            )
            .unwrap();

        for c in comments {
            ins.execute((*id, c)).unwrap();
        }
    }

    pub fn add_pr_comments(
        tx: &Token,
        id: super::PullRequestId,
        comments: impl Iterator<Item = String>,
    ) -> Vec<ReviewCommentId> {
        let mut ins = tx
            .prepare(
                "
                INSERT INTO review_comments
                    (pull_request, body, position, path)
                    VALUES (?, ?, 1, '')
                RETURNING id
            ",
            )
            .unwrap();

        comments
            .into_iter()
            .map(|c| {
                ins.query_row((*id, c), |row| row.get(0).map(ReviewCommentId))
                    .unwrap()
            })
            .collect()
    }

    pub fn update_comment(tx: &Token, id: ReviewCommentId, body: &str) {
        tx.execute(
            "
            UPDATE review_comments
            SET body = ?, updated_at = datetime()
            WHERE id = ?
        ",
            (body, *id),
        )
        .unwrap();
    }

    pub fn delete_comment(tx: &Token, comment_id: ReviewCommentId) -> bool {
        tx.execute("DELETE FROM review_comments WHERE id = ?", [*comment_id])
            .unwrap()
            != 0
    }
}
