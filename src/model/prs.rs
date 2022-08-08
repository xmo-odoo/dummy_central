use bon::builder;
use gix_hash::{ObjectId, oid};
use rusqlite::{OptionalExtension as _, types::FromSqlError};

use super::{
    Token, Write,
    git::ObjectDbId,
    repos::{Repository, RepositoryId},
    users::UserId,
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
    pub head: gix_hash::ObjectId,
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
    tx: &Token<Write>,
    repo: RepositoryId,
    creator: UserId,
    title: &str,
    body: Option<&str>,
) -> IssueId {
    // NOTE: despite RETURNING sqlite does not support anything other than
    // SELECT in CTE, so this has to be two queries
    let number: usize = tx
        .query_row(
            "
        UPDATE repositories
        SET issue_seq = issue_seq + 1
        WHERE id = ?
        RETURNING issue_seq
        ",
            [*repo],
            |row| row.get(0),
        )
        .expect("sql execution to succeed");
    tx.query_row(
        "
        INSERT INTO issues (repository, number, user, state, title, body)
        VALUES (?, ?, ?, 'open', ?, ?)
        RETURNING id
    ",
        (*repo, number, *creator, title, body),
        |row| row.get("id").map(IssueId),
    )
    .expect("sql execution to succeed")
}

pub fn find_issue_id<M>(
    tx: &Token<M>,
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
    .expect("sql execution to succeed")
}

pub fn get_issue<M>(tx: &Token<M>, id: IssueId) -> Issue {
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
    .expect("sql execution to succeed")
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
pub fn get_labels<T, F, M>(tx: &Token<M>, id: IssueId, f: F) -> Vec<T>
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
    .expect("statement preparation")
    .query_map([*id], |row| {
        Ok(f(Label {
            id: row.get("id").map(LabelId)?,
            name: row.get("name")?,
            description: row.get("description")?,
            color: row.get("color")?,
        }))
    })
    .expect("sql execution to succeed")
    .map(Result::unwrap)
    .collect()
}

pub fn ensure_label_exists(tx: &Token<Write>, name: &str) -> LabelId {
    // TODO: single query? apparently can't UNION
    tx.query_row(
        "
        INSERT INTO labels (name, color) VALUES (?, 'ededed')
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
    .expect("sql execution to succeed")
}

pub fn add_label(tx: &Token<Write>, issue: IssueId, label: LabelId) {
    tx.execute(
        "INSERT INTO issue_labels (issue, label) VALUES (?, ?)",
        (*issue, *label),
    )
    .expect("sql execution to succeed");
}

pub fn remove_label(tx: &Token<Write>, issue: IssueId, label: LabelId) {
    tx.execute(
        "DELETE FROM issue_labels WHERE issue = ? AND label = ?",
        (*issue, *label),
    )
    .expect("sql execution to succeed");
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

pub fn get_comment_by_i64<M>(
    tx: &Token<M>,
    repo: RepositoryId,
    comment: i64,
) -> Option<Comment> {
    tx.query_row(
        "
        SELECT c.id
        FROM issue_comments c
        JOIN issues i ON (c.issue = i.id)
        JOIN repositories r ON (i.repository = r.id)
        WHERE c.id = ? AND r.id = ?
        ",
        [comment, *repo],
        |row| row.get("id").map(CommentId),
    )
    .optional()
    .expect("sql execution to succeed")
    .map(|cid| get_comment(tx, cid))
}

pub fn get_comment<M>(tx: &Token<M>, comment: CommentId) -> Comment {
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
    .expect("sql execution to succeed")
}

pub fn get_comments<T, F, M>(tx: &Token<M>, issue: IssueId, f: F) -> Vec<T>
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
    .expect("sql preparation to succeed")
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
    .expect("sql execution to succeed")
    .map(Result::unwrap)
    .collect()
}

pub fn create_comment(
    tx: &Token<Write>,
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
    .expect("sql execution to succeed")
}

pub fn update_comment(tx: &Token<Write>, comment: CommentId, body: &str) {
    tx.execute(
        "UPDATE issue_comments SET body = ?, updated_at = datetime() WHERE id = ?",
        (body, *comment),
    ).expect("sql execution to succeed");
}

pub fn delete_comment(tx: &Token<Write>, comment: CommentId) {
    tx.execute("DELETE FROM issue_comments WHERE id = ?", [*comment])
        .expect("sql execution to succeed");
}

pub fn create_pr(
    tx: &Token<Write>,
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
        .expect("sql execution to succeed");

    let pr_id = tx.query_row("
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
    .expect("sql execution to succeed");

    let issue = get_issue(tx, issue);
    if let Some(body) = issue.body {
        let mut st = tx
            .prepare("INSERT INTO closing_references (pr, issue) VALUES (?, ?)")
            .expect("the query to be valid");
        for referenced in ReferenceFinder::new(
            tx,
            &issue.repository.owner.login,
            &issue.repository.name,
        )
        .find_issues(body.as_bytes())
        {
            st.execute([*pr_id, *referenced])
                .expect("the insertion to work");
        }
    }

    pr_id
}

pub fn from_issue<M>(tx: &Token<M>, id: IssueId) -> Option<PullRequest> {
    tx.query_row(
        "select issue from pull_requests where issue = ?",
        [*id],
        |row| row.get(0).map(PullRequestId).map(|id| get_pr(tx, id)),
    )
    .optional()
    .expect("sql execution to succeed")
}

pub fn find_by_id<M>(tx: &Token<M>, id: i64) -> Option<PullRequest> {
    from_issue(tx, IssueId(id))
}

pub fn find_by_head<M>(tx: &Token<M>, head: &oid) -> Option<PullRequestId> {
    tx.query_row(
        "
            select issue
            from pull_requests p
            left join objects o on (p.head = o.id)
            where o.sha = ?
        ",
        [head.as_bytes()],
        |row| row.get(0).map(PullRequestId),
    )
    .optional()
    .expect("sql execution to succeed")
}

pub enum Repo<'a> {
    Id(RepositoryId),
    Name(&'a str, &'a str),
}
impl From<RepositoryId> for Repo<'static> {
    fn from(id: RepositoryId) -> Self {
        Self::Id(id)
    }
}
impl<'a> From<(&'a str, &'a str)> for Repo<'a> {
    fn from((owner, name): (&'a str, &'a str)) -> Self {
        Self::Name(owner, name)
    }
}
impl<'a> From<(&'a String, &'a String)> for Repo<'a> {
    fn from((owner, name): (&'a String, &'a String)) -> Self {
        Self::Name(owner.as_str(), name.as_str())
    }
}

pub fn find_by_number<'r, M, R>(
    tx: &Token<M>,
    repository: R,
    number: usize,
) -> Option<PullRequestId>
where
    R: Into<Repo<'r>>,
{
    match repository.into() {
        Repo::Id(repo_id) => tx.query_row(
            "
                select p.issue
                from pull_requests p
                left join issues i on (i.id = p.issue)
                where i.repository = ? AND i.number = ?
            ",
            (*repo_id, number),
            |row| row.get(0).map(PullRequestId),
        ),
        Repo::Name(owner, name) => tx.query_row(
            "
                select p.issue
                from pull_requests p
                left join issues i on (i.id = p.issue)
                left join repositories r on (r.id = i.repository)
                left join users u on (u.id = r.owner)
                where u.login = ? AND r.name = ? AND i.number = ?
            ",
            (owner, name, number),
            |row| row.get(0).map(PullRequestId),
        ),
    }
    .optional()
    .expect("sql execution to succeed")
}

pub fn find_pr<M>(
    tx: &Token<M>,
    owner: &str,
    repo: &str,
    number: usize,
) -> Option<PullRequest> {
    // TODO: efficient version?
    find_by_number(tx, (owner, repo), number).map(|pid| get_pr(tx, pid))
}

pub fn get_pr<M>(tx: &Token<M>, id: PullRequestId) -> PullRequest {
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
    .expect("sql execution to succeed")
}

// FIXME: maybe objects should have views based on ACL?
pub fn can_write(
    tx: &Token<Write>,
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
    .expect("sql execution to succeed")
}

/// Returns whether the PR was updated
pub fn set_draft(tx: &Token<Write>, pr: PullRequestId, draft: bool) -> bool {
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
        .expect("sql execution to succeed")
}

#[builder]
pub fn update<T: Into<IssueId>>(
    #[builder(start_fn)] token: &Token<Write>,
    #[builder(start_fn)] issue: T,
    title: Option<&str>,
    body: Option<Option<&str>>,
    state: Option<State>,
) {
    let issue_id = issue.into();
    token
        .execute(
            "
UPDATE issues
SET title = coalesce(?, title),
    body = iif(?, ?, body),
    state = coalesce(?, state)
WHERE id = ?
    ",
            (
                title,
                body.is_some(),
                body.unwrap_or(None),
                state.map(|s| s.as_str()),
                *issue_id,
            ),
        )
        .expect("sql execution to succeed");
    let Some(Some(body)) = body else {
        return;
    };

    token.query_row(
        "
        SELECT u.login as owner, r.name as name
        FROM pull_requests p
        LEFT JOIN issues i ON (i.id = p.issue)
        LEFT JOIN repositories r ON (r.id = i.repository)
        LEFT JOIN users u ON (u.id = r.owner)
        WHERE p.issue = ?
        ",
        [*issue_id],
        |row | {
            token.execute("DELETE FROM closing_references WHERE pr = ?", [*issue_id])?;
            // prefer upsert to INSERT OR IGNORE as it *only* skips unique violations not arbitrary constraint failures
            let mut st = token.prepare("INSERT INTO closing_references (pr, issue) VALUES (?, ?) ON CONFLICT DO NOTHING")?;
            for referenced in ReferenceFinder::new(
                token,
                row.get_ref("owner")?.as_str()?,
                row.get_ref("name")?.as_str()?
            ).find_issues(body.as_bytes()) {
                st.execute([*issue_id, *referenced])?;
            }
            Ok(())
        }
    ).optional() // if the issue is not a PR
    .expect("sql execution to succeed");
}

pub fn referenced<M>(token: &Token<M>, by: PullRequestId) -> Vec<IssueId> {
    token
        .prepare("SELECT issue FROM closing_references WHERE pr = ?")
        .expect("query to be valid")
        .query_map([*by], |row| row.get(0).map(IssueId))
        .expect("sql execution to succeed")
        .map(|r| r.expect("nothing to go wrong"))
        .collect()
}

pub struct ReferenceFinder<'a, M> {
    tx: &'a Token<M>,
    re: regex::bytes::Regex,
    owner: &'a str,
    name: &'a str,
}
impl<'a, M> ReferenceFinder<'a, M> {
    pub fn new(
        tx: &'a Token<M>,
        owner: &'a str,
        name: &'a str,
    ) -> ReferenceFinder<'a, M> {
        let re = regex::bytes::RegexBuilder::new(
            r"
            (?: close[sd]?
            | fix | fixes | fixed
            | resolve[sd]?
            )
            \s+
            \#
            ([0-9]+)
        ",
        )
        .ignore_whitespace(true)
        .case_insensitive(true)
        .build()
        .expect("the regex to be correct");
        Self {
            tx,
            re,
            owner,
            name,
        }
    }

    pub fn find_issues<'x>(
        &'x self,
        message: &'x [u8],
    ) -> impl Iterator<Item = IssueId> + use<'a, 'x, M> {
        self.re.captures_iter(message).filter_map(|c| {
            std::str::from_utf8(&c[1])
                .ok()
                .and_then(|s| s.parse().ok())
                .and_then(|n| find_issue_id(self.tx, self.owner, self.name, n))
        })
    }
}

pub fn set_base(tx: &Token<Write>, pr: PullRequestId, base: &str) {
    tx.execute(
        "UPDATE pull_requests SET base = ? WHERE issue = ?",
        (base, *pr),
    )
    .expect("sql execution to succeed");
}

pub mod reviews {
    use rusqlite::{
        OptionalExtension,
        types::{FromSqlError, ToSqlOutput},
    };

    use crate::model::{Token, Write};

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
        tx: &Token<Write>,
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
        ).expect("sql execution to succeed")
    }

    pub fn get_by_i64<M>(tx: &Token<M>, id: i64) -> Option<Review> {
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
        })).optional().expect("sql execution to succeed")
    }

    pub fn get_review<M>(tx: &Token<M>, id: ReviewId) -> Review {
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
        .expect("sql execution to succeed")
    }

    pub fn list<T, F, M>(
        tx: &Token<M>,
        id: super::PullRequestId,
        f: F,
    ) -> Vec<T>
    where
        F: Fn(Review) -> T,
    {
        tx.prepare("
            SELECT id, state, author, body, commit_id, submitted_at, pull_request
            FROM reviews WHERE pull_request = ?"
        ).expect("sql query preparation to succeed")
        .query_map([*id], |row| Ok(f(Review {
            id: row.get("id").map(ReviewId)?,
            state: row.get("state")?,
            author: row.get("author").map(crate::model::users::UserId)?,
            body: row.get("body")?,
            commit_id: row.get("commit_id").map(super::ObjectDbId)?,
            submitted_at: row.get("submitted_at")?,
            pull_request: row.get("pull_request").map(super::PullRequestId)?,
        }))).expect("sql execution to succeed")
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

    pub fn comment_by_i64<M>(
        tx: &Token<M>,
        _repo_id: crate::model::repos::RepositoryId,
        comment_id: i64,
    ) -> Option<ReviewCommentId> {
        tx.query_row(
            "SELECT id FROM review_comments WHERE id = ?",
            [comment_id],
            |row| row.get(0).map(ReviewCommentId),
        )
        .optional()
        .expect("sql execution to succeed")
    }

    pub fn get_comment<M>(
        tx: &Token<M>,
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
        .expect("sql execution to succeed")
    }

    // TODO: same methods for pr comments and review comments?
    pub fn list_comments<T, F, M>(
        tx: &Token<M>,
        review_id: ReviewId,
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
             WHERE review = ?
             ORDER BY id
        ",
        )
        .expect("sql query preparation to succeed")
        .query_map([*review_id], |row| row_to_comment(row).map(&f))
        .expect("sql execution to succeed")
        .map(Result::unwrap)
        .collect()
    }

    pub fn list_pr_comments<T, F, M>(
        tx: &Token<M>,
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
        .expect("sql query preparation to succeed")
        .query_map([*pr_id], |row| row_to_comment(row).map(&f))
        .expect("sql execution to succeed")
        .map(Result::unwrap)
        .collect()
    }

    pub fn add_review_comments(
        tx: &Token<Write>,
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
            .expect("sql query preparation to succeed");

        for c in comments {
            ins.execute((*id, c)).expect("sql execution to succeed");
        }
    }

    pub fn add_pr_comments(
        tx: &Token<Write>,
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
            .expect("sql query preparation to succeed");

        comments
            .into_iter()
            .map(|c| {
                ins.query_row((*id, c), |row| row.get(0).map(ReviewCommentId))
                    .expect("sql execution to succeed")
            })
            .collect()
    }

    pub fn update_comment(tx: &Token<Write>, id: ReviewCommentId, body: &str) {
        tx.execute(
            "
            UPDATE review_comments
            SET body = ?, updated_at = datetime()
            WHERE id = ?
        ",
            (body, *id),
        )
        .expect("sql execution to succeed");
    }

    pub fn delete_comment(
        tx: &Token<Write>,
        comment_id: ReviewCommentId,
    ) -> bool {
        tx.execute("DELETE FROM review_comments WHERE id = ?", [*comment_id])
            .expect("sql execution to succeed")
            != 0
    }
}
