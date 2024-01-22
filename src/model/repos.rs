use github_types::repos::{CreateStatusResponse, HookContentType};
use rusqlite::{
    types::{FromSql, FromSqlError},
    OptionalExtension as _, Row,
};

use super::{users::UserId, Token};

#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
pub struct RepositoryId(pub(in crate::model) i64);
impl std::ops::Deref for RepositoryId {
    type Target = i64;
    fn deref(&self) -> &i64 {
        &self.0
    }
}
#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
pub struct Network(i64);
impl std::ops::Deref for Network {
    type Target = i64;
    fn deref(&self) -> &i64 {
        &self.0
    }
}

#[derive(Clone)]
pub struct Repository {
    pub id: RepositoryId,
    pub owner: super::users::User<'static>,
    pub name: String,
    pub parent: Option<RepositoryId>,
    pub source: Option<RepositoryId>,
    pub default_branch: String,
    pub network: Network,
}
impl Repository {
    pub fn id_i64(&self) -> RepositoryId {
        self.id
    }
}
pub fn by_id(tx: &Token, id: RepositoryId) -> Repository {
    tx.query_row(
        "
        SELECT id, name, default_branch, parent, owner, network
        FROM repositories
        WHERE id = ?
    ",
        [*id],
        |row| {
            let parent = row.get::<_, Option<i64>>("parent")?.map(RepositoryId);
            Ok(Repository {
                id: RepositoryId(row.get("id")?),
                name: row.get("name")?,
                default_branch: row.get("default_branch")?,
                parent,
                source: std::iter::successors(parent, |id| {
                    by_id(tx, *id).parent
                })
                .last(),
                owner: super::users::get_by_id(
                    tx,
                    row.get("owner").map(super::users::UserId)?,
                ),
                network: row.get("network").map(Network)?,
            })
        },
    )
    .unwrap()
}

pub fn by_name(tx: &Token, owner: &str, name: &str) -> Option<Repository> {
    tx.query_row(
        "
        SELECT r.id, r.name, r.default_branch, r.parent, r.owner, r.network
        FROM repositories r, users
        WHERE users.id = r.owner
          AND users.login = ?
          AND r.name = ?
    ",
        (owner, name),
        |row| {
            let parent = row.get::<_, Option<i64>>("parent")?.map(RepositoryId);
            Ok(Repository {
                id: RepositoryId(row.get("id")?),
                name: row.get("name")?,
                default_branch: row.get("default_branch")?,
                parent,
                source: std::iter::successors(parent, |id| {
                    by_id(tx, *id).parent
                })
                .last(),
                owner: super::users::get_by_id(
                    tx,
                    row.get("owner").map(super::users::UserId)?,
                ),
                network: row.get("network").map(Network)?,
            })
        },
    )
    .optional()
    .unwrap()
}

pub fn id_by_name(tx: &Token, owner: &str, name: &str) -> Option<RepositoryId> {
    tx.query_row(
        "
        SELECT repositories.id
        FROM repositories, users
        WHERE users.id = repositories.owner
          AND users.login = ?
          AND repositories.name = ?
    ",
        (owner, name),
        |row| row.get("id").map(RepositoryId),
    )
    .optional()
    .unwrap()
}

pub fn delete(tx: &Token, id: RepositoryId) {
    // FIXME: adjust repos whose parent is id?
    tx.execute("DELETE FROM repositories WHERE id = ?", [*id])
        .unwrap();
}

pub fn create_repository(
    tx: &Token,
    creator: super::users::UserId,
    owner: super::users::UserId,
    name: &str,
    parent: Option<RepositoryId>,
) -> Option<Repository> {
    let network = if let Some(parent) = parent {
        by_id(tx, parent).network
    } else {
        tx.query_row(
            "INSERT INTO network DEFAULT VALUES RETURNING id",
            [],
            |row| row.get("id").map(Network),
        )
        .unwrap()
    };
    // the default branch is copied from the owner, not the creator
    let repo_id = tx
        .query_row(
            "
        INSERT INTO repositories (owner, name, default_branch, parent, network)
        VALUES (?1, ?2, (SELECT default_branch FROM users WHERE id = ?1), ?3, ?4)
        RETURNING id
    ",
            (*owner, name, parent.map(|id| *id), *network),
            |row| row.get(0).map(RepositoryId),
        )
        .ok()?;
    // the creator of a repo is an admin
    tx.execute(
        "INSERT INTO collaborators (repository, user, role) VALUES (?, ?, 5)",
        (*repo_id, *creator),
    )
    .unwrap();

    // if forking, all the heads (branches proper) get copied
    if let Some(parent) = parent {
        tx.execute(
            "
            INSERT INTO refs (repository, name, object)
            SELECT ?, name, object
            FROM refs
            WHERE repository = ?
            AND name LIKE 'refs/heads/%'
        ",
            (*repo_id, *parent),
        )
        .unwrap();
    }

    Some(by_id(tx, repo_id))
}

pub fn update_repository(
    tx: &Token,
    repo: RepositoryId,
    name: Option<&str>,
    default_branch: Option<&str>,
) {
    tx.execute(
        "
    UPDATE repositories
        SET name = coalesce(?1, name),
            default_branch = coalesce(?2, default_branch)
    WHERE id = ?3
    ",
        (name, default_branch, *repo),
    )
    .unwrap();
}

pub fn find_fork(
    tx: &Token,
    repo: RepositoryId,
    for_owner: UserId,
) -> Option<RepositoryId> {
    // TODO: does this make sense if repo already belongs to owner?
    // FIXME: find repo with same network!
    tx.query_row(
        "
        WITH RECURSIVE sources (id, source) AS (
            SELECT id, id FROM repositories WHERE parent IS NULL
        UNION
            SELECT r.id, s.source
            FROM repositories r
            JOIN sources s ON (s.id = r.parent)
        )
        SELECT own.id
        FROM repositories own, repositories other
        JOIN sources own_source ON (own_source.id = own.id)
        JOIN sources other_source ON (other_source.id = other.id)
        WHERE own.owner = ?
          AND other.id = ?
          AND own_source.source = other_source.source
    ",
        (*for_owner, *repo),
        |row| row.get("id").map(RepositoryId),
    )
    .optional()
    .unwrap()
}

pub struct ContentType(pub HookContentType);
impl From<ContentType> for HookContentType {
    fn from(c: ContentType) -> HookContentType {
        c.0
    }
}
impl FromSql for ContentType {
    fn column_result(
        value: rusqlite::types::ValueRef<'_>,
    ) -> rusqlite::types::FromSqlResult<Self> {
        match value.as_str()? {
            "json" => Ok(ContentType(HookContentType::Json)),
            "form" => Ok(ContentType(HookContentType::Form)),
            _ => Err(FromSqlError::InvalidType),
        }
    }
}
pub struct Hook {
    pub id: i64,
    pub active: bool,
    pub content_type: ContentType,
    pub url: String,
    pub events: Vec<String>, // actually a set of events
    pub insecure_ssl: bool,
    pub secret: Option<String>,
}
impl TryFrom<&Row<'_>> for Hook {
    type Error = rusqlite::Error;

    fn try_from(row: &Row<'_>) -> Result<Self, Self::Error> {
        Ok(Hook {
            id: row.get("id")?,
            active: row.get("active")?,
            content_type: row.get("content_type")?,
            url: row.get("url")?,
            insecure_ssl: row.get("insecure_ssl")?,
            secret: row.get("secret")?,
            events: row
                .get_ref("events")?
                .as_str()?
                .split(' ')
                .map(String::from)
                .collect(),
        })
    }
}

pub fn list_hooks(tx: &Token, repo: RepositoryId) -> Vec<Hook> {
    tx.prepare(
        "
        SELECT id, active, content_type, url, events, insecure_ssl, secret
        FROM repository_webhooks
        WHERE repository = ?
    ",
    )
    .unwrap()
    .query_map([*repo], |row| row.try_into())
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

pub fn get_hook(tx: &Token, id: i64) -> Hook {
    tx.query_row(
        "
        SELECT id, active, content_type, url, events, insecure_ssl, secret
        FROM repository_webhooks
        WHERE id = ?
    ",
        [id],
        |row| row.try_into(),
    )
    .unwrap()
}

pub fn create_hook(
    tx: &Token,
    repo: RepositoryId,
    crate::github::HookConfig {
        active,
        events,
        content_type,
        secret,
        url,
        ..
    }: &crate::github::HookConfig,
) -> Hook {
    tx.query_row(
        "
        INSERT INTO repository_webhooks
            (repository, active, events, content_type, secret, url)
        VALUES (?, ?, ?, ?, ?, ?)
        RETURNING id, active, content_type, url, events, insecure_ssl, secret
    ",
        (
            *repo,
            active,
            events.iter().fold(String::new(), |s, e| {
                if s.is_empty() {
                    e.as_str().into()
                } else {
                    s + " " + e.as_str()
                }
            }),
            content_type.as_str(),
            &secret,
            &url,
        ),
        |row| row.try_into(),
    )
    .unwrap()
}

pub fn update_hook(
    tx: &Token,
    hook: i64,
    active: Option<bool>,
    secret: Option<&str>,
) -> bool {
    1 == tx
        .execute(
            "
        UPDATE repository_webhooks
        SET active = coalesce(?, active),
            secret = coalesce(?, secret)
        WHERE id = ?
    ",
            (active, secret, hook),
        )
        .unwrap()
}

pub fn delete_hook(tx: &Token, hook: i64) -> bool {
    1 == tx
        .execute(
            "
        DELETE FROM repository_webhooks
        WHERE id = ?
    ",
            [hook],
        )
        .unwrap()
}

pub fn get_statuses(
    tx: &Token,
    network: Network,
    oid: &gix_hash::oid,
) -> Vec<CreateStatusResponse> {
    tx.prepare(
        "
        SELECT s.id, s.context, s.state, s.target_url, s.description
        FROM statuses s
        LEFT JOIN objects ON (objects.id = object)
        WHERE network = ? AND sha = ?
    ",
    )
    .unwrap()
    .query_map((*network, oid.as_bytes()), |row| {
        Ok(CreateStatusResponse {
            id: row.get("id")?,
            context: row.get("context")?,
            state: row
                .get_ref("state")?
                .as_str()?
                .try_into()
                .expect("status state should be constrained in the database"),
            target_url: row.get("target_url")?,
            description: row.get("description")?,
            creator: None,
        })
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

pub fn get_collaborators(tx: &Token, repo: RepositoryId) -> Vec<String> {
    tx.prepare(
        "
        SELECT login
        FROM collaborators c
        LEFT JOIN users u ON (c.user = u.id)
        WHERE repository = ?
    ",
    )
    .unwrap()
    .query_map([*repo], |row| row.get(0))
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

pub fn add_collaborator(tx: &Token, repo: RepositoryId, login: String) -> bool {
    1 == tx
        .execute(
            "
        INSERT INTO collaborators (repository, user, role)
        SELECT ?, id, 3 FROM users WHERE login = ?
        -- could DO NOTHING but then would need different way to return that the
        -- user does not exist
        ON CONFLICT DO UPDATE SET role = 3
    ",
            (*repo, &login),
        )
        .unwrap()
}
