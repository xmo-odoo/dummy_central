use std::collections::BTreeSet;

use github_types::repos::{
    CreateRepositoryRuleset, CreateStatusResponse, HookContentType, HookEvent,
    RulesetEnforcement, RulesetRule, RulesetRuleUpdate, RulesetTarget,
};
use itertools::Itertools;
use rusqlite::{
    ErrorCode::ConstraintViolation,
    OptionalExtension as _, Row,
    types::{FromSql, FromSqlError},
};

use super::{Token, Write, users::UserId};

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
pub fn by_id<M>(tx: &Token<M>, id: RepositoryId) -> Repository {
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

pub fn by_name<M>(
    tx: &Token<M>,
    owner: &str,
    name: &str,
) -> Option<Repository> {
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

pub fn id_by_name<M>(
    tx: &Token<M>,
    owner: &str,
    name: &str,
) -> Option<RepositoryId> {
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

pub fn delete(tx: &Token<Write>, id: RepositoryId) {
    // FIXME: adjust repos whose parent is id?
    tx.execute("DELETE FROM repositories WHERE id = ?", [*id])
        .unwrap();
}

pub fn create_repository(
    tx: &Token<Write>,
    creator: super::users::UserId,
    owner: super::users::UserId,
    name: &str,
    parent: Option<(RepositoryId, bool)>,
) -> Option<Repository> {
    let network = if let Some((parent, _)) = parent {
        by_id(tx, parent).network
    } else {
        tx.query_row(
            "INSERT INTO network DEFAULT VALUES RETURNING id",
            [],
            |row| row.get("id").map(Network),
        )
        .unwrap()
    };
    // the default branch name is set from the owner of the source,
    // not the creator of the fork (or the source repo)
    let repo_id = tx
        .query_row(
            "
        INSERT INTO repositories (owner, name, default_branch, parent, network)
        VALUES (?1, ?2, (SELECT default_branch FROM users WHERE id = ?1), ?3, ?4)
        RETURNING id
    ",
            (*owner, name, parent.map(|(id, _)| *id), *network),
            |row| row.get(0).map(RepositoryId),
        )
        .ok()?;
    // the creator of a repo is an admin
    tx.execute(
        "INSERT INTO collaborators (repository, user, role) VALUES (?, ?, 5)",
        (*repo_id, *creator),
    )
    .unwrap();

    // if forking, heads (branches proper) get copied
    if let Some((parent, default_branch_only)) = parent {
        if default_branch_only {
            // unlike above, the default branch being copied is the source repo's default branch
            tx.execute(
                "
                INSERT INTO refs (repository, name, object)
                SELECT ?, refs.name, refs.object
                FROM refs JOIN repositories ON (refs.repository = repositories.id)
                WHERE refs.repository = ? AND refs.name = 'refs/heads/' || repositories.default_branch
                ",
                (*repo_id, *parent),
            )
        } else {
            tx.execute(
                "
                INSERT INTO refs (repository, name, object)
                SELECT ?, name, object
                FROM refs
                WHERE repository = ? AND name LIKE 'refs/heads/%'
            ",
                (*repo_id, *parent),
            )
        }
        .unwrap();
    }

    Some(by_id(tx, repo_id))
}

pub fn update_repository(
    tx: &Token<Write>,
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

pub fn find_fork<M>(
    tx: &Token<M>,
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
    pub events: BTreeSet<HookEvent>, // actually a set of events
    pub insecure_ssl: bool,
    pub secret: String,
    pub last_response_code: Option<u16>,
    pub last_response_status: Option<String>,
    pub last_response_message: Option<String>,
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
                .filter_map(|s| s.parse().ok())
                .collect(),
            last_response_code: row.get("last_response_code")?,
            last_response_status: row.get("last_response_status")?,
            last_response_message: row.get("last_response_message")?,
        })
    }
}

pub fn list_hooks<M>(tx: &Token<M>, repo: RepositoryId) -> Vec<Hook> {
    tx.prepare(
        "
        SELECT id, active, content_type, url, events, insecure_ssl, secret,
            last_response_code, last_response_status, last_response_message
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

pub fn get_hook<M>(tx: &Token<M>, id: i64) -> Hook {
    tx.query_row(
        "
        SELECT id, active, content_type, url, events, insecure_ssl, secret,
            last_response_code, last_response_status, last_response_message
        FROM repository_webhooks
        WHERE id = ?
    ",
        [id],
        |row| row.try_into(),
    )
    .unwrap()
}

pub fn create_hook(
    tx: &Token<Write>,
    repo: RepositoryId,
    crate::github::HookConfig {
        active,
        events,
        content_type,
        secret,
        url,
        insecure_ssl,
        ..
    }: &crate::github::HookConfig,
) -> Option<Hook> {
    tx.query_row(
        "
        INSERT INTO repository_webhooks
            (repository, active, events, content_type, secret, url, insecure_ssl, last_response_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'unused')
        RETURNING id, active, content_type, url, events, insecure_ssl, secret,
            last_response_code, last_response_status, last_response_message
    ",
        (
            *repo,
            active,
            events.iter().map(HookEvent::as_str).join(" "),
            content_type.as_str(),
            &secret,
            &url,
            insecure_ssl,
        ),
        |row| row.try_into(),
    )
    .inspect_err(|e| if e.sqlite_error_code() != Some(ConstraintViolation) {
        panic!("{e}");
    })
    .ok()
}

pub fn update_hook(
    tx: &Token<Write>,
    owner: &str,
    name: &str,
    hook: i64,
    active: Option<bool>,
    secret: Option<&str>,
    events: Option<BTreeSet<HookEvent>>,
) -> bool {
    1 == tx
        .execute(
            "
        UPDATE repository_webhooks as w
        SET active = coalesce(?, active),
            secret = coalesce(?, secret),
            events = coalesce(?, events)
        FROM repositories r, users u
        WHERE w.id = ?
          AND w.repository = r.id
          AND r.owner = u.id
          AND u.login = ?
          AND r.name = ?
    ",
            (
                active,
                secret,
                events.map(|h| h.iter().map(HookEvent::as_str).join(" ")),
                hook,
                owner,
                name,
            ),
        )
        .unwrap()
}

pub fn hook_set_last_response(tx: &Token<Write>, hook: i64, code: u16) {
    tx.execute(
        "
        UPDATE repository_webhooks as w
        SET last_response_code = ?,
            last_response_status = ?,
            last_response_message = ?
        WHERE w.id = ?
        ",
        (
            code,
            Option::<&str>::None,
            if code % 100 != 2 {
                Some(format!("Invalid HTTP Response: {code}"))
            } else {
                None
            },
            hook,
        ),
    )
    .unwrap();
}

pub fn delete_hook(
    tx: &Token<Write>,
    owner: &str,
    name: &str,
    hook: i64,
) -> bool {
    1 == tx
        .execute(
            "
        DELETE FROM repository_webhooks
        WHERE id = ?
          AND repository in (
              SELECT r.id
              FROM repositories r
              JOIN users u ON r.owner = u.id
              WHERE u.login = ? AND r.name = ?
          )
    ",
            (hook, owner, name),
        )
        .unwrap()
}

impl<M> Token<M> {
    pub fn get_statuses(
        &self,
        network: Network,
        oid: &gix_hash::oid,
    ) -> Vec<CreateStatusResponse> {
        self.prepare(
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
                state: row.get_ref("state")?.as_str()?.try_into().expect(
                    "status state should be constrained in the database",
                ),
                target_url: row.get("target_url")?,
                description: row.get("description")?,
                creator: None,
            })
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
    }
}

pub enum Role {
    Read,
    Triage,
    Write,
    Maintain,
    Administrate,
}
pub fn get_collaborators<M>(
    tx: &Token<M>,
    repo: RepositoryId,
) -> Vec<(UserId, Role)> {
    tx.prepare(
        "
        SELECT user, role
        FROM collaborators c
        WHERE repository = ?
    ",
    )
    .unwrap()
    .query_map([*repo], |row| {
        Ok((
            UserId(row.get(0)?),
            match row.get(1)? {
                1 => Role::Read,
                2 => Role::Triage,
                3 => Role::Write,
                4 => Role::Maintain,
                5 => Role::Administrate,
                n => {
                    return Err(rusqlite::Error::IntegralValueOutOfRange(1, n));
                }
            },
        ))
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

pub fn add_collaborator(
    tx: &Token<Write>,
    repo: RepositoryId,
    login: String,
) -> bool {
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

pub fn remove_collaborator(
    tx: &Token<Write>,
    repo: RepositoryId,
    login: &str,
) -> bool {
    1 == tx
        .execute(
            "
        DELETE FROM collaborators
        WHERE repository = ? AND user = (SELECT id FROM users WHERE login = ?)
    ",
            (*repo, login),
        )
        .unwrap()
}

#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
pub struct RulesetId(pub(in crate::model) i64);
impl std::ops::Deref for RulesetId {
    type Target = i64;
    fn deref(&self) -> &i64 {
        &self.0
    }
}

pub fn create_ruleset(
    tx: &Token<Write>,
    repo: RepositoryId,
    ruleset: CreateRepositoryRuleset,
) -> Result<RulesetId, rusqlite::Error> {
    tx.query_row(
        "
        INSERT INTO rulesets (repository, name, enforcement, target)
        VALUES (?, ?, ?, ?)
        RETURNING id
    ",
        (
            *repo,
            &ruleset.name,
            match ruleset.enforcement {
                RulesetEnforcement::Active => "active",
                RulesetEnforcement::Disabled => "disabled",
            },
            match ruleset.target {
                RulesetTarget::Branch => "branch",
                // RulesetTarget::Tag => "tag",
                // RulesetTarget::Push => "push",
            }
        ),
        |row| {
            let id: i64 = row.get(0)?;
            let mut stmt = tx.prepare(
                "INSERT INTO ruleset_conditions (ruleset, include, condition) VALUES (?, ?, ?)",
            )?;
            for cond in ruleset.conditions.ref_name.include {
                stmt.execute((id, 1, cond))?;
            }
            for cond in ruleset.conditions.ref_name.exclude {
                stmt.execute((id, 0, cond))?;
            }
            let mut stmt = tx.prepare(
                "INSERT INTO ruleset_rules (ruleset, type, parameters) VALUES (?, ?, ?)",
            )?;
            for rule in ruleset.rules {
                match rule {
                    RulesetRule::Creation =>
                        stmt.execute((id, "creation", None::<&str>))?,
                    RulesetRule::Update(RulesetRuleUpdate { update_allows_fetch_and_merge: true }) =>
                        stmt.execute((id, "update", Some(r#"{"update_allows_fetch_and_merge": true}"#)))?,
                    RulesetRule::Update(RulesetRuleUpdate { update_allows_fetch_and_merge: false }) =>
                        stmt.execute((id, "update", Some(r#"{"update_allows_fetch_and_merge": false}"#)))?,
                };
            }
            Ok(RulesetId(id))
        },
    )
}

#[derive(Clone)]
pub struct Ruleset {
    pub id: RulesetId,
    pub created_at: String,
    pub updated_at: String,

    pub repository_id: RepositoryId,

    pub name: String,
    pub enforcement: RulesetEnforcement,
    pub target: RulesetTarget,
}

impl<'stmt> TryFrom<&Row<'stmt>> for Ruleset {
    type Error = rusqlite::Error;

    fn try_from(row: &Row<'stmt>) -> Result<Self, Self::Error> {
        Ok(Ruleset {
            id: RulesetId(row.get("id")?),
            created_at: row.get("created_at")?,
            updated_at: row.get("updated_at")?,
            repository_id: RepositoryId(row.get("repository")?),
            name: row.get("name")?,
            enforcement: match row.get::<_, String>("enforcement")?.as_str() {
                "active" => RulesetEnforcement::Active,
                "disabled" => RulesetEnforcement::Disabled,
                v => {
                    return Err(rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        format!("Invalid enforcement value: {v}").into(),
                    ));
                }
            },
            target: match row.get::<_, String>("target")?.as_str() {
                "branch" => RulesetTarget::Branch,
                // "tag" => RulesetTarget::Tag,
                // "push" => RulesetTarget::Push,
                v => {
                    return Err(rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        format!("Invalid target value: {v}").into(),
                    ));
                }
            },
        })
    }
}

pub fn read_rulesets<T>(tx: &Token<T>, repo: RepositoryId) -> Vec<Ruleset> {
    tx.prepare(
        "
        SELECT id, created_at, updated_at, repository, name, enforcement, target
        FROM rulesets
        WHERE repository = ?
    ",
    )
    .unwrap()
    .query_map([*repo], |row| row.try_into())
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

pub fn read_ruleset<T>(tx: &Token<T>, id: RulesetId) -> Ruleset {
    tx.query_row(
        "
        SELECT id, created_at, updated_at, repository, name, enforcement, target
        FROM rulesets
        WHERE id = ?
    ",
        [*id],
        |row| row.try_into(),
    )
    .unwrap()
}

pub fn read_ruleset_conditions<T>(
    tx: &Token<T>,
    id: RulesetId,
) -> (Vec<String>, Vec<String>) {
    let mut stmt = tx
        .prepare(
            "
        SELECT include, condition
        FROM ruleset_conditions
        WHERE ruleset = ?
    ",
        )
        .unwrap();
    let mut includes = Vec::new();
    let mut excludes = Vec::new();
    for r in stmt.query_map([*id], |row| row.try_into()).unwrap() {
        let (include, condition) = r.unwrap();
        if include {
            includes.push(condition);
        } else {
            excludes.push(condition);
        }
    }
    (includes, excludes)
}

pub fn read_ruleset_rules<T>(tx: &Token<T>, id: RulesetId) -> Vec<RulesetRule> {
    let mut stmt = tx
        .prepare(
            "
        SELECT type, parameters
        FROM ruleset_rules
        WHERE ruleset = ?
    ",
        )
        .unwrap();
    stmt.query_map([*id], |row| {
        match row.get_ref_unwrap("type").as_str().unwrap() {
            "creation" => Ok(RulesetRule::Creation),
            "update" => {
                let parameters =
                    row.get_ref_unwrap("parameters").as_str().unwrap();
                let parameters =
                    serde_json::from_str::<RulesetRuleUpdate>(parameters)
                        .unwrap();
                Ok(RulesetRule::Update(parameters))
            }
            r => Err(rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                format!("Invalid rule type: {r}").into(),
            )),
        }
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

pub fn delete_ruleset(
    tx: &Token<Write>,
    repo_id: RepositoryId,
    ruleset_id: i64,
) -> bool {
    tx.query_one(
        "
        DELETE FROM rulesets
        WHERE id = ? AND repository = ?
        RETURNING id
    ",
        [ruleset_id, *repo_id],
        |r| r.get::<_, i64>("id"),
    )
    .optional()
    .unwrap()
    .is_some()
}

pub fn rulesets_for_branch<T>(
    tx: &Token<T>,
    repo: &Repository,
    branch: &str,
) -> impl Iterator<Item = Ruleset> {
    assert!(!branch.starts_with("refs/"));
    assert!(!branch.starts_with("heads/"));
    let default_ref = format!("refs/heads/{}", repo.default_branch);
    let ref_ = format!("refs/heads/{branch}");
    read_rulesets(tx, repo.id)
        .into_iter()
        .filter(|ruleset| {
            matches!(ruleset.enforcement, RulesetEnforcement::Active)
        })
        .filter(|ruleset| matches!(ruleset.target, RulesetTarget::Branch))
        .filter(move |ruleset| {
            let (includes, excludes) = read_ruleset_conditions(tx, ruleset.id);

            patterns_to_globset(
                includes.iter().map(|s| s.as_str()),
                &default_ref,
            )
            .is_match(&ref_)
                && !patterns_to_globset(
                    excludes.iter().map(|s| s.as_str()),
                    &default_ref,
                )
                .is_match(&ref_)
        })
}

fn patterns_to_globset<'a>(
    mut patterns: impl Iterator<Item = &'a str>,
    default_ref: &str,
) -> globset::GlobSet {
    match patterns.try_fold(
        globset::GlobSetBuilder::new(),
        |mut builder, pattern| {
            let pattern = match pattern {
                "~ALL" => {
                    return std::ops::ControlFlow::Break(
                        globset::GlobSetBuilder::new()
                            .add(globset::Glob::new("*").unwrap())
                            .build()
                            .unwrap(),
                    );
                }
                "~DEFAULT_BRANCH" => default_ref,
                p => p,
            };
            builder.add(
                globset::GlobBuilder::new(pattern)
                    .backslash_escape(false)
                    .build()
                    .unwrap(),
            );
            std::ops::ControlFlow::Continue(builder)
        },
    ) {
        std::ops::ControlFlow::Break(builder) => builder,
        std::ops::ControlFlow::Continue(builder) => builder.build().unwrap(),
    }
}

#[cfg(test)]
mod tests {
    use super::patterns_to_globset;

    #[test]
    fn test_basic() {
        let patterns = vec!["refs/heads/main"];
        let globset =
            patterns_to_globset(patterns.into_iter(), "refs/heads/main");
        assert!(globset.is_match("refs/heads/main"));
        assert!(!globset.is_match("refs/heads/bugfix"));
    }
    #[test]
    fn test_default_branch() {
        let patterns = vec!["~DEFAULT_BRANCH"];
        let globset =
            patterns_to_globset(patterns.into_iter(), "refs/heads/main");
        assert!(globset.is_match("refs/heads/main"));
        assert!(!globset.is_match("refs/heads/feature"));
    }
    #[test]
    fn test_all() {
        let patterns = vec!["~ALL"];
        let globset =
            patterns_to_globset(patterns.into_iter(), "refs/heads/main");
        assert!(globset.is_match("refs/heads/main"));
        assert!(globset.is_match("refs/heads/feature"));
        assert!(globset.is_match("refs/tags/v1.0"));
    }
    #[test]
    fn test_glob() {
        let patterns = vec!["refs/heads/feature/*"];
        let globset =
            patterns_to_globset(patterns.into_iter(), "refs/heads/main");
        assert!(globset.is_match("refs/heads/feature/awesome-feature"));
        assert!(!globset.is_match("refs/heads/main"));

        // these are invalid patterns but I want to test what globset does
        let patterns = vec!["*feature"];
        let globset =
            patterns_to_globset(patterns.into_iter(), "refs/heads/main");
        assert!(globset.is_match("refs/heads/feature/awesome-feature"));
        assert!(!globset.is_match("refs/heads/main"));
        assert!(globset.is_match("refs/heads/bugfix/feature"));
    }
}
