use std::{marker::PhantomData, ops::Deref, sync::LazyLock};

use github_types::repos::StatusState;

pub mod git;
pub mod prs;
pub mod repos;
pub mod users;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

type Pool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>;
static POOL: LazyLock<(Pool, Pool)> = LazyLock::new(|| {
    let path = tempfile::NamedTempFile::new()
        .expect("tmp should be writeable by the current user")
        .into_temp_path()
        .keep()
        .expect("persisting the database file should succeed");

    init_db(&path).expect("initializing the database should succeed");

    let manager =
        r2d2_sqlite::SqliteConnectionManager::file(&path).with_init(|c| {
            c.execute_batch(
                "
            -- otherwise FKs are not checked, and it's not a sticky setting
            PRAGMA foreign_keys=1;
            -- we don't need our databases to be resilient to crashes
            PRAGMA synchronous=off;
            -- probably doesn't matter since we've locked this at the pool level
            PRAGMA busy_timeout = 0;
        ",
            )
        });

    let write_pool = r2d2::Builder::new()
        .max_size(1)
        .connection_timeout(std::time::Duration::from_secs(5))
        .build(manager)
        .expect("creating the write pool should succeed");

    let read_pool = r2d2::Pool::new(
        r2d2_sqlite::SqliteConnectionManager::file(path)
            .with_flags(rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .with_init(|c| c.execute_batch("PRAGMA synchronous=off;")),
    )
    .expect("creating the read pool should succeed");

    (write_pool, read_pool)
});

fn init_db(path: &std::path::Path) -> Result<()> {
    let cn = rusqlite::Connection::open(path)?;
    cn.execute_batch("PRAGMA journal_mode=wal; ")?;
    cn.execute_batch(include_str!("./model.sql"))?;
    Ok(())
}

type Connection = r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>;
// TODO: make tokens opaque?
pub struct Read;
pub struct Write;

pub struct Token<M>(Connection, PhantomData<M>);
impl<M> Deref for Token<M> {
    type Target = rusqlite::Connection;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
// FIXME: `Token::<Op>::get` is not an amazing interface...
impl Token<Write> {
    pub async fn get()
    -> std::result::Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let c = tokio::task::spawn_blocking(|| POOL.0.get()).await??;
        c.execute_batch("BEGIN IMMEDIATE")
            .expect("the connection should be valid");
        Ok(Token(c, PhantomData))
    }
    pub fn commit(self) {
        self.execute_batch("COMMIT")
            .expect("commit should always succeed since there's only one writer possible");
    }
}
impl Token<Read> {
    pub async fn get()
    -> std::result::Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        tokio::task::spawn_blocking(|| POOL.1.get())
            .await?
            .map(|c| Token(c, PhantomData))
            .map_err(|e| e.into())
    }
}
/// Unconditionally tries to rollback the transaction on drop.
///
/// This is a bit sucky as it's going to fail on Read tokens and committed tx...
///
/// To avoid these we'd need to split read and write into different types,
/// and then `ManuallyDrop` the write token during `commit`.
impl<M> Drop for Token<M> {
    fn drop(&mut self) {
        let _ = self.0.execute_batch("ROLLBACK");
    }
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for Token<Read> {
    type Rejection = String;

    async fn from_request_parts(
        _: &mut axum::http::request::Parts,
        _: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        Self::get().await.map_err(|e| e.to_string())
    }
}

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for Token<Write> {
    type Rejection = String;

    async fn from_request_parts(
        _: &mut axum::http::request::Parts,
        _: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        Self::get().await.map_err(|e| e.to_string())
    }
}

#[derive(Copy, Clone)]
pub struct StatusId(i64);
impl Deref for StatusId {
    type Target = i64;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
pub fn create_status(
    tx: &Token<Write>,
    commit: git::ObjectDbId,
    state: StatusState,
    context: &str,
    target_url: Option<&str>,
    description: Option<&str>,
) -> StatusId {
    tx.query_row(
        "INSERT OR REPLACE INTO statuses (object, state, context, target_url, description)
         VALUES (?, ?, ?, ?, ?)
         RETURNING id",
        (*commit, <&str>::from(state), context, target_url, description),
        |row| row.get(0).map(StatusId),
    )
    .expect("insertion failed")
}
