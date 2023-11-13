use github_types::repos::StatusState;
use once_cell::sync::Lazy;
use rusqlite::{OpenFlags as of, Transaction};
use std::{
    ops::{Deref, DerefMut},
    sync::atomic::{AtomicUsize, Ordering},
};

pub mod git;
pub mod prs;
pub mod repos;
pub mod users;

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

type Pool = r2d2::Pool<r2d2_sqlite::SqliteConnectionManager>;
static POOL: Lazy<Pool> = Lazy::new(|| {
    let path = tempfile::NamedTempFile::new()
        .unwrap()
        .into_temp_path()
        .keep()
        .unwrap();

    let manager = r2d2_sqlite::SqliteConnectionManager::file(path)
        // otherwise FKs are not checked, and it's not a sticky setting
        .with_init(|c| c.execute_batch("PRAGMA foreign_keys=1;"));

    let pool = r2d2::Pool::new(manager).unwrap();

    let pooled_connection = pool.get().unwrap();
    pooled_connection
        .execute_batch("PRAGMA journal_mode=wal;")
        .unwrap();
    pooled_connection
        .execute_batch(include_str!("./model.sql"))
        .expect("Failed to initialise core db");

    pool
});

pub type Token<'cn> = Transaction<'cn>;
pub struct Source(r2d2::PooledConnection<r2d2_sqlite::SqliteConnectionManager>);
impl Source {
    pub fn get() -> Self {
        // there's a weird situation where *creating* a connection requires an
        // exclusive lock but apparently doesn't wait for it (?), so with a high
        // enough level of concurrency we get "database is locked" errors.
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap();
        Self(POOL.get().unwrap())
    }
    pub fn token(&mut self) -> Token<'_> {
        self.0.transaction().expect("Connection to not be broken")
    }
    pub fn token_eager(&mut self) -> Token<'_> {
        self.0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Exclusive)
            .expect("Connection to not be broken")
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
    tx: &Token,
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
