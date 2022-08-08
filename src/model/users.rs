use rusqlite::{
    types::{FromSql, FromSqlError, FromSqlResult, ValueRef},
    OptionalExtension as _,
};
use std::borrow::Cow;

use super::{Result, Source, Token};

pub fn load(
    users: impl Iterator<
        Item = (String, Option<String>, &'static str, Vec<String>, String),
    >,
) -> Result {
    let mut db = Source::get();
    let tx = db.token();
    let mut insert_user =
        tx.prepare("INSERT INTO users (login, name, type) VALUES (?, ?, ?)")?;
    let mut insert_email = tx.prepare(
        r#"
            INSERT INTO emails (user, email, "primary", visibility) 
            VALUES (?, ?, true, 'public')
        "#,
    )?;
    let mut insert_token =
        tx.prepare("INSERT INTO tokens (user, token) VALUES (?, ?)")?;

    for (login, name, typ, tokens, email) in users {
        let user_id = insert_user.insert((login, name, typ))?;
        for token in tokens {
            insert_token.insert((user_id, token))?;
        }
        if !email.is_empty() {
            insert_email.insert((user_id, email))?;
        }
    }
    drop(insert_token);
    drop(insert_email);
    drop(insert_user);
    tx.commit()?;
    Ok(())
}

#[derive(Copy, Clone, Debug)]
pub enum Type {
    User,
    Organization,
}
impl FromSql for Type {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        Ok(match value.as_str()? {
            "user" => Type::User,
            "organization" => Type::Organization,
            // should probably invalid value instead
            _ => return Err(FromSqlError::InvalidType),
        })
    }
}

// FIXME: how to make sure we create UserId only from fks to users?
#[derive(Copy, Clone, Debug)]
pub struct UserId(pub i64);
impl std::ops::Deref for UserId {
    type Target = i64;
    fn deref(&self) -> &i64 {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct User<'a> {
    pub id: UserId,
    pub login: Cow<'a, str>,
    pub r#type: Type,
    /// name may not be set
    pub name: Option<Cow<'a, str>>,
    /// "primary" email, iff public?
    pub email: Option<Cow<'a, str>>,
}
impl TryFrom<&'_ rusqlite::Row<'_>> for User<'static> {
    type Error = rusqlite::Error;
    fn try_from(row: &'_ rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: UserId(row.get("id")?),
            login: row.get::<_, String>("login")?.into(),
            name: row.get::<_, Option<String>>("name")?.map(Into::into),
            r#type: row.get("type")?,
            email: row.get::<_, Option<String>>("email")?.map(Into::into),
        })
    }
}

pub fn get_user(tx: &Token, login: &str) -> Option<User<'static>> {
    tx.query_row(
        "SELECT id, login, type, name, email
        FROM users
        LEFT JOIN emails
           ON (emails.user = users.id AND \"primary\" AND visibility = 'public')
        where login = ?
        ",
        [login],
        |row| row.try_into(),
    )
    .optional()
    .unwrap()
}

/// Gets a User by their Id. Because UserId should only be obtainable from a
/// real record with verified FKs, this can not fail (well except for the bit
/// where we can get a UserId *then* remove the account, but we don't talk
/// about that).
pub fn get_by_id(tx: &Token, id: UserId) -> User<'static> {
    tx.query_row(
        "SELECT id, login, type, name, email
        FROM users
        LEFT JOIN emails
           ON (emails.user = users.id AND \"primary\" AND visibility = 'public')
        where id = ?
        ",
        [id.0],
        |row| row.try_into(),
    )
    .unwrap()
}

/// Gets a User by their Id. Because i64 are arbitrary and may come from outside
/// of the known world, the corresponding user may not exist.
pub fn get_by_i64(tx: &Token, id: i64) -> Option<User<'static>> {
    tx.query_row(
        "SELECT id, login, type, name, email
        FROM users
        LEFT JOIN emails
           ON (emails.user = users.id AND \"primary\" AND visibility = 'public')
        where id = ?
        ",
        [id],
        |row| row.try_into(),
    )
    .optional()
    .unwrap()
}

/// Finds the "current user" by auth token
pub fn find_current_user(tx: &Token, token: &str) -> Option<User<'static>> {
    tx.query_row(
        "SELECT users.id, login, type, name, email
        FROM users
        JOIN tokens ON (users.id = tokens.user)
        LEFT JOIN emails
           ON (emails.user = users.id AND \"primary\" AND visibility = 'public')
        WHERE tokens.token = ?
        ",
        [token],
        |row| row.try_into(),
    )
    .optional()
    .unwrap()
}

pub enum Visibility {
    Private,
    Public,
}
impl FromSql for Visibility {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        Ok(match value.as_str()? {
            "public" => Visibility::Public,
            "private" => Visibility::Private,
            // should probably invalid value instead
            _ => return Err(FromSqlError::InvalidType),
        })
    }
}
pub struct Email<'a> {
    pub email: Cow<'a, str>,
    pub verified: bool,
    pub primary: bool,
    pub visibility: Visibility,
}
pub fn list_user_emails(tx: &Token, id: &UserId) -> Vec<Email<'static>> {
    tx.prepare(
        r#"SELECT email, "primary", visibility FROM emails WHERE user = ?"#,
    )
    .unwrap()
    .query_map([id.0], |row| {
        Ok(Email {
            email: row.get::<_, String>("email").map(Into::into)?,
            verified: true,
            primary: row.get("primary")?,
            visibility: row.get("visibility")?,
        })
    })
    .unwrap()
    .map(|e| e.unwrap())
    .collect()
}
