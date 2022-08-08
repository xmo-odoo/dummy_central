use std::borrow::Cow;

use rusqlite::{
    OptionalExtension as _,
    types::{FromSql, FromSqlError, FromSqlResult, ValueRef},
};

use super::{Result, Token, Write};

pub async fn load(
    users: impl Iterator<
        Item = (String, Option<String>, &'static str, Vec<String>, String),
    >,
) -> Result {
    let tx = Token::<Write>::get().await.unwrap();
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
    tx.commit();
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
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
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

pub fn get_user<M>(tx: &Token<M>, login: &str) -> Option<User<'static>> {
    tx.query_row(
        "SELECT id, login, type, name, email
        FROM users
        LEFT JOIN emails
           ON (user = users.id AND \"primary\" AND visibility = 'public')
        WHERE login = ?
        ",
        [login],
        |row| row.try_into(),
    )
    .optional()
    .unwrap()
}

pub fn get_user_from_email<M>(
    tx: &Token<M>,
    email: &str,
) -> Option<User<'static>> {
    tx.query_row(
        "SELECT id, login, type, name, p.email
        FROM users
        LEFT JOIN emails e ON e.user = users.id
        LEFT JOIN emails p
            ON (p.user = users.id AND p.\"primary\" AND p.visibility = 'public')
        WHERE e.email = ?
        ",
        [email],
        |row| row.try_into(),
    )
    .optional()
    .unwrap()
}

/// Gets a User by their Id. Because UserId should only be obtainable from a
/// real record with verified FKs, this can not fail (well except for the bit
/// where we can get a UserId *then* remove the account, but we don't talk
/// about that).
pub fn get_by_id<M>(tx: &Token<M>, id: UserId) -> User<'static> {
    tx.query_row(
        "SELECT id, login, type, name, email
        FROM users
        LEFT JOIN emails
           ON (user = users.id AND \"primary\" AND visibility = 'public')
        WHERE id = ?
        ",
        [id.0],
        |row| row.try_into(),
    )
    .unwrap()
}

/// Gets a User by their Id. Because i64 are arbitrary and may come from outside
/// of the known world, the corresponding user may not exist.
pub fn get_by_i64<M>(tx: &Token<M>, id: i64) -> Option<User<'static>> {
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
pub fn find_current_user<M>(
    tx: &Token<M>,
    token: &str,
) -> Option<User<'static>> {
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
pub fn list_user_emails<M>(tx: &Token<M>, id: UserId) -> Vec<Email<'static>> {
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
