use crate::model::{Token, Write, users::UserId};
use std::collections::HashMap;

use aws_lc_rs::{encoding::AsDer as _, rsa::PrivateDecryptingKey};
use rusqlite::{OptionalExtension as _, ToSql, named_params};
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub struct AppId(pub i64);
impl std::ops::Deref for AppId {
    type Target = i64;
    fn deref(&self) -> &i64 {
        &self.0
    }
}

pub(super) fn id_by_slug<W>(tx: &Token<W>, slug: &str) -> Option<AppId> {
    tx.query_one(
        "SELECT id FROM applications WHERE slug = ?",
        [slug],
        |row| row.get(0).map(AppId),
    )
    .ok()
}

pub(crate) fn id_by_client_id<W>(
    tx: &Token<W>,
    client_id: &str,
) -> Option<AppId> {
    tx.query_one(
        "SELECT id FROM applications WHERE client_id = ?",
        [client_id],
        |row| row.get(0).map(AppId),
    )
    .ok()
}

/// The client_id is sufficient so this tacks on an auth component which is a
/// bit... odd. But I'm not entirely sure how this should be handled, it's
/// used as both a real auth (HTTP Basic auth for the oauth flow) and a pseudo
/// auth (oauth authorization finalization as query parameters)
pub(crate) fn id_by_secret<W>(
    tx: &Token<W>,
    client_id: &str,
    client_secret: &str,
) -> Option<AppId> {
    let secret = uuid::Uuid::try_parse(client_secret).unwrap();
    tx.query_one(
        "
            SELECT id
            FROM applications
            JOIN application_secrets ON (application = id)
            WHERE client_id = ? AND value = ?
            ",
        (client_id, secret.as_bytes()),
        |row| row.get(0).map(AppId),
    )
    .ok()
}

pub(super) struct App {
    pub(super) id: AppId,
    pub(super) owner: UserId,
    pub(super) name: String,
    pub(super) slug: String,
    pub(super) url: String,
    pub(super) description: Option<String>,

    pub(super) request_oauth_on_install: bool,
    pub(super) setup_on_update: bool,
    pub(super) setup_url: String,
    pub(super) callback_urls: String,

    pub(super) client_id: String,
}

pub(super) fn by_id<W>(tx: &Token<W>, appid: AppId) -> App {
    tx.query_one(
        "
        SELECT id, owner, name, description,
            request_oauth_on_install, setup_on_update, setup_url, callback_urls,
            slug, client_id, url
        FROM applications
        WHERE id = ?
        ",
        [*appid],
        |row| {
            Ok(App {
                id: AppId(row.get(0)?),
                owner: UserId(row.get(1)?),
                name: row.get(2)?,
                slug: row.get(8)?,
                url: row.get(10)?,
                description: row.get(3)?,
                request_oauth_on_install: row.get(4)?,
                setup_on_update: row.get(5)?,
                setup_url: row.get(6)?,
                callback_urls: row.get(7)?,
                client_id: row.get(9)?,
            })
        },
    )
    .expect("The application to be present if we have an AppId")
}

// TODO: can fail if the application is already installed
pub(super) fn install_into(tx: &Token<Write>, app: AppId, user: UserId) -> i64 {
    tx.query_one(
        "
        INSERT INTO installations (application, user, all_repos)
        VALUES (?, ?, 0)
        RETURNING id
        ",
        (*app, *user),
        |row| row.get(0),
    )
    .unwrap()
}

fn serialize_userid<S>(val: &UserId, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    (**val).serialize(serializer)
}

fn deserialize_userid<'de, D>(deserializer: D) -> Result<UserId, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(UserId(i64::deserialize(deserializer)?))
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Manifest {
    #[serde(
        serialize_with = "serialize_userid",
        deserialize_with = "deserialize_userid"
    )]
    pub(super) owner: UserId,
    pub(super) public: bool,

    pub(super) name: String,
    pub(super) description: Option<String>,
    pub(super) url: String,

    pub(super) request_oauth_on_install: bool,
    pub(super) setup_on_update: bool,
    pub(super) setup_url: String,
    pub(super) callback_urls: String,

    pub(super) webhook_url: String,

    pub(super) events: Vec<String>,
    pub(super) permissions: HashMap<String, Permission>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Permission {
    Read,
    Write,
}
impl ToSql for Permission {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        Ok(match self {
            Permission::Read => "read".into(),
            Permission::Write => "write".into(),
        })
    }
}

pub(super) fn create_pending(
    tx: &Token<Write>,
    code: uuid::Uuid,
    manifest: &Manifest,
) {
    tx.execute(
        "INSERT INTO applications_pending (code, manifest) VALUES (?, jsonb(?))",
        (code.as_bytes(), serde_json::to_string(manifest).expect("")),
    ).expect("insertion to succeed");
}

pub(crate) struct CreatedApp {
    pub id: AppId,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub owner: UserId,
    pub url: String,
    pub permissions: HashMap<String, Permission>,
    pub events: Vec<String>,
    pub client_id: String,
    pub client_secret: String,
    pub webhook_secret: String,
    pub key: PrivateDecryptingKey,
}

pub(crate) fn finalize(
    tx: &Token<Write>,
    code: uuid::Uuid,
) -> Option<CreatedApp> {
    let manifest: Manifest = tx
        .query_one(
            "
        DELETE FROM applications_pending
        WHERE code = ? AND expires_at > unixepoch()
        RETURNING json(manifest)
        ",
            [code.as_bytes()],
            |row| Ok(serde_json::from_str(row.get_ref(0)?.as_str()?).unwrap()),
        )
        .unwrap();

    let slug: String = manifest
        .name
        .chars()
        .filter_map({
            let mut non_printable = false;
            move |c| match c {
                'a'..='z' | '0'..='9' => {
                    non_printable = false;
                    Some(c)
                }
                'A'..='Z' => {
                    non_printable = false;
                    Some(c.to_ascii_lowercase())
                }
                // technically should also strip out diacritics and print the base
                // char if ascii alphanum, but does not go much further (unicode
                // sandwich demo sentence gets bodied, and jp is nil and rejected)
                _ if !non_printable => {
                    non_printable = true;
                    Some('-')
                }
                _ => None,
            }
        })
        .collect();
    if slug.is_empty() {
        return None;
    }
    // in github that's 20 base62 digits ~ 15 bytes
    let client_id = uuid::Uuid::new_v4();
    // in github that's 40 hex digits = 20 bytes
    let client_secret = uuid::Uuid::new_v4();
    let webhook_secret = uuid::Uuid::new_v4();
    // RSA256 = RSA_PKCS1_2048_8192_SHA256
    let private_key = aws_lc_rs::rsa::PrivateDecryptingKey::generate(
        aws_lc_rs::rsa::KeySize::Rsa2048,
    )
    .expect("");

    let bot_user = tx
        .query_one(
            "
            INSERT INTO users (login, type)
            VALUES (concat(?, '[bot]'), 'bot')
            RETURNING id
            ",
            [&slug],
            |r| r.get(0).map(UserId),
        )
        .unwrap();

    let appid = tx
        .query_one(
            "
        INSERT INTO applications
        (
            owner,
            public,
            name,
            slug,
            description,
            url,
            user,
            client_id,
            request_oauth_on_install,
            setup_on_update,
            setup_url,
            callback_urls,
            webhook_active,
            webhook_url,
            webhook_secret,
            events
        )
        VALUES (
            :owner,
            :public,
            :name,
            :slug,
            :description,
            :url,
            :user,
            :client_id,
            :request_oauth_on_install,
            :setup_on_update,
            :setup_url,
            :callback_urls,
            :webhook_active,
            :webhook_url,
            :webhook_secret,
            jsonb(:events)
        )
        RETURNING id
        ",
            named_params! {
                ":owner": *manifest.owner,
                ":public": manifest.public,
                ":name": &manifest.name,
                ":slug": &slug,
                ":description": manifest.description,
                ":url": &manifest.url,
                ":user": *bot_user,
                ":client_id": &client_id.as_simple().to_string(),
                ":request_oauth_on_install": manifest.request_oauth_on_install,
                ":setup_on_update": manifest.setup_on_update,
                ":setup_url": manifest.setup_url,
                ":callback_urls": manifest.callback_urls,
                ":webhook_active": true,
                ":webhook_url": manifest.webhook_url,
                ":webhook_secret": &webhook_secret.as_simple().to_string(),
                ":events": serde_json::to_string(&manifest.events).expect(""),
            },
            |row| row.get(0).map(AppId),
        )
        .unwrap();
    tx.execute(
        "
        INSERT INTO application_secrets (application, value)
        VALUES (?, ?)
        ",
        (*appid, client_secret.as_bytes()),
    )
    .unwrap();
    tx.execute(
        "
        INSERT INTO application_keys (application, pubkey)
        VALUES (?, ?)
        ",
        (
            *appid,
            private_key.public_key().as_der().expect("").as_ref(),
        ),
    )
    .unwrap();
    let mut stmt = tx.prepare(
        "INSERT INTO permissions (application, scope, access) VALUES (?, ?, ?)",
    )
    .unwrap();
    for (k, v) in &manifest.permissions {
        stmt.execute((*appid, k, v)).unwrap();
    }

    Some(CreatedApp {
        id: appid,
        name: manifest.name,
        slug,
        description: manifest.description,
        owner: manifest.owner,
        url: manifest.url,
        permissions: manifest.permissions,
        events: manifest.events,
        client_id: client_id.as_simple().to_string(),
        client_secret: client_secret.as_simple().to_string(),
        webhook_secret: webhook_secret.as_simple().to_string(),
        key: private_key,
    })
}

pub(super) fn create_pending_authorization(
    tx: &Token<Write>,
    app: AppId,
    user: UserId,
) -> String {
    let code = uuid::Uuid::new_v4();
    tx.execute(
        "
        INSERT INTO authorizations_pending (code, application, user)
        VALUES (?, ?, ?)
        ",
        (code.as_bytes(), *app, *user),
    )
    .unwrap();
    code.as_simple().to_string()
}

pub(super) struct AuthorizationTokens {
    pub(super) access_token: uuid::Uuid,
    pub(super) refresh_token: uuid::Uuid,
}

pub(super) fn validate_pending_authorization(
    tx: &Token<Write>,
    appid: AppId,
    code: String,
) -> Option<AuthorizationTokens> {
    let Some((app, user, valid)) = tx
        .query_row(
            "
            DELETE FROM authorizations_pending
            WHERE code = ?
            RETURNING application, user, expires_at > unixepoch()
            ",
            [uuid::Uuid::try_parse(&code).unwrap().as_bytes()],
            // TODO: this should probable be an Option<(i64, i64)>
            |row| <(i64, i64, bool)>::try_from(row),
        )
        .optional()
        .unwrap()
    else {
        todo!()
    };
    (valid && app == *appid).then(||{
        let access_token = uuid::Uuid::new_v4();
        let refresh_token = uuid::Uuid::new_v4();
        tx.execute(
            "
            INSERT INTO authorizations (application, user, access_token, refresh_token)
            VALUES (?, ?, ?, ?)
            ",
            (app, user, access_token.as_bytes(), refresh_token.as_bytes()),
        ).unwrap();
        AuthorizationTokens { access_token, refresh_token }
    })
}

pub(super) fn list_installations<M>(
    tx: &Token<M>,
    appid: AppId,
) -> Vec<UserId> {
    let mut stmt = tx
        .prepare("SELECT user FROM installations WHERE application = ?")
        .unwrap();
    stmt.query_map([*appid], |row| row.get(0).map(UserId))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

pub(super) fn delete_installation(
    tx: &Token<Write>,
    appid: AppId,
    installation_id: i64,
) -> bool {
    tx.execute(
        "DELETE FROM installations WHERE application = ? AND id = ?",
        (*appid, installation_id),
    )
    .unwrap()
        != 0
}

pub(super) fn installation_token(
    tx: &Token<Write>,
    appid: AppId,
    installation_id: i64,
    token: uuid::Uuid,
) -> Option<i64> {
    tx.query_one(
        "
        SELECT EXISTS (
            SELECT 1 FROM installations
            WHERE application = ? AND id = ?
        )
        ",
        (*appid, installation_id),
        |row| row.get::<_, bool>(0),
    )
    .unwrap()
    .then(|| {
        tx.query_one(
            "
            INSERT INTO installation_tokens (installation, value)
            VALUES (?, ?) RETURNING expires_at
            ",
            (installation_id, token.as_bytes()),
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
    })
}

pub(crate) struct Authorization {
    pub(crate) id: i64,
    pub(crate) application: AppId,
    pub(crate) user: UserId,
    pub(crate) expires_at: i64,
}
pub(crate) fn get_authorization(
    tx: &Token<crate::model::Read>,
    appid: AppId,
    raw_token: &str,
) -> Option<Authorization> {
    let token = uuid::Uuid::try_parse(raw_token).unwrap();
    tx.query_row(
        "
        SELECT id, application, user, access_token_expires_at FROM authorizations
        WHERE application = ? AND access_token = ?
        ",
        (*appid, token.as_bytes()),
        |row| {
            Ok(Authorization {
                id: row.get(0)?,
                application: row.get(1).map(AppId)?,
                user: row.get(2).map(UserId)?,
                expires_at: row.get(3)?,
            })
        },
    )
    .optional()
    .unwrap()
}

pub(crate) fn delete_authorization(
    tx: &Token<Write>,
    appid: AppId,
    raw_token: &str,
) -> bool {
    let Ok(token) = uuid::Uuid::try_parse(raw_token) else {
        return false;
    };
    tx.execute(
        "DELETE FROM authorizations WHERE application = ? AND access_token = ?",
        (*appid, token.as_bytes()),
    )
    .unwrap()
        != 0
}
