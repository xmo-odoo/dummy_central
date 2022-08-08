use std::borrow::Cow;

use chrono::{DateTime, SecondsFormat};
use gix_object::Kind;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Authorship {
    /// The name of the author or committer of the commit. You'll
    /// receive a `422` status code if `name` is omitted.
    pub name: String,
    /// The email of the author or committer of the commit. You'll
    /// receive a `422` status code if `email` is omitted.
    pub email: String,
    #[serde(default)]
    pub date: Option<String>,
}
/// Converts an Authorship into a Signature, defaulting the time to current if
/// missing.
impl TryFrom<Authorship> for gix_actor::Signature {
    type Error = Authorship;
    fn try_from(a: Authorship) -> Result<Self, Self::Error> {
        let time = if let Some(d) = &a.date {
            let Ok(dt) = DateTime::parse_from_rfc3339(d) else {
                return Err(a);
            };
            gix_date::Time::new(
                std::cmp::max(dt.timestamp(), 0).rem_euclid(2i64.pow(32)) as _,
                dt.offset().local_minus_utc(),
            )
        } else {
            gix_date::Time::now_utc()
        };

        Ok(gix_actor::Signature {
            name: a.name.into(),
            email: a.email.into(),
            time,
        })
    }
}
impl From<gix_actor::SignatureRef<'_>> for Authorship {
    fn from(s: gix_actor::SignatureRef<'_>) -> Self {
        Self {
            name: s.name.to_string(),
            email: s.email.to_string(),
            date: DateTime::from_timestamp(s.seconds(), 0)
                .map(|d| d.to_rfc3339_opts(SecondsFormat::Secs, true)),
        }
    }
}

#[derive(Debug)]
pub enum BlobEncoding {
    Base64,
    Text,
}
impl Default for BlobEncoding {
    fn default() -> Self {
        Self::Text
    }
}
impl<'de> Deserialize<'de> for BlobEncoding {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match <&str>::deserialize(deserializer) {
            Ok("base64") => Ok(Self::Base64),
            _ => Ok(Self::Text),
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct CreateBlobRequest {
    #[serde(default)]
    pub encoding: BlobEncoding,
    pub content: String,
}
impl CreateBlobRequest {
    pub fn as_bytes(&self) -> Cow<'_, [u8]> {
        match self.encoding {
            BlobEncoding::Text => self.content.as_bytes().into(),
            BlobEncoding::Base64 => {
                // implement Ruby's base64 decoding:
                //
                // - skip all non-base64 content
                // - stops iif the 3rd or 4th character of a chunk of 4) is an `=`
                let mut input = self.content.chars().filter_map(|c| {
                    Some(Some(match c {
                        'A'..='Z' => c as u8 - b'A',
                        'a'..='z' => c as u8 - b'a' + 26,
                        '0'..='9' => c as u8 - b'0' + 52,
                        '+' => 62,
                        '/' => 63,
                        '=' => return Some(None),
                        _ => return None,
                    }))
                });

                macro_rules! next {
                    ($v:ident <= $it:ident) => {
                        let Some(Some($v)) = $it.next() else {
                            break;
                        };
                    };
                    ($v:ident <= $it:ident, skip) => {
                        let mut filtered = $it.by_ref().filter_map(|e| e);
                        let Some($v) = filtered.next() else {
                            break;
                        };
                    };
                }
                let mut output = Vec::new();
                loop {
                    next!(a <= input, skip);
                    next!(b <= input, skip);
                    output.push((a << 2) | (b >> 4));
                    next!(c <= input);
                    output.push(((b & 0xF) << 4) | (c >> 2));
                    next!(d <= input);
                    output.push(((c & 0x3) << 6) | d);
                }
                output.into()
            }
        }
    }
}

#[derive(Serialize)]
pub struct CreateBlobResponse {
    pub sha: String,
    pub url: String,
}

#[derive(Serialize)]
#[serde(tag = "encoding", rename_all = "snake_case")]
pub enum BlobResponse {
    Base64 {
        node_id: String,
        #[serde(flatten)]
        _id: CreateBlobResponse,
        content: String,
        size: usize,
    },
}

#[derive(Deserialize, Debug)]
pub struct TreeCreation {
    pub tree: Vec<Entry>,
    pub base_tree: Option<String>,
}
#[derive(Deserialize, Debug)]
pub struct Entry {
    /// the file referenced in the tree
    pub path: String,
    pub mode: String,
    #[serde(flatten)]
    pub item: Item,
}
#[derive(Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Item {
    Blob(BlobItem),
    Commit { sha: String },
    Tree { sha: String },
}
#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum BlobItem {
    Content { content: String },
    Sha { sha: String },
}

#[derive(Serialize)]
pub struct TreeResponse {
    pub sha: String,
    pub url: String,
    pub tree: Vec<TreeResponseEntry>,
    pub truncated: bool,
}
#[derive(Serialize)]
pub struct TreeResponseEntry {
    pub path: String,
    pub mode: String,
    pub size: Option<usize>,
    #[serde(flatten)]
    pub obj: ShortObject,
}

#[derive(Deserialize, Debug)]
pub struct CommitReq {
    pub message: String,
    pub tree: String,
    #[serde(default)]
    pub parents: Vec<String>,
    #[serde(default, deserialize_with = "crate::utils::unset")]
    pub author: Option<Option<Authorship>>,
    pub committer: Option<Authorship>,
}

#[derive(Deserialize, Debug)]
pub struct RefReq {
    pub sha: String,
    /// fully qualified reference, must contain at least two `/` (and start with refs?)
    pub r#ref: String,
}

#[derive(Serialize)]
pub struct RefResponse {
    pub r#ref: String,
    pub node_id: String,
    pub url: String,
    pub object: ShortObject,
}
#[derive(Serialize)]
pub struct ShortObject {
    pub r#type: &'static str,
    pub sha: String,
    pub url: String,
}
impl From<(&str, &str, &str, Kind, &gix_hash::oid)> for ShortObject {
    fn from(
        (root, owner, name, kind, oid): (
            &str,
            &str,
            &str,
            Kind,
            &gix_hash::oid,
        ),
    ) -> Self {
        let kind = match kind {
            Kind::Commit => "commit",
            Kind::Tag => "tag",
            Kind::Tree => "tree",
            Kind::Blob => "blob",
        };
        Self {
            r#type: kind,
            sha: oid.to_string(),
            url: format!("{root}/repos/{owner}/{name}/git/{kind}s/{oid}"),
        }
    }
}

impl From<(&String, &String, &String, Kind, gix_hash::ObjectId)>
    for ShortObject
{
    fn from(
        (root, owner, name, kind, oid): (
            &String,
            &String,
            &String,
            Kind,
            gix_hash::ObjectId,
        ),
    ) -> Self {
        Self::from((
            root.as_str(),
            owner.as_str(),
            name.as_str(),
            kind,
            oid.as_ref(),
        ))
    }
}

#[derive(Deserialize, Debug)]
pub struct RefUpdateRequest {
    pub sha: String,
    #[serde(default)]
    pub force: bool,
}
