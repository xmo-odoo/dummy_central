use chrono::{DateTime, FixedOffset, NaiveDateTime, SecondsFormat};
use git_object::Kind;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

// FIXME: decorrelate internal authorship model from over the wire, so date is not optional
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
/// missing, invalid, or out of range (for a u32 timestamp)
///
/// TODO: see what tz github uses in those cases (or if it's just an error but
///       it doesn't seem to be at least for out of range dates)
impl From<Authorship> for git_actor::Signature {
    fn from(a: Authorship) -> Self {
        let time = a
            .date
            .and_then(|d| DateTime::parse_from_rfc3339(&d).ok())
            .map_or_else(git_actor::Time::now_utc, |dt| {
                git_actor::Time::new(
                    // it's really weird but this is the actual github behaviour,
                    // not entirely clear what the git date-parsing code does
                    dt.timestamp() as _,
                    dt.offset().local_minus_utc(),
                )
            });

        git_actor::Signature {
            name: a.name.into(),
            email: a.email.into(),
            time,
        }
    }
}
impl From<git_actor::SignatureRef<'_>> for Authorship {
    fn from(s: git_actor::SignatureRef<'_>) -> Self {
        let dt = DateTime::<FixedOffset>::from_utc(
            NaiveDateTime::from_timestamp_opt(
                s.time.seconds_since_unix_epoch as _,
                0,
            )
            .unwrap(),
            FixedOffset::east_opt(s.time.offset_in_seconds).unwrap(),
        );

        Self {
            name: s.name.to_string(),
            email: s.email.to_string(),
            date: Some(dt.to_rfc3339_opts(SecondsFormat::Secs, true)),
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(from = "&str")]
pub enum BlobEncoding {
    Base64,
    Text,
}
impl From<&str> for BlobEncoding {
    fn from(s: &str) -> Self {
        if s == "base64" {
            Self::Base64
        } else {
            Self::Text
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct CreateBlobRequest {
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
                        let $v = if let Some(Some(x)) = $it.next() {
                            x
                        } else {
                            break;
                        };
                    };
                    ($v:ident <= $it:ident, skip) => {
                        let mut filtered = $it.by_ref().filter_map(|e| e);
                        let $v = if let Some(x) = filtered.next() {
                            x
                        } else {
                            break;
                        };
                    };
                }
                let mut output = Vec::new();
                loop {
                    next!(a <= input, skip);
                    next!(b <= input, skip);
                    output.push(a << 2 | b >> 4);
                    next!(c <= input);
                    output.push((b & 0xF) << 4 | c >> 2);
                    next!(d <= input);
                    output.push((c & 0x3) << 6 | d);
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

#[derive(Deserialize)]
pub struct TreeCreation {
    pub tree: Vec<Entry>,
    pub base_tree: Option<String>,
}
#[derive(Deserialize)]
pub struct Entry {
    /// the file referenced in the tree
    /// TODO: check if that's a filename or a path
    pub path: String,
    /// TODO: should be an EntryMode parsed from a string, but
    ///       git_object parses from an integer
    pub mode: String,
    #[serde(flatten)]
    pub item: Item,
}
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Item {
    Blob(BlobItem),
    Commit { sha: String },
    Tree { sha: String },
}
#[derive(Deserialize)]
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
    pub size: usize,
    #[serde(flatten)]
    pub obj: ShortObject,
}

#[derive(Deserialize, Debug)]
pub struct CommitReq {
    pub message: String,
    pub tree: String,
    #[serde(default)]
    pub parents: Vec<String>,
    pub author: Option<Authorship>,
    pub committer: Option<Authorship>,
}

#[derive(Deserialize)]
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
impl From<(&str, &str, &str, Kind, &git_hash::oid)> for ShortObject {
    fn from(
        (root, owner, name, kind, oid): (
            &str,
            &str,
            &str,
            Kind,
            &git_hash::oid,
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

impl From<(&String, &String, &String, Kind, git_hash::ObjectId)>
    for ShortObject
{
    fn from(
        (root, owner, name, kind, oid): (
            &String,
            &String,
            &String,
            Kind,
            git_hash::ObjectId,
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
