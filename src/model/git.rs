use std::collections::{hash_map::RandomState, HashMap, HashSet, VecDeque};

use git_actor::Signature;
use git_diff::tree::{recorder::Change, Changes, Recorder, State};
use git_hash::{oid, ObjectId};
use git_object::{
    tree::Entry, Commit, CommitRef, Kind, Object, ObjectRef, TagRef, Tree,
    TreeRefIter,
};
use rusqlite::{types::ValueRef, OptionalExtension};
use sha1::{Digest, Sha1};

use super::{
    repos::{Network, RepositoryId},
    Token,
};

/// git_object's `loose_header` const size, not sure why 28 (I count about 12)
const HEADER_SIZE: usize = 28;

pub mod refs {
    use git_hash::{oid, ObjectId};
    use rusqlite::OptionalExtension;

    use crate::model::{repos::RepositoryId, Token};

    pub fn resolve(
        tx: &Token,
        repo: RepositoryId,
        name: &str,
    ) -> Option<ObjectId> {
        tx.query_row(
            "
            SELECT sha FROM refs
            LEFT JOIN objects ON (id = object)
            WHERE repository = ? AND name = ?
        ",
            (*repo, name),
            |row| Ok(ObjectId::from(row.get_ref("sha")?.as_blob()?)),
        )
        .optional()
        .unwrap()
    }

    pub fn list(tx: &Token, repo: RepositoryId, mut f: impl FnMut(&str, &oid)) {
        tx.prepare(
            "
            SELECT name, sha FROM refs
            LEFT JOIN objects ON (id = object)
            WHERE repository = ?
        ",
        )
        .unwrap()
        .query_map([*repo], |row| {
            f(
                row.get_ref("name")?.as_str()?,
                oid::from_bytes_unchecked(row.get_ref("sha")?.as_bytes()?),
            );
            Ok(())
        })
        .unwrap()
        .for_each(Result::unwrap)
    }

    pub fn create(tx: &Token, repo: RepositoryId, name: &str, oid: &oid) {
        assert_eq!(
            tx.execute(
                "
                INSERT INTO refs (name, repository, object)
                VALUES (?, ?, (SELECT id FROM objects WHERE sha = ?))
            ",
                (name, *repo, oid.as_bytes())
            )
            .unwrap(),
            1
        )
    }

    pub fn set(tx: &Token, repo: RepositoryId, name: &str, to: &oid) {
        tx.execute(
            "
            UPDATE refs SET object = to_.id
            FROM objects to_
            WHERE refs.repository = ?
                AND refs.name = ?
                AND to_.sha = ?
            ",
            (*repo, name, to.as_bytes()),
        )
        .unwrap();
    }

    pub fn update(
        tx: &Token,
        repo: RepositoryId,
        name: &str,
        from: &oid,
        to: &oid,
    ) {
        assert_eq!(
            tx.execute(
                "
                UPDATE refs SET object = to_.id
                FROM objects from_, objects to_
                WHERE refs.repository = ?
                  AND refs.name = ?
                  AND from_.sha = ?
                  AND refs.object = from_.id
                  AND to_.sha = ?
                ",
                (*repo, name, from.as_bytes(), to.as_bytes())
            )
            .unwrap(),
            1
        )
    }
    pub fn delete(tx: &Token, repo: RepositoryId, name: &str, oid: &oid) {
        assert_eq!(
            tx.execute("
                    DELETE FROM refs INNER JOIN objects ON (objects.id = refs.object)
                    WHERE refs.repository = ? AND refs.name = ? AND objects.sha = ?
                ", (*repo, name, oid.as_bytes())
            ).unwrap(),
            1
        )
    }

    pub fn delete_unchecked(
        tx: &Token,
        repo: RepositoryId,
        name: &str,
    ) -> bool {
        tx.execute(
            "
                DELETE FROM refs
                WHERE refs.repository = ? AND refs.name = ?
            ",
            (*repo, name),
        )
        .unwrap()
            == 1
    }
}

pub fn get_objects(tx: &Token, network: Network) -> Vec<ObjectId> {
    tx.prepare("SELECT sha FROM objects WHERE network = ?")
        .unwrap()
        .query_map([*network], |row| {
            Ok(ObjectId::from(row.get_ref("sha")?.as_bytes()?))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
pub struct ObjectDbId(pub(super) i64);
impl std::ops::Deref for ObjectDbId {
    type Target = i64;
    fn deref(&self) -> &i64 {
        &self.0
    }
}

pub fn get(tx: &Token, network: Network, oid: &oid) -> Option<ObjectDbId> {
    tx.query_row(
        "SELECT id FROM objects WHERE network = ? AND sha = ?",
        (*network, oid.as_bytes()),
        |row| row.get("id").map(ObjectDbId),
    )
    .optional()
    .unwrap()
}

pub fn deref(tx: &Token, id: ObjectDbId) -> ObjectId {
    tx.query_row("SELECT sha FROM objects WHERE id = ?", [*id], |row| {
        Ok(ObjectId::from(row.get_ref("sha")?.as_blob()?))
    })
    .unwrap()
}

pub fn load(
    tx: &Token,
    network: Network,
    oid: &oid,
) -> Option<git_object::Object> {
    tx.query_row(
        "SELECT data FROM objects WHERE network = ? AND sha = ?",
        (*network, oid.as_bytes()),
        |row| {
            let data = row.get_ref("data")?.as_blob()?;
            Ok(ObjectRef::from_loose(data).unwrap().to_owned())
        },
    )
    .optional()
    .unwrap()
}

pub fn get_in<'buf>(
    tx: &Token,
    network: Network,
    oid: &oid,
    buf: &'buf mut Vec<u8>,
) -> Option<(git_object::Kind, &'buf [u8])> {
    tx.query_row(
        "SELECT data FROM objects WHERE network = ? AND sha = ?",
        (*network, oid.as_bytes()),
        |row| {
            buf.extend(row.get_ref("data")?.as_blob()?);
            Ok(())
        },
    )
    .optional()
    .unwrap()?;

    let (kind, _, consumed) = git_object::decode::loose_header(buf).ok()?;
    Some((kind, &buf[consumed..]))
}

pub fn store(
    tx: &Token,
    network: Network,
    object: impl git_object::WriteTo,
) -> ObjectId {
    let mut obj = Vec::new();
    object
        .write_to(&mut obj)
        .expect("Write to vec probably can't fail");
    if object.kind() == Kind::Commit {
        assert!(!obj.contains(&0));
    }
    let mut to = Vec::with_capacity(HEADER_SIZE + obj.len());
    // writes object header
    to.extend(object.loose_header());
    // writes the rest of the ~~owl~~ object
    to.extend(obj);
    // computes oid and inserts serialized object
    let oid = ObjectId::from(<[u8; 20]>::from(Sha1::digest(&to)));

    tx.execute(
        "
        INSERT INTO objects (network, sha, data) VALUES (?, ?, ?)
        ON CONFLICT DO NOTHING
    ",
        (*network, oid.as_bytes(), to),
    )
    .unwrap();

    oid
}

/// Resolves oid until a tree object, retuens the tree, fails if it reached a
/// dead-end (a blob) or an oid which doesn't exist
pub fn load_tree(
    tx: &Token,
    network: Network,
    oid: &oid,
) -> Option<impl Iterator<Item = Entry> + Clone> {
    let mut object_id = oid.to_owned();
    loop {
        object_id = match load(tx, network, &object_id)? {
            Object::Tree(t) => return Some(t.entries.into_iter()),
            Object::Blob(_) => return None,
            Object::Commit(c) => c.tree,
            Object::Tag(t) => t.target,
        }
    }
}

pub fn find_tree(
    tx: &Token,
    network: Network,
    oid: &oid,
) -> Option<impl Iterator<Item = Entry>> {
    load(tx, network, oid)
        .and_then(|o| o.try_into_tree().ok())
        .map(|t| t.entries.into_iter())
}

pub fn log<'a, 'b: 'a>(
    token: &'a Token<'b>,
    network: Network,
    oid: &oid,
) -> Option<Log<'a, 'b>> {
    load(token, network, oid).map(|_| Log::new(token, network, oid))
}

pub struct Log<'a, 'b: 'a> {
    token: &'a Token<'b>,
    network: Network,
    seen: HashSet<ObjectId>,
    to_check: VecDeque<ObjectId>,
}
impl<'a, 'b> Log<'a, 'b> {
    fn new<'s, 'c: 's>(
        token: &'s Token<'c>,
        network: Network,
        oid: &oid,
    ) -> Log<'s, 'c> {
        Log {
            token,
            network,
            seen: HashSet::with_capacity(8),
            to_check: VecDeque::from([oid.to_owned()]),
        }
    }
}

impl Iterator for Log<'_, '_> {
    type Item = ObjectId;
    fn next(&mut self) -> Option<ObjectId> {
        if let Some(next) = self.to_check.pop_front() {
            if self.seen.insert(next) {
                self.to_check.extend(
                    load(self.token, self.network, &next)
                        .unwrap()
                        .into_commit()
                        .parents,
                );
            }
            return Some(next);
        }
        None
    }
}

pub fn merge(
    tx: &Token,
    network: Network,
    message: String,
    left: &oid,
    right: &oid,
    author: Signature,
    committer: Signature,
) -> Result<ObjectId, MergeError> {
    let merge_base = find_merge_base(tx, network, left, right)
        .ok_or(MergeError::NoCommonAncestor)?;
    // FIXME: if oid1 is the merge base, this is an ff merge, if oid2 is the
    //        merge base, this is already merged

    let updates = {
        // fixme: should be recursive resolutions as those are commits!
        let mut _base_buf = Vec::new();
        let base = resolve_tree_in(tx, network, &merge_base, &mut _base_buf)?;
        let mut _left_buf = Vec::new();
        let left_tree = resolve_tree_in(tx, network, left, &mut _left_buf)?;
        let mut _right_buf = Vec::new();
        let right_tree = resolve_tree_in(tx, network, right, &mut _right_buf)?;

        let mut changes1 = Recorder::default();
        Changes::from(base.clone())
            .needed_to_obtain(
                left_tree,
                State::default(),
                |oid, buf| get_tree_in(tx, network, oid, buf),
                &mut changes1,
            )
            .map_err(|_| MergeError::NotFound)?;
        let mut updates = HashMap::with_capacity(changes1.records.len());
        for c in changes1.records {
            updates.insert(path(&c).to_owned(), c);
        }

        let mut changes2 = Recorder::default();
        Changes::from(base)
            .needed_to_obtain(
                right_tree,
                State::default(),
                |oid, buf| get_tree_in(tx, network, oid, buf),
                &mut changes2,
            )
            .map_err(|_| MergeError::NotFound)?;

        for c2 in changes2.records {
            let p = path(&c2);
            if let Some(c1) = updates.get(p) {
                if c1 == &c2 {
                    continue;
                }
                return Err(MergeError::Conflict);
            }
            updates.insert(p.to_owned(), c2);
        }
        updates
    };

    let mut new_tree: Tree = load(tx, network, &merge_base)
        .and_then(|o| o.try_into_commit().ok())
        .map(|c| c.tree)
        .and_then(|t| load(tx, network, &t))
        .and_then(|o| o.try_into_tree().ok())
        .expect("we just got it!");

    for (path, change) in updates {
        match change {
            Change::Addition {
                entry_mode,
                oid,
                path,
            } => {
                assert!(!new_tree.entries.iter().any(|e| e.filename == path));
                new_tree.entries.push(Entry {
                    mode: entry_mode,
                    filename: path,
                    oid,
                });
            }
            Change::Deletion {
                entry_mode,
                oid,
                path,
            } => {
                // todo: validate that the suppression worked (?)
                new_tree.entries.retain(|e| e.filename != path);
            }
            Change::Modification {
                previous_entry_mode,
                previous_oid,
                entry_mode,
                oid,
                path,
            } => {
                let e = new_tree
                    .entries
                    .iter_mut()
                    .find(|e| e.filename == path)
                    .unwrap();
                assert_eq!(e.oid, previous_oid);
                assert_eq!(e.mode, entry_mode);
                e.oid = oid;
            }
        }
    }
    new_tree
        .entries
        .sort_by(|e1, e2| e1.filename.cmp(&e2.filename));

    let tid = store(tx, network, new_tree);
    let cid = store(
        tx,
        network,
        Commit {
            tree: tid,
            parents: vec![left.to_owned(), right.to_owned()].into(),
            author,
            committer,
            encoding: None,
            message: message.into(),
            extra_headers: Vec::new(),
        },
    );

    Ok(cid)
}

/// Returns a tree buffer for the oid, or fails with the relevant merge error
/// (NotFound or InvalidObjectType)
fn get_tree_in<'buf>(
    tx: &Token,
    network: Network,
    oid: &oid,
    mut buf: &'buf mut Vec<u8>,
) -> Result<TreeRefIter<'buf>, MergeError> {
    get_in(tx, network, oid, &mut *buf)
        .ok_or(MergeError::NotFound)
        .and_then(|(kind, buf)| {
            if kind == Kind::Tree {
                Ok(TreeRefIter::from_bytes(buf))
            } else {
                Err(MergeError::InvalidObjectType(kind))
            }
        })
}

/// Resolves oid until a tree object, returns the tree, fails if it reaches a
/// dead end (blob) or an oid which does not exist
fn resolve_tree_in<'buf>(
    tx: &Token,
    network: Network,
    oid: &oid,
    buf: &'buf mut Vec<u8>,
) -> Result<TreeRefIter<'buf>, MergeError> {
    let mut object_id = oid.to_owned();
    loop {
        buf.clear();
        object_id = match get_in(tx, network, &object_id, buf)
            .ok_or(MergeError::NotFound)?
        {
            (Kind::Tree, data) => {
                // this mess is sadly necessary because `buf` contains the
                // loose object header so can't be used directly, but if we use
                // `data` then we hit the "return borrow from mutable in loop"
                // thing (#70255), therefore we need to recompute the tree
                // object slice directly from `buf`
                let left = data.len();
                let consumed = buf.len() - left;
                return Ok(TreeRefIter::from_bytes(&buf[consumed..]));
            }
            (Kind::Blob, _) => return Err(MergeError::NoTree),
            (Kind::Commit, data) => CommitRef::from_bytes(data)
                .map_err(|_| MergeError::Corrupted(object_id, Kind::Commit))?
                .tree(),
            (Kind::Tag, data) => TagRef::from_bytes(data)
                .map_err(|_| MergeError::Corrupted(object_id, Kind::Tag))?
                .target(),
        };
    }
}

pub fn find_merge_base(
    tx: &Token,
    network: Network,
    oid1: &oid,
    oid2: &oid,
) -> Option<ObjectId> {
    // FIXME: it's possible for there to be 2 BCE in cross merge situations,
    //        in which case recursive merge means creating a virtual branch
    //        in which the BCEs are merged, then that is used as the common
    //        ancestor

    // create a set of all oid1 ancestors, then find the first
    // (breadth-first) ancestor of oid2 that's in
    let ancestors: HashSet<ObjectId> = log(tx, network, oid1)?.collect();

    log(tx, network, oid2)?.find(|oid| ancestors.contains(oid))
}

#[derive(Debug)]
pub enum MergeError {
    NoCommonAncestor,
    NotFound,
    NoTree,
    Conflict,
    InvalidObjectType(Kind),
    Corrupted(ObjectId, Kind),
}
impl std::fmt::Display for MergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::NoCommonAncestor => f.write_str("No common ancestor."),
            Self::NotFound => f.write_str("Something was not found."),
            Self::Conflict => f.write_str("Conflict"),
            Self::NoTree => f.write_str("Never found a tree object"),
            Self::InvalidObjectType(kind) => write!(
                f,
                "Invalid object type, expected {}, found {}",
                Kind::Tree,
                kind
            ),
            Self::Corrupted(oid, kind) => {
                write!(f, "Found corrupted object {} ({})", oid.to_hex(), kind)
            }
        }
    }
}
impl std::error::Error for MergeError {}

fn path(c: &Change) -> &git_object::bstr::BStr {
    match c {
        Change::Addition { path, .. }
        | Change::Deletion { path, .. }
        | Change::Modification { path, .. } => path.as_ref(),
    }
}
