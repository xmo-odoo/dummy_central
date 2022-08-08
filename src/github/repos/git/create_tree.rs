use std::{collections::BTreeMap, mem::take};

use gix_actor::bstr::BString;
use gix_hash::Kind::Sha1;
use gix_hash::ObjectId;
use gix_object::{
    Tree,
    tree::{self, EntryKind},
};

use crate::model::{Token, Write, git, repos::Repository};
use github_types::git::{BlobItem, Entry as TreeCreateEntry};

pub struct TransientTree<'a>(
    &'a Token<Write>,
    &'a Repository,
    pub BTreeMap<BString, Entry>,
);
impl<'a> TransientTree<'a> {
    pub fn new(
        token: &'a Token<Write>,
        repository: &'a Repository,
        oid: Option<ObjectId>,
    ) -> Option<Self> {
        let t = if let Some(oid) = oid {
            git::load(token, repository.network, &oid)
                .and_then(|o| o.try_into_tree().ok())?
                .entries
                .into_iter()
                .map(|mut e| (take(&mut e.filename), e.into()))
                .collect()
        } else {
            BTreeMap::new()
        };
        Some(Self(token, repository, t))
    }
    pub fn add(
        &mut self,
        tce: TreeCreateEntry,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let new_entry =
            Entry::from_item(self.0, self.1.network, &tce.mode, tce.item)?;

        let mut map = &mut self.2;
        let name = if let Some((init, name)) = tce.path.rsplit_once('/') {
            for t in init.split('/') {
                let e = map
                    .entry(BString::from(t))
                    .or_insert_with(Entry::null_tree);
                map = if let Entry::Tree(_, m) = e {
                    m
                } else {
                    *e = Entry::null_tree();
                    e.map_mut()
                };
            }
            name.into()
        } else {
            tce.path.into()
        };
        map.insert(name, new_entry);
        Ok(())
    }
    pub fn save(self) -> ObjectId {
        let Self(tx, repo, map) = self;
        save_map(tx, repo, map)
    }
}

fn save_map(
    tx: &Token<Write>,
    repo: &Repository,
    map: BTreeMap<BString, Entry>,
) -> ObjectId {
    git::store(
        tx,
        repo.network,
        Tree {
            entries: {
                let mut v: Vec<_> = map
                    .into_iter()
                    .filter_map(|(filename, entry)| {
                        Some(match entry {
                            Entry::Blob(oid) => tree::Entry {
                                mode: EntryKind::Blob.into(),
                                filename,
                                oid,
                            },
                            Entry::BlobExecutable(oid) => tree::Entry {
                                mode: EntryKind::BlobExecutable.into(),
                                filename,
                                oid,
                            },
                            Entry::Link(oid) => tree::Entry {
                                mode: EntryKind::Link.into(),
                                filename,
                                oid,
                            },
                            Entry::Commit(oid) => tree::Entry {
                                mode: EntryKind::Commit.into(),
                                filename,
                                oid,
                            },
                            Entry::Tree(oid, map)
                                if oid.is_null() && map.is_empty() =>
                            {
                                return None;
                            }
                            Entry::Tree(oid, map) => tree::Entry {
                                mode: EntryKind::Tree.into(),
                                filename,
                                oid: if map.is_empty() {
                                    oid
                                } else {
                                    save_map(tx, repo, map)
                                },
                            },
                        })
                    })
                    .collect();
                v.sort();
                v
            },
        },
    )
}

#[derive(Debug)]
pub(crate) enum Entry {
    Blob(ObjectId),
    BlobExecutable(ObjectId),
    Link(ObjectId),
    Commit(ObjectId),
    // in the git model you can't have an empty tree, so leave the btree empty
    // to indicate it's not been loaded yet
    Tree(ObjectId, BTreeMap<BString, Entry>),
}
impl Entry {
    fn map_mut(&mut self) -> &mut BTreeMap<BString, Entry> {
        match self {
            Entry::Tree(_, m) => m,
            _ => panic!("at the disco"),
        }
    }
    fn null_tree() -> Self {
        Entry::Tree(ObjectId::null(Sha1), BTreeMap::default())
    }
    // FIXME: handle invalid hashes (should this validate the objects exist?)
    fn from_item(
        tx: &Token<Write>,
        network: crate::model::repos::Network,
        mode: &str,
        item: github_types::git::Item,
    ) -> Result<Entry, Box<dyn std::error::Error>> {
        Ok(match item {
            github_types::git::Item::Blob(item) => {
                let oid = match item {
                    BlobItem::Sha { sha } => {
                        gix_hash::ObjectId::from_hex(sha.as_bytes())
                            .map_err(|_| {
                                format!("tree.sha {sha} is not a valid blob")
                            })
                            .and_then(reject_null)?
                    }
                    BlobItem::Content { content } => git::store(
                        tx,
                        network,
                        gix_object::Blob {
                            data: content.into_bytes(),
                        },
                    ),
                };
                match mode {
                    "100644" => Self::Blob(oid),
                    "100755" => Self::BlobExecutable(oid),
                    "120000" => Self::Link(oid),
                    _ => Err(format!("Invalid mode {mode} for blob"))?,
                }
            }
            github_types::git::Item::Commit { sha } => Self::Commit(
                gix_hash::ObjectId::from_hex(sha.as_bytes())
                    .map_err(|_| {
                        format!("tree.sha {sha} is not a valid commit")
                    })
                    .and_then(reject_null)?,
            ),
            github_types::git::Item::Tree { sha } => Self::Tree(
                gix_hash::ObjectId::from_hex(sha.as_bytes())
                    .map_err(|_| format!("tree.sha {sha} is not a valid tree"))
                    .and_then(reject_null)?,
                BTreeMap::default(),
            ),
        })
    }
}

fn reject_null(oid: gix_hash::ObjectId) -> Result<gix_hash::ObjectId, String> {
    if oid.is_null() {
        Err("GitRPC::BadObjectState".into())
    } else {
        Ok(oid)
    }
}

impl From<tree::Entry> for Entry {
    fn from(tree::Entry { mode, oid, .. }: tree::Entry) -> Entry {
        match EntryKind::from(mode) {
            EntryKind::Blob => Entry::Blob(oid),
            EntryKind::BlobExecutable => Entry::BlobExecutable(oid),
            EntryKind::Link => Entry::Link(oid),
            EntryKind::Tree => Entry::Tree(oid, Default::default()),
            EntryKind::Commit => Entry::Commit(oid),
        }
    }
}
