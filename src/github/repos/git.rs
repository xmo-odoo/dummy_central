use base64::prelude::{Engine as _, BASE64_STANDARD};
use flate2::write::ZlibEncoder;
use git_object::bstr::{self, BString, ByteSlice};
use git_object::tree::{Entry as TreeEntry, EntryMode};
use git_object::{Data, Kind, ObjectRef};
use git_pack::data::output::bytes::FromEntriesIter;
use git_pack::data::output::{Count, Entry as PackEntry};
use git_pack::data::Version;
use rusqlite::{params, OptionalExtension as _};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{btree_map::Entry::*, HashMap, VecDeque};
use std::io::Write;
use std::sync::{RwLock, RwLockWriteGuard};
use std::time::{SystemTime, UNIX_EPOCH};
use warp::*;

use guard::guard;

use crate::github::{Authorization, Error, St};
use crate::model::prs::PullRequestId;
use crate::model::repos::RepositoryId;
use crate::model::users::find_current_user;
use crate::model::Source;

pub use github_types::git::*;
use github_types::repos::HookEvent;
use github_types::webhooks;

#[rustfmt::skip]
pub fn routes<T>(base: T) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone
where
    T: Filter<Extract = (Authorization, St, String, String), Error = Rejection> + Clone + Send + Sync + 'static,
{
    let base = base.and(path::path("git"));

    base.clone().and(path!("blobs")).and(post()).and(body::json()).map(create_blob).boxed()
        .or(base.clone().and(path!("blobs" / String)).and(get()).map(get_blob).boxed())
        .or(base.clone().and(path!("trees" / String)).and(get()).and(query()) .map(get_tree).boxed())
        .or(base.clone().and(path!("trees")).and(post()).and(body::json()).map(create_tree).boxed())
        .or(base.clone().and(path!("commits" / String)).and(get()).map(get_commit).boxed())
        .or(base.clone().and(path!("commits")).and(post()).and(body::json()).map(create_commit).boxed())
        .or(base.clone().and(path!("refs")).and(get()).map(list_refs))
        .or(base.clone().and(path!("refs")).and(post()).and(body::json()).map(create_ref).boxed())
        .or(base.clone().and(path::path("ref")).and(path::tail()).and(get()).map(get_ref).boxed())
        .or(base.clone().and(path::path("refs")).and(path::tail()).and(get()).map(get_ref).boxed())
        .or(base.clone().and(path::path("refs")).and(path::tail()).and(patch()).and(body::json()).map(update_ref).boxed())
        .or(base.clone().and(path::path("refs")).and(path::tail()).and(delete()).map(delete_ref).boxed())
}

fn create_blob(
    _: Authorization,
    st: St,
    owner: String,
    name: String,
    req: CreateBlobRequest,
) -> impl Reply {
    let mut db = Source::get();
    let tx = db.token_eager();
    guard!(let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Error::NotFound.into_response("git", "create-a-blob");
    });

    let oid = crate::model::git::store(
        &tx,
        repo.network,
        git_object::BlobRef::from_bytes(&req.as_bytes()).unwrap(),
    );

    tx.commit().unwrap();
    reply::with_status(
        reply::json(&CreateBlobResponse {
            sha: oid.to_string(),
            url: format!(
                "{}/repos/{}/{}/git/blobs/{}",
                st.root, owner, name, oid
            ),
        }),
        http::StatusCode::CREATED,
    )
    .into_response()
}

/// gh (apparently) uses Ruby's `Base64.encode`, meaning it adds a newline
/// (*not a CRLF*) every 60 encoded characters
fn gh_base64_encode(data: &[u8]) -> String {
    let encoded = BASE64_STANDARD.encode(data);
    let mut s = String::with_capacity(encoded.len() + encoded.len() / 60 + 1);
    for chunk in encoded.as_bytes().chunks(60) {
        s.push_str(
            std::str::from_utf8(chunk)
                .expect("base64 encoding should be pure ascii"),
        );
        s.push('\n');
    }
    s
}
fn get_blob(
    _: Authorization,
    st: St,
    owner: String,
    name: String,
    blob_id: String,
) -> impl Reply {
    let mut db = Source::get();
    let tx = &db.token();
    guard!(let Some(repo) = crate::model::repos::by_name(tx, &owner, &name) else {
        return Error::NotFound.into_response("git", "get-a-blob");
    });

    guard!(let Some(object) = git_hash::ObjectId::from_hex(blob_id.as_bytes()).ok()
    .and_then(|oid| crate::model::git::load(tx, repo.network, &oid)) else {
        return Error::NotFound.into_response("git", "get-a-blob");
    });
    let blob = object.into_blob();
    let url =
        format!("{}/repos/{}/{}/git/blobs/{}", st.root, owner, name, blob_id);
    reply::with_status(
        reply::json(&BlobResponse::Base64 {
            node_id: String::new(),
            _id: CreateBlobResponse { sha: blob_id, url },
            content: gh_base64_encode(&blob.data),
            size: blob.data.len(),
        }),
        http::StatusCode::OK,
    )
    .into_response()
}
fn get_tree(
    _: Authorization,
    st: St,
    owner: String,
    name: String,
    tree_id: String,
    query: HashMap<String, String>,
) -> impl Reply {
    let mut db = Source::get();
    let tx = &db.token();
    guard!(let Some(repo) = crate::model::repos::by_name(tx, &owner, &name) else {
        return Error::NotFound.into_response("git", "get-a-tree");
    });

    // todo: invalid oid? missing tree?
    let t = git_hash::ObjectId::from_hex(tree_id.as_bytes())
        .ok()
        .and_then(|oid| crate::model::git::load(tx, repo.network, &oid));
    let tree = if let Some(t) = t {
        t
    } else {
        return Error::NotFound.into_response("git", "get-a-tree");
    };
    let tree = tree.into_tree();

    // TODO: check if the trigger is having the query
    //       parameter at all or having a non-empty value
    if query.get("recursive").map(|s| &**s).unwrap_or("") != "" {
        // TODO: recursive
    }
    reply::with_status(
        reply::json(&TreeResponse {
            sha: tree_id,
            url: String::new(),
            truncated: false,
            tree: tree
                .entries
                .iter()
                .map(|e| {
                    let obj = crate::model::git::load(tx, repo.network, &e.oid)
                        .unwrap();
                    TreeResponseEntry {
                        path: e.filename.to_string(),
                        size: 0, // FIXME
                        mode: match e.mode {
                            EntryMode::Blob => "100644",
                            EntryMode::BlobExecutable => "100755",
                            EntryMode::Link => "120000",
                            EntryMode::Tree => "040000",
                            EntryMode::Commit => "160000",
                        }
                        .to_string(),
                        obj: ShortObject::from((
                            &st.root,
                            &owner,
                            &name,
                            obj.kind(),
                            e.oid,
                        )),
                    }
                })
                .collect(),
        }),
        http::StatusCode::OK,
    )
    .into_response()
}
fn create_tree(
    _: Authorization,
    st: St,
    owner: String,
    name: String,
    req: TreeCreation,
) -> impl Reply {
    let mut db = Source::get();
    let tx = db.token_eager();
    guard!(let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Error::NotFound.into_response("git", "create-a-tree");
    });

    // TODO: what if oid is not valid, or not in repo, or not a tree?
    let empty_tree = git_object::Tree::empty();
    let mut tree: git_object::Tree = req
        .base_tree
        .and_then(|h| git_hash::ObjectId::from_hex(h.as_bytes()).ok())
        .and_then(|oid| crate::model::git::load(&tx, repo.network, &oid))
        .map(|o| o.into_tree())
        .unwrap_or(empty_tree);
    // make room for up to all the entries passed in
    tree.entries.reserve(req.tree.len());

    // TODO: does each entry need to be validated?
    for Entry { path, mode, item } in req.tree {
        let mode = match mode.as_str() {
            "100644" => EntryMode::Blob,
            "100755" => EntryMode::BlobExecutable,
            "120000" => EntryMode::Link,
            "040000" => EntryMode::Tree,
            "160000" => EntryMode::Commit,
            _ => unreachable!("check what happens on invalid mode"),
        };
        // TODO: do these need to be validated against the mode?
        let oid = match item {
            Item::Blob(BlobItem::Content { content }) => {
                crate::model::git::store(
                    &tx,
                    repo.network,
                    git_object::Blob {
                        data: content.into_bytes(),
                    },
                )
            }
            Item::Blob(BlobItem::Sha { sha })
            | Item::Commit { sha }
            | Item::Tree { sha } => {
                git_hash::ObjectId::from_hex(sha.as_bytes()).unwrap()
            }
        };
        // TODO: does the oid need to be checked against the repo? (probably duh)
        let entry = TreeEntry {
            mode,
            filename: path.into(),
            oid,
        };
        // might be better to replace all the existing entries
        // (by only searching inside the original slice),
        // append the new ones, then re-sort the
        // almost-entirely-sorted sequence
        match tree.entries.binary_search(&entry) {
            Ok(idx) => tree.entries[idx] = entry,
            Err(idx) => tree.entries.insert(idx, entry),
        }
    }

    let new_tree = crate::model::git::store(&tx, repo.network, tree);

    tx.commit().unwrap();
    reply::with_status(
        reply::json(&TreeResponse {
            sha: new_tree.to_hex().to_string(),
            url: String::new(),
            tree: Vec::new(),
            truncated: true,
        }),
        http::StatusCode::CREATED,
    )
    .into_response()
}
fn get_commit(
    _: Authorization,
    st: St,
    owner: String,
    name: String,
    cid: String,
) -> impl Reply {
    let mut db = Source::get();
    let tx = &db.token();
    guard!(let Some(repo) = crate::model::repos::by_name(tx, &owner, &name) else {
        return Error::NotFound.into_response("git", "get-a-commit");
    });

    let oid =
        git_hash::ObjectId::from_hex(cid.as_bytes()).expect("invalid sha");
    let obj = crate::model::git::load(tx, repo.network, &oid)
        .expect("unknown object");
    let commit = obj.into_commit();

    reply::with_status(
        reply::json(&super::Commit {
            sha: cid,
            node_id: None,
            message: commit.message.to_str_lossy().into_owned(),
            tree: super::Tree {
                sha: commit.tree.to_hex().to_string(),
                url: None,
            },
            parents: Some(
                commit
                    .parents
                    .into_iter()
                    .map(|oid| super::CommitLink {
                        sha: oid.to_hex().to_string(),
                        url: None,
                        html_url: None,
                    })
                    .collect(),
            ),
            author: Some(commit.author.to_ref().into()),
            committer: Some(commit.committer.to_ref().into()),
            url: format!(
                "{}/repos/{}/{}/git/commits/{}",
                st.root, owner, name, oid
            ),
            html_url: None,
        }),
        http::StatusCode::OK,
    )
    .into_response()
}
fn create_commit(
    auth: Authorization,
    st: St,
    owner: String,
    name: String,
    req: CommitReq,
) -> impl Reply {
    let mut db = Source::get();
    let tx = db.token_eager();
    // TODO: test error when trying to hit this endpoint unauth'd
    guard!(let Some(user) = crate::github::auth_to_user(&tx, auth) else {
        return Error::NotFound.into_response("git", "create-a-commit")
    });

    guard!(let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Error::NotFound.into_response("git", "create-a-commit");
    });

    let default_signature = git_actor::Signature {
        name: user.login.as_ref().into(),
        email: user
            .email
            .as_ref()
            .map(Cow::as_ref)
            .unwrap_or("user@example.org")
            .into(),
        time: git_actor::Time::now_utc(),
    };
    // FIXME: {author: null} should be an error, but missing should fallback
    //        github is stupid
    // FIXME: mostly duplicate of the one in contents
    let commit_oid = crate::model::git::store(
        &tx,
        repo.network,
        git_object::Commit {
            message: req.message.trim().into(),
            // FIXME: validate tree, and parents
            tree: git_hash::ObjectId::from_hex(req.tree.as_bytes()).unwrap(),
            parents: req
                .parents
                .iter()
                .map(|h| git_hash::ObjectId::from_hex(h.as_bytes()).unwrap())
                .collect(),
            author: req
                .author
                .map_or_else(|| default_signature.clone(), Into::into),
            committer: req.committer.map_or(default_signature, Into::into),
            encoding: None,
            extra_headers: Vec::new(),
        },
    );
    let commit = crate::model::git::load(&tx, repo.network, &commit_oid)
        .map(|o| o.into_commit())
        .unwrap();

    tx.commit().unwrap();
    reply::with_status(
        reply::json(&super::Commit {
            sha: commit_oid.to_hex().to_string(),
            node_id: None,
            message: commit.message.to_string(),
            tree: super::Tree {
                sha: commit.tree.to_hex().to_string(),
                url: None,
            },
            parents: Some(
                commit
                    .parents
                    .into_iter()
                    .map(|sha| super::CommitLink {
                        sha: sha.to_hex().to_string(),
                        url: None,
                        html_url: None,
                    })
                    .collect(),
            ),
            author: Some(commit.author.to_ref().into()),
            committer: Some(commit.committer.to_ref().into()),
            url: format!(
                "{}/repos/{}/{}/git/commits/{}",
                st.root, owner, name, commit_oid
            ),
            html_url: None,
        }),
        http::StatusCode::CREATED,
    )
    .into_response()
}

fn create_ref(
    _: Authorization,
    st: St,
    owner: String,
    name: String,
    req: RefReq,
) -> impl Reply {
    let mut db = Source::get();
    let tx = db.token_eager();

    if !req.r#ref.starts_with("refs/") {
        return Error::Unprocessable(
            "Reference name must start with 'refs/'.",
            &[],
        )
        .into_response("git", "create-a-reference");
    }
    if req.r#ref.matches('/').count() < 2 {
        return Error::Unprocessable(
            "Reference name must contain at least three slash-separated components.",
            &[],
        )
        .into_response("git", "create-a-reference");
    }

    guard!(let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Error::NotFound.into_response("git", "create-a-reference");
    });

    // FIXME: should fail for "empty repository" aka repo with no branches
    let oid = git_hash::ObjectId::from_hex(req.sha.as_bytes()).unwrap();
    guard!(let Some(obj) = crate::model::git::load(&tx, repo.network, &oid) else {
        return Error::Unprocessable("Object does not exist", &[])
            .into_response("git", "create-a-reference");
    });

    if req.r#ref.starts_with("refs/heads/") && obj.kind() != Kind::Commit {
        return Error::Unprocessable("Reference update failed", &[])
            .into_response("git", "create-a-reference");
    }
    if req.r#ref.starts_with("refs/tags/") && obj.kind() != Kind::Tag {
        return Error::Unprocessable("Reference update failed", &[])
            .into_response("git", "create-a-reference");
    }

    if crate::model::git::refs::resolve(&tx, repo.id, &req.r#ref).is_some() {
        return Error::Unprocessable("Reference already exists", &[])
            .into_response("git", "create-a-reference");
    } else {
        crate::model::git::refs::create(&tx, repo.id, &req.r#ref, &oid);
    };

    let url = format!("{}/repos/{}/{}/git/{}", st.root, owner, name, req.r#ref);
    tx.commit().unwrap();
    reply::with_status(
        reply::json(&RefResponse {
            r#ref: req.r#ref,
            node_id: String::new(),
            url,
            object: ShortObject::from((
                &st.root,
                &owner,
                &name,
                obj.kind(),
                oid,
            )),
        }),
        http::StatusCode::CREATED,
    )
    .into_response()
}
fn list_refs(
    _: Authorization,
    st: St,
    owner: String,
    name: String,
) -> impl Reply {
    // TODO: pagination
    // TODO: ordering
    let mut db = Source::get();
    let tx = &db.token();
    guard!(let Some(repo) = crate::model::repos::by_name(tx, &owner, &name) else {
        return Error::NotFound.into_response("git", "get-a-reference");
    });

    let mut refs = Vec::new();
    crate::model::git::refs::list(tx, repo.id, |refname, oid| {
        let obj = crate::model::git::load(tx, repo.network, oid)
            .expect("All refs should point to an object");
        refs.push(RefResponse {
            r#ref: refname.to_string(),
            node_id: String::new(),
            url: format!(
                "{}/repos/{}/{}/git/{}",
                st.root, owner, name, refname
            ),
            object: ShortObject::from((
                &st.root,
                &owner,
                &name,
                obj.kind(),
                oid.to_owned(),
            )),
        })
    });
    reply::with_status(reply::json(&refs), http::StatusCode::OK).into_response()
}
fn get_ref(
    _: Authorization,
    st: St,
    owner: String,
    name: String,
    ref_: path::Tail,
) -> impl Reply {
    let mut db = Source::get();
    let tx = &db.token();
    guard!(let Some(repo) = crate::model::repos::by_name(tx, &owner, &name) else {
        return Error::NotFound.into_response("git", "get-a-reference");
    });

    let refname = format!("refs/{}", ref_.as_str());
    guard!(let Some(oid) = crate::model::git::refs::resolve(tx, repo.id, &refname) else {
        return Error::NotFound.into_response("git", "get-a-reference");
    });

    let obj = crate::model::git::load(tx, repo.network, &oid)
        .expect("refs probably have to point to valid objects");

    let url = format!("{}/repos/{}/{}/git/{}", st.root, owner, name, refname);
    let sha = oid.to_string();
    reply::with_status(
        reply::json(&RefResponse {
            r#ref: refname,
            node_id: String::new(),
            url,
            object: ShortObject::from((
                &st.root,
                &owner,
                &name,
                obj.kind(),
                oid.to_owned(),
            )),
        }),
        http::StatusCode::OK,
    )
    .into_response()
}
fn update_ref(
    auth: Authorization,
    st: St,
    owner: String,
    name: String,
    ref_: path::Tail,
    req: RefUpdateRequest,
) -> impl Reply {
    let mut db = Source::get();
    let tx = db.token_eager();
    guard!(let Some(user) = crate::github::auth_to_user(&tx, auth) else {
        return Error::Unauthenticated("").into_response("git", "update-a-reference");
    });
    guard!(let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Error::NotFound.into_response("git", "update-a-reference");
    });

    // FIXME: should fail for "empty repository" aka repo with no branches (and objects?)
    // FIXME: what if branch is protected
    let refname = format!("refs/{}", ref_.as_str());
    // drop it to avoid using it, should only be using the normalised refname
    drop(ref_);
    guard!(let Some(current_oid) = crate::model::git::refs::resolve(&tx, repo.id, &refname) else {
        return Error::Unprocessable("Reference does not exist", &[])
            .into_response("git", "update-a-reference");
    });
    let new_oid = git_hash::ObjectId::from_hex(req.sha.as_bytes()).unwrap();
    guard!(let Some(new) = crate::model::git::load(&tx, repo.network, &new_oid) else {
        return Error::Unprocessable("Object does not exist", &[])
            .into_response("git", "update-a-reference");
    });

    let mut forced = false;
    let new_kind = new.kind();
    // updating a ref to itself is perfectly OK, and we can bypass the insert
    if new_oid != current_oid {
        // TODO: check whether it's the object type or the ref path
        //       which triggers the check
        if refname.starts_with("refs/heads/") {
            guard!(let Some(new) = new.as_commit() else {
                return Error::Unprocessable("Object is not a commit", &[])
                    .into_response("git", "update-a-reference")
            });
            if !crate::model::git::log(&tx, repo.network, &new_oid)
                .unwrap()
                .any(|oid| oid == current_oid)
            {
                if !req.force {
                    return Error::Unprocessable(
                        "Update is not a fast forward",
                        &[],
                    )
                    .into_response("git", "update-a-reference");
                }
                forced = true;
            }
        } else if refname.starts_with("refs/tags/") && new.kind() != Kind::Tag {
            return Error::Unprocessable("Object is not a tag", &[])
                .into_response("git", "update-a-reference");
        }

        crate::model::git::refs::update(
            &tx,
            repo.id,
            &refname,
            &current_oid,
            &new_oid,
        );

        if let Some(refname) = refname.strip_prefix("refs/heads/") {
            // Update PRs and send webhooks
            let branch: BranchRef = (repo.id, refname);
            find_and_update_pr(&tx, &st, &user, new_oid, branch, forced);
        }
    };
    tx.commit().unwrap();

    let url = format!("{}/repos/{}/{}/git/{}", st.root, owner, name, refname);
    reply::with_status(
        reply::json(&RefResponse {
            r#ref: refname,
            node_id: String::new(),
            url,
            object: ShortObject::from((
                &st.root, &owner, &name, new_kind, new_oid,
            )),
        }),
        http::StatusCode::OK,
    )
    .into_response()
}

/// Fully identify a branch to try and find a PR
/// (repo, branch_name)
pub type BranchRef<'a> = (RepositoryId, &'a str);
/// A ref has been updated, which may be the `head` of a PR in a repo
/// (the same or) an other). This thus requires checking in all repos whether
/// they have a PR from this branch, and cascading the update (as a synchronise
/// event + head update + magic ref + lock the PR in case of forced update)
pub fn find_and_update_pr(
    tx: &crate::model::Token,
    st: &super::Config,
    writer: &crate::github::User,
    new_oid: git_hash::ObjectId,
    (source_id, branchname): BranchRef,
    forced: bool,
) {
    let network = crate::model::repos::by_id(tx, source_id).network;
    let head_id = crate::model::git::get(tx, network, &new_oid).unwrap();
    let mut statement = tx
        .prepare(
            "
        UPDATE pull_requests AS p
        SET head = ?, dead = p.dead or (? and i.state = 'closed')
        FROM issues i
        WHERE p.repository = ? AND p.branch = ? AND i.id = p.issue
        RETURNING issue
    ",
        )
        .unwrap();
    let prs = statement
        .query_map((*head_id, forced, *source_id, branchname), |row| {
            row.get("issue").map(PullRequestId::unsafe_from)
        })
        .unwrap();

    for pr_id in prs {
        let pr_id = pr_id.unwrap();
        let issue = crate::model::prs::get_issue(tx, pr_id.into());

        crate::model::git::refs::set(
            tx,
            issue.repository.id,
            &format!("refs/pull/{}/head", issue.number),
            &new_oid,
        );

        let repo = issue.repository;
        super::send_hook(tx, repo, st, HookEvent::PullRequest, writer, || {
            webhooks::WebhookEvent::PullRequest(webhooks::PullRequest {
                action: webhooks::PullRequestAction::Synchronize,
                number: issue.number,
                pull_request: super::issues::pr_response(tx, st, pr_id),
            })
        });
    }
}

fn delete_ref(
    _: Authorization,
    st: St,
    owner: String,
    name: String,
    ref_: path::Tail,
) -> impl Reply {
    let mut db = Source::get();
    let tx = db.token_eager();
    guard!(let Some(repo_id) = crate::model::repos::id_by_name(&tx, &owner, &name) else {
        return Error::NotFound.into_response("git", "delete-a-reference");
    });
    // FIXME: what if a PR from this ref exists?

    let refname = format!("refs/{}", ref_.as_str());
    if crate::model::git::refs::delete_unchecked(&tx, repo_id, &refname) {
        tx.commit().unwrap();
        http::StatusCode::NO_CONTENT.into_response()
    } else {
        Error::Unprocessable("Reference does not exist", &[])
            .into_response("git", "delete-a-reference")
    }
}
