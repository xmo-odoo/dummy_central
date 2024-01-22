use std::borrow::Cow;
use std::collections::HashMap;

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router, http};
use base64::prelude::{Engine as _, BASE64_STANDARD};
use gix_object::bstr::ByteSlice;
use gix_object::tree::{Entry as TreeEntry, EntryKind};
use gix_object::{Kind, WriteTo as _};
use tracing::instrument;

pub use github_types::git::*;
use github_types::repos::HookEvent;
use github_types::webhooks;

use crate::github::{Authorization, Error, GHError, St};
use crate::model::prs::PullRequestId;
use crate::model::repos::RepositoryId;
use crate::model::Source;

#[rustfmt::skip]
pub fn routes() -> Router<St> {
    Router::new()
        .route("/blobs", post(create_blob))
        .route("/blobs/:id", get(get_blob))
        .route("/trees/:id", get(get_tree))
        .route("/trees", post(create_tree))
        .route("/commits/:id", get(get_commit))
        .route("/commits", post(create_commit))
        .route("/refs", get(list_refs).post(create_ref))
        .route("/ref/*refname", get(get_ref))
        .route("/refs/*refname", get(get_ref).patch(update_ref).delete(delete_ref))
}

#[instrument(skip(st), err(Debug))]
async fn create_blob(
    State(st): State<St>,
    Path((owner, name)): Path<(String, String)>,
    Json(req): Json<CreateBlobRequest>,
) -> Result<(http::StatusCode, Json<CreateBlobResponse>), GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token_eager();
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "blob",
            "create-a-blob",
        ));
    };

    let oid = crate::model::git::store(
        &tx,
        repo.network,
        gix_object::BlobRef::from_bytes(&req.as_bytes()).unwrap(),
    );

    tx.commit().unwrap();
    Ok((
        http::StatusCode::CREATED,
        Json(CreateBlobResponse {
            sha: oid.to_string(),
            url: format!(
                "{}/repos/{}/{}/git/blobs/{}",
                st.root, owner, name, oid
            ),
        }),
    ))
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
#[instrument(skip(st), err(Debug))]
async fn get_blob(
    State(st): State<St>,
    Path((owner, name, blob_id)): Path<(String, String, String)>,
) -> Result<Json<BlobResponse>, GHError<'static>> {
    let mut db = Source::get();
    let tx = &db.token();
    let Some(repo) = crate::model::repos::by_name(tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "blob",
            "get-a-blob",
        ));
    };

    let Some(object) = gix_hash::ObjectId::from_hex(blob_id.as_bytes())
        .ok()
        .and_then(|oid| crate::model::git::load(tx, repo.network, &oid))
    else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "blob",
            "get-a-blob",
        ));
    };
    let blob = object.into_blob();
    let url =
        format!("{}/repos/{}/{}/git/blobs/{}", st.root, owner, name, blob_id);
    Ok(Json(BlobResponse::Base64 {
        node_id: String::new(),
        _id: CreateBlobResponse { sha: blob_id, url },
        content: gh_base64_encode(&blob.data),
        size: blob.data.len(),
    }))
}

#[instrument(skip(st), err(Debug))]
async fn get_tree(
    State(st): State<St>,
    Path((owner, name, tree_id)): Path<(String, String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<TreeResponse>, GHError<'static>> {
    let mut db = Source::get();
    let tx = &db.token();
    let Some(repo) = crate::model::repos::by_name(tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "tree",
            "get-a-tree",
        ));
    };

    // todo: invalid oid? missing tree?
    let t = gix_hash::ObjectId::from_hex(tree_id.as_bytes())
        .ok()
        .and_then(|oid| crate::model::git::load(tx, repo.network, &oid));
    let Some(tree) = t else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "tree",
            "get-a-tree",
        ));
    };
    let tree = tree.into_tree();

    // TODO: check if the trigger is having the query
    //       parameter at all or having a non-empty value
    if query.get("recursive").map_or("", |s| &**s) != "" {
        // TODO: recursive
    }
    Ok(Json(TreeResponse {
        sha: tree_id,
        url: String::new(),
        truncated: false,
        tree: tree
            .entries
            .iter()
            .map(|e| {
                let obj =
                    crate::model::git::load(tx, repo.network, &e.oid).unwrap();
                TreeResponseEntry {
                    path: e.filename.to_string(),
                    size: obj.size() as _,
                    mode: match e.mode.kind() {
                        EntryKind::Blob => "100644",
                        EntryKind::BlobExecutable => "100755",
                        EntryKind::Link => "120000",
                        EntryKind::Tree => "040000",
                        EntryKind::Commit => "160000",
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
    }))
}

#[instrument(err(Debug))]
async fn create_tree(
    State(_): State<St>,
    Path((owner, name)): Path<(String, String)>,
    Json(req): Json<TreeCreation>,
) -> Result<(http::StatusCode, Json<TreeResponse>), GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token_eager();
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "tree",
            "create-a-tree",
        ));
    };

    // TODO: what if oid is not valid, or not in repo, or not a tree?
    let empty_tree = gix_object::Tree::empty();
    let mut tree: gix_object::Tree = req
        .base_tree
        .and_then(|h| gix_hash::ObjectId::from_hex(h.as_bytes()).ok())
        .and_then(|oid| crate::model::git::load(&tx, repo.network, &oid))
        .map_or(empty_tree, |o| o.into_tree());
    // make room for up to all the entries passed in
    tree.entries.reserve(req.tree.len());

    // TODO: does each entry need to be validated?
    for Entry { path, mode, item } in req.tree {
        let mode = match mode.as_str() {
            "100644" => EntryKind::Blob,
            "100755" => EntryKind::BlobExecutable,
            "120000" => EntryKind::Link,
            "040000" => EntryKind::Tree,
            "160000" => EntryKind::Commit,
            _ => unreachable!("check what happens on invalid mode"),
        }
        .into();
        // TODO: do these need to be validated against the mode?
        let oid = match item {
            Item::Blob(BlobItem::Content { content }) => {
                crate::model::git::store(
                    &tx,
                    repo.network,
                    gix_object::Blob {
                        data: content.into_bytes(),
                    },
                )
            }
            Item::Blob(BlobItem::Sha { sha })
            | Item::Commit { sha }
            | Item::Tree { sha } => {
                gix_hash::ObjectId::from_hex(sha.as_bytes()).unwrap()
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

    Ok((
        http::StatusCode::CREATED,
        Json(TreeResponse {
            sha: new_tree.to_hex().to_string(),
            url: String::new(),
            tree: Vec::new(),
            truncated: true,
        }),
    ))
}

#[instrument(skip(st), err(Debug))]
async fn get_commit(
    State(st): State<St>,
    Path((owner, name, cid)): Path<(String, String, String)>,
) -> Result<Json<super::Commit>, GHError<'static>> {
    let mut db = Source::get();
    let tx = &db.token();
    let Some(repo) = crate::model::repos::by_name(tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "commit",
            "get-a-commit",
        ));
    };

    let not_found = || {
        let msg = format!("No commit found for SHA: {cid}");
        return Error::Unprocessable(msg.into(), &[]).into_response(
            "commits",
            "commits",
            "get-a-commit",
        );
    };
    let oid = gix_hash::ObjectId::from_hex(cid.as_bytes())
        .map_err(|_| not_found())?;
    let commit = crate::model::git::load(tx, repo.network, &oid)
        .and_then(|obj| obj.try_into_commit().ok())
        .ok_or_else(not_found)?;

    Ok(Json(super::Commit {
        sha: cid,
        node_id: None,
        message: String::from_utf8_lossy(commit.message.trim()).to_string(),
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
    }))
}

#[instrument(skip(st), err(Debug))]
async fn create_commit(
    auth: Authorization,
    State(st): State<St>,
    Path((owner, name)): Path<(String, String)>,
    Json(req): Json<CommitReq>,
) -> Result<(http::StatusCode, Json<super::Commit>), GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token_eager();
    // TODO: test error when trying to hit this endpoint unauth'd
    let Some(user) = crate::github::auth_to_user(&tx, auth) else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "commit",
            "create-a-commit",
        ));
    };

    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "commit",
            "create-a-commit",
        ));
    };

    let default_signature = gix_actor::Signature {
        name: user.login.as_ref().into(),
        email: user
            .email
            .as_ref()
            .map_or("user@example.org", Cow::as_ref)
            .into(),
        time: gix_date::Time::now_utc(),
    };
    // FIXME: {author: null} should be an error, but missing should fallback
    //        github is stupid
    // FIXME: mostly duplicate of the one in contents
    let commit = gix_object::Commit {
        message: req.message.trim().into(),
        // FIXME: validate tree, and parents
        tree: gix_hash::ObjectId::from_hex(req.tree.as_bytes()).unwrap(),
        parents: req
            .parents
            .iter()
            .map(|h| gix_hash::ObjectId::from_hex(h.as_bytes()).unwrap())
            .collect(),
        author: req
            .author
            .map_or_else(|| default_signature.clone(), Into::into),
        committer: req.committer.map_or(default_signature, Into::into),
        encoding: None,
        extra_headers: Vec::new(),
    };
    let commit_oid = crate::model::git::store(&tx, repo.network, &commit);

    tx.commit().unwrap();

    Ok((
        http::StatusCode::CREATED,
        Json(super::Commit {
            sha: commit_oid.to_hex().to_string(),
            node_id: None,
            message: String::from_utf8_lossy(commit.message.trim()).to_string(),
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
    ))
}

#[instrument(skip(st), err(Debug))]
async fn create_ref(
    State(st): State<St>,
    Path((owner, name)): Path<(String, String)>,
    Json(req): Json<RefReq>,
) -> Result<(http::StatusCode, Json<RefResponse>), GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token_eager();

    if !req.r#ref.starts_with("refs/") {
        return Err(Error::unprocessable(
            "Reference name must start with 'refs/'.",
            &[],
        )
        .into_response("git", "refs", "create-a-reference"));
    }
    if req.r#ref.matches('/').count() < 2 {
        return Err(Error::unprocessable(
            "Reference name must contain at least three slash-separated components.",
            &[],
        )
        .into_response("git", "refs", "create-a-reference"));
    }

    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "refs",
            "create-a-reference",
        ));
    };

    // FIXME: should fail for "empty repository" aka repo with no branches
    let oid = gix_hash::ObjectId::from_hex(req.sha.as_bytes()).unwrap();
    let Some(obj) = crate::model::git::load(&tx, repo.network, &oid) else {
        return Err(Error::unprocessable("Object does not exist", &[])
            .into_response("git", "refs", "create-a-reference"));
    };

    if req.r#ref.starts_with("refs/heads/") && obj.kind() != Kind::Commit {
        return Err(Error::unprocessable("Reference update failed", &[])
            .into_response("git", "refs", "create-a-reference"));
    }
    if req.r#ref.starts_with("refs/tags/") && obj.kind() != Kind::Tag {
        return Err(Error::unprocessable("Reference update failed", &[])
            .into_response("git", "refs", "create-a-reference"));
    }

    if crate::model::git::refs::resolve(&tx, repo.id, &req.r#ref).is_some() {
        return Err(Error::unprocessable("Reference already exists", &[])
            .into_response("git", "refs", "create-a-reference"));
    }
    crate::model::git::refs::create(&tx, repo.id, &req.r#ref, &oid);

    let url = format!("{}/repos/{}/{}/git/{}", st.root, owner, name, req.r#ref);
    tx.commit().unwrap();

    Ok((
        http::StatusCode::CREATED,
        Json(RefResponse {
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
    ))
}

#[instrument(skip(st), err(Debug))]
async fn list_refs(
    State(st): State<St>,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Json<Vec<RefResponse>>, GHError<'static>> {
    // TODO: pagination
    // TODO: ordering
    let mut db = Source::get();
    let tx = &db.token();
    let Some(repo) = crate::model::repos::by_name(tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "refs",
            "get-a-reference",
        ));
    };

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
        });
    });
    Ok(Json(refs))
}

#[instrument(skip(st), err(Debug))]
async fn get_ref(
    State(st): State<St>,
    Path((owner, name, ref_)): Path<(String, String, String)>,
) -> Result<Json<RefResponse>, GHError<'static>> {
    let mut db = Source::get();
    let tx = &db.token();
    let Some(repo) = crate::model::repos::by_name(tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "refs",
            "get-all-references-in-a-namespace",
        ));
    };

    let refname = format!("refs/{}", ref_.as_str());
    let Some(oid) = crate::model::git::refs::resolve(tx, repo.id, &refname)
    else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "refs",
            "get-all-references-in-a-namespace",
        ));
    };

    let obj = crate::model::git::load(tx, repo.network, &oid)
        .expect("refs probably have to point to valid objects");

    let url = format!("{}/repos/{}/{}/git/{}", st.root, owner, name, refname);
    Ok(Json(RefResponse {
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
    }))
}

#[instrument(skip(st), err(Debug))]
async fn update_ref(
    auth: Authorization,
    State(st): State<St>,
    Path((owner, name, ref_)): Path<(String, String, String)>,
    Json(req): Json<RefUpdateRequest>,
) -> Result<Json<RefResponse>, GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token_eager();
    let Some(user) = crate::github::auth_to_user(&tx, auth) else {
        return Err(Error::Unauthenticated("").into_response(
            "git",
            "refs",
            "update-a-reference",
        ));
    };
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "refs",
            "update-a-reference",
        ));
    };

    // FIXME: should fail for "empty repository" aka repo with no branches (and objects?)
    // FIXME: what if branch is protected
    let refname = format!("refs/{}", ref_.as_str());
    // drop it to avoid using it, should only be using the normalised refname
    drop(ref_);
    let Some(current_oid) =
        crate::model::git::refs::resolve(&tx, repo.id, &refname)
    else {
        return Err(Error::unprocessable("Reference does not exist", &[])
            .into_response("git", "refs", "update-a-reference"));
    };
    let new_oid = gix_hash::ObjectId::from_hex(req.sha.as_bytes()).unwrap();
    let Some(new) = crate::model::git::load(&tx, repo.network, &new_oid) else {
        return Err(Error::unprocessable("Object does not exist", &[])
            .into_response("git", "refs", "update-a-reference"));
    };

    let mut forced = false;
    let new_kind = new.kind();
    // updating a ref to itself is perfectly OK, and we can bypass the insert
    if new_oid != current_oid {
        // TODO: check whether it's the object type or the ref path
        //       which triggers the check
        if refname.starts_with("refs/heads/") {
            let Some(_new) = new.as_commit() else {
                return Err(Error::unprocessable(
                    "Object is not a commit",
                    &[],
                )
                .into_response(
                    "git",
                    "refs",
                    "update-a-reference",
                ));
            };
            if !crate::model::git::log(&tx, repo.network, &new_oid)
                .expect("new_oid should exist because we checked it at #545")
                .any(|oid| oid == current_oid)
            {
                if !req.force {
                    return Err(Error::unprocessable(
                        "Update is not a fast forward",
                        &[],
                    )
                    .into_response(
                        "git",
                        "refs",
                        "update-a-reference",
                    ));
                }
                forced = true;
            }
        } else if refname.starts_with("refs/tags/") && new.kind() != Kind::Tag {
            return Err(Error::unprocessable("Object is not a tag", &[])
                .into_response("git", "refs", "update-a-reference"));
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
    Ok(Json(RefResponse {
        r#ref: refname,
        node_id: String::new(),
        url,
        object: ShortObject::from((&st.root, &owner, &name, new_kind, new_oid)),
    }))
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
    new_oid: gix_hash::ObjectId,
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

#[instrument(err(Debug))]
async fn delete_ref(
    State(_): State<St>,
    Path((owner, name, ref_)): Path<(String, String, String)>,
) -> Result<http::StatusCode, GHError<'static>> {
    let mut db = Source::get();
    let tx = db.token_eager();
    let Some(repo_id) = crate::model::repos::id_by_name(&tx, &owner, &name)
    else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "refs",
            "delete-a-reference",
        ));
    };
    // FIXME: what if a PR from this ref exists?

    let refname = format!("refs/{}", ref_.as_str());
    if crate::model::git::refs::delete_unchecked(&tx, repo_id, &refname) {
        tx.commit().unwrap();
        Ok(http::StatusCode::NO_CONTENT)
    } else {
        Err(Error::unprocessable("Reference does not exist", &[])
            .into_response("git", "refs", "delete-a-reference"))
    }
}
