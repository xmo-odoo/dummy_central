use std::borrow::Cow;

use axum::extract::{Path, RawQuery, State};
use axum::routing::{get, post};
use axum::{Json, Router, http};
use base64::prelude::{BASE64_STANDARD, Engine as _};
use github_types::pulls::PullRequestResponse;
use gix_object::bstr::ByteSlice;
use gix_object::tree::EntryKind;
use gix_object::{Kind, WriteTo as _};
use serde_json::Value;
use tracing::instrument;

pub use github_types::git::*;
use github_types::repos::HookEvent;
use github_types::webhooks;

use crate::github::{Authorization, Error, GHError, GithubErrorDetails, St};
use crate::model::prs::{self, PullRequestId};
use crate::model::repos::RepositoryId;
use crate::model::{Read, Token, Write};

mod create_tree;

#[rustfmt::skip]
pub fn routes() -> Router<St> {
    Router::new()
        .route("/blobs", post(create_blob))
        .route("/blobs/{id}", get(get_blob))
        .route("/trees/{id}", get(get_tree))
        .route("/trees", post(create_tree))
        .route("/commits/{id}", get(get_commit))
        .route("/commits", post(create_commit))
        .route("/refs", get(list_refs).post(create_ref))
        .route("/ref/{*refname}", get(get_ref))
        .route("/refs/{*refname}", get(get_ref).patch(update_ref).delete(delete_ref))
}

#[instrument(skip(st, tx))]
async fn create_blob(
    State(st): State<St>,
    Path((owner, name)): Path<(String, String)>,
    tx: Token<Write>,
    Json(req): Json<CreateBlobRequest>,
) -> Result<(http::StatusCode, Json<CreateBlobResponse>), GHError<'static>> {
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "blobs",
            "create-a-blob",
        ));
    };

    if crate::model::git::get_objects(&tx, repo.network).is_empty() {
        return Err(Error::Conflict("Git Repository is empty.", None)
            .into_response("git", "blobs", "create-a-blob"));
    }

    let oid = crate::model::git::store(
        &tx,
        repo.network,
        gix_object::BlobRef::from_bytes(&req.as_bytes()).unwrap(),
    );

    tx.commit();
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
#[instrument(skip(st, tx))]
async fn get_blob(
    State(st): State<St>,
    Path((owner, name, blob_id)): Path<(String, String, String)>,
    tx: Token<Read>,
) -> Result<Json<BlobResponse>, GHError<'static>> {
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "blob",
            "get-a-blob",
        ));
    };

    let Some(object) = gix_hash::ObjectId::from_hex(blob_id.as_bytes())
        .ok()
        .and_then(|oid| crate::model::git::load(&tx, repo.network, &oid))
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

#[instrument(skip(st, tx))]
async fn get_tree(
    State(st): State<St>,
    Path((owner, name, tree_id)): Path<(String, String, String)>,
    tx: Token<Read>,
    RawQuery(query): RawQuery,
) -> Result<Json<TreeResponse>, GHError<'static>> {
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "tree",
            "get-a-tree",
        ));
    };

    // TODO: invalid oid?
    let Some(oid) = gix_hash::ObjectId::from_hex(tree_id.as_bytes())
        .ok()
        // TODO: full rev-parse? And deref until tree?
        .or_else(|| {
            crate::model::git::refs::resolve(
                &tx,
                repo.id,
                &format!("refs/heads/{tree_id}"),
            )
        })
    else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "tree",
            "get-a-tree",
        ));
    };
    let Some(entries) = crate::model::git::load_tree(&tx, repo.network, &oid)
    else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "tree",
            "get-a-tree",
        ));
    };

    // github treats `?recursive` as false but `?recursive=` as true
    let recursive = query
        .unwrap_or(String::new())
        .split('&')
        .any(|s| s.starts_with("recursive="));

    Ok(Json(tree_to_response(
        &st,
        &owner,
        &name,
        &tx,
        &repo,
        oid.to_string(),
        entries,
        recursive,
    )))
}

#[allow(clippy::too_many_arguments)]
fn tree_to_response<M>(
    st: &St,
    owner: &String,
    name: &String,
    tx: &crate::model::Token<M>,
    repo: &crate::model::repos::Repository,
    tree_id: String,
    entries: impl IntoIterator<Item = gix_object::tree::Entry>,
    recursive: bool,
) -> TreeResponse {
    let mut entries: std::collections::VecDeque<_> =
        entries.into_iter().collect();
    TreeResponse {
        sha: tree_id,
        url: String::new(),
        truncated: false,
        tree: std::iter::from_fn(move || {
            let e = entries.pop_front()?;
            let (size, obj) = if e.mode.kind() == EntryKind::Commit {
                // FIXME: should probably be the remote-repo URL?
                (
                    None,
                    ShortObject {
                        r#type: "commit",
                        sha: e.oid.to_string(),
                        url: String::new(),
                    },
                )
            } else {
                let obj = crate::model::git::load(tx, repo.network, &e.oid)
                    .expect("invalid tree: object not found");
                let size = obj.size() as _;
                let kind = obj.kind();
                if recursive && let gix_object::Object::Tree(tree) = obj {
                    for mut child in tree.entries.into_iter().rev() {
                        child.filename = [
                            e.filename.as_slice(),
                            b"/",
                            child.filename.as_slice(),
                        ]
                        .concat()
                        .into();
                        entries.push_front(child);
                    }
                }
                (
                    Some(size),
                    ShortObject::from((&st.root, owner, name, kind, e.oid)),
                )
            };

            Some(TreeResponseEntry {
                path: e.filename.to_string(),
                size,
                mode: match e.mode.kind() {
                    EntryKind::Blob => "100644",
                    EntryKind::BlobExecutable => "100755",
                    EntryKind::Link => "120000",
                    EntryKind::Tree => "040000",
                    EntryKind::Commit => "160000",
                }
                .to_string(),
                obj,
            })
        })
        .collect(),
    }
}

#[instrument(skip(st, tx))]
async fn create_tree(
    State(st): State<St>,
    Path((owner, name)): Path<(String, String)>,
    tx: Token<Write>,
    Json(req): Json<TreeCreation>,
) -> Result<(http::StatusCode, Json<TreeResponse>), GHError<'static>> {
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "trees",
            "create-a-tree",
        ));
    };

    let new_tree = {
        let Ok(Some(mut tt)) = req
            .base_tree
            .as_ref()
            // don't flatten because we need to differentiate between a missing oid (None)
            // and an invalid oid (Some(Err(...)))
            .map(|h| gix_hash::ObjectId::from_hex(h.as_bytes()))
            .transpose()
            .map(|base_tree| {
                create_tree::TransientTree::new(&tx, &repo, base_tree)
            })
        else {
            return Err(Error::unprocessable(
                "base_tree is not a valid tree oid",
                &[],
            )
            .into_response("git", "trees", "create-a-tree"));
        };

        for e in req.tree {
            if e.path.starts_with('/') {
                return Err(Error::unprocessable(
                    "tree.path cannot start with a slash",
                    &[],
                )
                .into_response("git", "trees", "create-a-tree"));
            }
            tt.add(e).map_err(|err| {
                Error::Unprocessable(err.to_string().into(), &[]).into_response(
                    "git",
                    "trees",
                    "create-a-tree",
                )
            })?;
        }
        tt.save()
    };

    tx.commit();
    let tx = Token::<Read>::get().await.unwrap();

    Ok((
        http::StatusCode::CREATED,
        Json(tree_to_response(
            &st,
            &owner,
            &name,
            &tx,
            &repo,
            new_tree.to_string(),
            crate::model::git::load(&tx, repo.network, &new_tree)
                .unwrap()
                .into_tree()
                .entries,
            false,
        )),
    ))
}

#[instrument(skip(st, tx))]
async fn get_commit(
    State(st): State<St>,
    Path((owner, name, cid)): Path<(String, String, String)>,
    tx: Token<Read>,
) -> Result<Json<super::Commit>, GHError<'static>> {
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "commit",
            "get-a-commit",
        ));
    };

    let not_found = || {
        let msg = format!("No commit found for SHA: {cid}");
        Error::Unprocessable(msg.into(), &[]).into_response(
            "commits",
            "commits",
            "get-a-commit",
        )
    };
    let oid = gix_hash::ObjectId::from_hex(cid.as_bytes())
        .map_err(|_| not_found())?;
    let commit = crate::model::git::load(&tx, repo.network, &oid)
        .and_then(|obj| obj.try_into_commit().ok())
        .ok_or_else(not_found)?;

    let mut time_buf = Default::default();
    Ok(Json(super::Commit {
        sha: cid,
        node_id: None,
        message: String::from_utf8_lossy(commit.message.trim()).to_string(),
        tree: super::Tree {
            sha: commit.tree.to_string(),
            url: None,
        },
        parents: commit
            .parents
            .into_iter()
            .map(|oid| super::CommitLink {
                sha: oid.to_string(),
                url: format!(
                    "{}/repos/{}/{}/git/commits/{}",
                    st.root, owner, name, oid
                ),
                html_url: None,
            })
            .collect(),
        author: Some(commit.author.to_ref(&mut time_buf).into()),
        committer: Some(commit.committer.to_ref(&mut time_buf).into()),
        url: format!(
            "{}/repos/{}/{}/git/commits/{}",
            st.root, owner, name, oid
        ),
        html_url: None,
    }))
}

static FAILED_NAME: GithubErrorDetails<'static> =
    Error::details("author", "name", "missing_field", "");
static FAILED_EMAIL: GithubErrorDetails<'static> =
    Error::details("author", "email", "missing_field", "");
static FAILED_BOTH: &[GithubErrorDetails<'_>] = &[FAILED_NAME, FAILED_EMAIL];

#[instrument(skip(st, tx))]
async fn create_commit(
    auth: Authorization,
    State(st): State<St>,
    tx: Token<Write>,
    Path((owner, name)): Path<(String, String)>,
    Json(req): Json<Value>,
) -> Result<(http::StatusCode, Json<super::Commit>), GHError<'static>> {
    // TODO: test error when trying to hit this endpoint with invalid auth
    let Some(user) = crate::github::auth_to_user(&tx, auth) else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "commits",
            "create-a-commit",
        ));
    };

    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "commits",
            "create-a-commit",
        ));
    };

    match req.get("tree") {
        None => Err(Error::unprocessable(
            "Invalid request.\n\n\"tree\" wasn't supplied.",
            &[],
        )),
        Some(Value::String(_)) => Ok(()),
        Some(_) => Err(Error::unprocessable(
            "Invalid request.\n\nFor 'properties/tree', nil is not a string.",
            &[],
        )),
    }
    .map_err(|e| e.into_response("git", "commits", "create-a-commit"))?;

    if let Some(Value::Object(a)) = req.get("author") {
        match (a.get("email"), a.get("name")) {
            (Some(Value::String(e)), Some(Value::String(n))) => {
                if e.is_empty() || n.is_empty() {
                    Err(Error::unprocessable("Validation Failed",
                        if e.is_empty() && n.is_empty() {
                            FAILED_BOTH
                        } else if e.is_empty() {
                            std::slice::from_ref(&FAILED_EMAIL)
                        } else {
                            std::slice::from_ref(&FAILED_NAME)
                        }
                    ))
                } else {
                    Ok(())
                }
            }
            (_, Some(Value::String(_))) => Err(Error::unprocessable(
                "Invalid request.\n\nFor 'properties/email', nil is not a string.",
                &[],
            )),
            (Some(Value::String(_)), _) => Err(Error::unprocessable(
                "Invalid request.\n\nFor 'properties/name', nil is not a string.",
                &[],
            )),
            (_, _) => Err(Error::unprocessable(
                "Invalid request.\n\nFor 'properties/email', nil is not a string.\nFor 'properties/name', nil is not a string.",
                &[],
            )),
        }.map_err(|e| e.into_response("git", "commits", "create-a-commit"))?;
    }

    let default_signature = gix_actor::Signature {
        name: user.login.as_ref().into(),
        email: user
            .email
            .as_ref()
            .map_or("user@example.org", Cow::as_ref)
            .into(),
        time: gix_date::Time::now_utc(),
    };

    let req = serde_json::from_value::<CommitReq>(req).unwrap();

    let author = match req.author {
        None => default_signature.clone(),
        Some(None) => return Err(Error::unprocessable(
            "Invalid request.\n\nFor 'properties/author', nil is not an object.",
            &[],
        ).into_response("git", "commits", "create-a-commit")),
        Some(Some(a)) => a.try_into().map_err(|a: Authorship| Error::Unprocessable(
            format!(
                "Invalid request.\n\n{} is not a valid date-time.",
                a.date.expect("a date parsing error implies we have a date"),
            ).into(),
            &[]
        ).into_response("git", "commits", "create-a-commit"))?,
    };

    let commit = gix_object::Commit {
        message: req.message.trim().into(),
        tree: gix_hash::ObjectId::from_hex(req.tree.as_bytes())
            .map_err(|_| Error::unprocessable(
                "The tree parameter must be exactly 40 characters and contain only [0-9a-f].",
                &[],
            ))
            .and_then(|oid|
                crate::model::git::load(&tx, repo.network, &oid)
                    .filter(|o| o.kind() == gix_object::Kind::Tree)
                    .ok_or_else(|| Error::unprocessable(
                        "Tree SHA does not exist",
                        &[]
                    ))
                    .map(|_| oid)
            )
            .map_err(|e| e.into_response("git", "commits", "create-a-commit"))?,
        parents: req
            .parents
            .iter()
            .map(|h| {
                let oid = gix_hash::ObjectId::from_hex(h.as_bytes())
                    .expect("github just returns a 500 with no body");
                crate::model::git::load(&tx, repo.network, &oid)
                    .filter(|o| o.kind() == gix_object::Kind::Commit)
                    .ok_or_else(|| Error::unprocessable(
                        "Parent SHA does not exist or is not a commit object",
                        &[]
                    ))
                    .map(|_| oid)
            })
            .collect::<Result<_, _>>()
            .map_err(|e| e.into_response("git", "commits", "create-a-commit"))?,
        author,
        committer: req.committer.map_or(
            Ok(default_signature),
            |c| c.try_into(),
        ).map_err(|c| Error::Unprocessable(
            format!(
                "Invalid request.\n\n{} is not a valid date-time.",
                c.date.expect("a date parsing error implies we have a date"),
            ).into(),
            &[]
        ).into_response("git", "commits", "create-a-commit"))?,
        encoding: None,
        extra_headers: Vec::new(),
    };
    let commit_oid = crate::model::git::store(&tx, repo.network, &commit);

    tx.commit();

    let mut time_buf = Default::default();
    Ok((
        http::StatusCode::CREATED,
        Json(super::Commit {
            sha: commit_oid.to_string(),
            node_id: None,
            message: String::from_utf8_lossy(commit.message.trim()).to_string(),
            tree: super::Tree {
                sha: commit.tree.to_string(),
                url: None,
            },
            parents: commit
                .parents
                .into_iter()
                .map(|sha| super::CommitLink {
                    sha: sha.to_string(),
                    url: format!(
                        "{}/repos/{}/{}/git/commits/{}",
                        st.root, owner, name, sha
                    ),
                    html_url: None,
                })
                .collect(),
            author: Some(commit.author.to_ref(&mut time_buf).into()),
            committer: Some(commit.committer.to_ref(&mut time_buf).into()),
            url: format!(
                "{}/repos/{}/{}/git/commits/{}",
                st.root, owner, name, commit_oid
            ),
            html_url: None,
        }),
    ))
}

#[instrument(skip(st, tx))]
async fn create_ref(
    State(st): State<St>,
    tx: Token<Write>,
    Path((owner, name)): Path<(String, String)>,
    Json(req): Json<RefReq>,
) -> Result<(http::StatusCode, Json<RefResponse>), GHError<'static>> {
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

    if crate::model::git::get_objects(&tx, repo.network).is_empty() {
        return Err(Error::Conflict("Git Repository is empty.", None)
            .into_response("git", "refs", "create-a-reference"));
    }

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
    if !crate::model::git::refs::create(&tx, &repo, &req.r#ref, &oid) {
        return Err(Error::unprocessable("Reference update failed", &[])
            .into_response("git", "refs", "create-a-reference"));
    };

    let url = format!("{}/repos/{}/{}/git/{}", st.root, owner, name, req.r#ref);
    tx.commit();

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

#[instrument(skip(st, tx))]
async fn list_refs(
    State(st): State<St>,
    Path((owner, name)): Path<(String, String)>,
    tx: Token<Read>,
) -> Result<Json<Vec<RefResponse>>, GHError<'static>> {
    // TODO: pagination
    // TODO: ordering
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "refs",
            "get-a-reference",
        ));
    };
    let mut refs = Vec::new();
    crate::model::git::refs::list(&tx, repo.id, |refname, oid| {
        let obj = crate::model::git::load(&tx, repo.network, oid)
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

#[instrument(skip(st, tx))]
async fn get_ref(
    State(st): State<St>,
    Path((owner, name, ref_)): Path<(String, String, String)>,
    tx: Token<Read>,
) -> Result<Json<RefResponse>, GHError<'static>> {
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "refs",
            "get-all-references-in-a-namespace",
        ));
    };

    let refname = format!("refs/{}", ref_.as_str());
    let Some(oid) = crate::model::git::refs::resolve(&tx, repo.id, &refname)
    else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "refs",
            "get-all-references-in-a-namespace",
        ));
    };
    let obj = crate::model::git::load(&tx, repo.network, &oid)
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

#[instrument(skip(st, tx))]
async fn update_ref(
    auth: Authorization,
    State(st): State<St>,
    Path((owner, name, ref_)): Path<(String, String, String)>,
    tx: Token<Write>,
    Json(req): Json<RefUpdateRequest>,
) -> Result<Json<RefResponse>, GHError<'static>> {
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
    if new_oid == current_oid {
        drop(tx);
    } else {
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

        if !crate::model::git::refs::update(
            &tx,
            &repo,
            &refname,
            &current_oid,
            &new_oid,
        ) {
            return Err(Error::unprocessable("Repository rule violations found\n\nCannot update this protected ref.\n\n", &[])
                .into_response("git", "refs", "update-a-reference"));
        };

        if let Some(refname) = refname.strip_prefix("refs/heads/") {
            // Update PRs and send webhooks
            let branch: BranchRef = (repo.id, refname);
            find_and_update_pr(&tx, &st, &user, new_oid, branch, forced);
        }
        tx.commit();
    };

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
    tx: &crate::model::Token<Write>,
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
        .expect("query failed somehow");
    let prs = statement
        .query_map((*head_id, forced, *source_id, branchname), |row| {
            row.get("issue").map(PullRequestId::unsafe_from)
        })
        .expect("query binding failed");

    for pr_id in prs {
        let pr_id = pr_id.expect("retrieving or converting row failed");
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

/// Try to find PRs created from the specified ref.
///
/// Returns a smallvec because in most cases we should find 0 or 1 prs for a
/// given ref (TODO: test if it's even possible to create two PRs from the same
/// ref)
pub fn find_prs<M>(
    tx: &crate::model::Token<M>,
    (source_id, branchname): BranchRef,
) -> smallvec::SmallVec<[PullRequestId; 1]> {
    tx.prepare(
        "
        select issue
        FROM pull_requests
        WHERE repository = ? AND branch = ?
    ",
    )
    .expect("query failed somehow")
    .query_map((*source_id, branchname), |row| {
        row.get("issue").map(PullRequestId::unsafe_from)
    })
    .expect("query binding failed")
    .collect::<Result<_, _>>()
    .expect("retrieving or converting row failed")
}

#[instrument(skip(st, tx))]
async fn delete_ref(
    auth: Authorization,
    State(st): State<St>,
    Path((owner, name, ref_)): Path<(String, String, String)>,
    tx: Token<Write>,
) -> Result<http::StatusCode, GHError<'static>> {
    let Some(user) = crate::github::auth_to_user(&tx, auth) else {
        return Err(Error::Unauthenticated("").into_response(
            "git",
            "refs",
            "delete-a-reference",
        ));
    };
    let Some(repo_id) = crate::model::repos::id_by_name(&tx, &owner, &name)
    else {
        return Err(Error::NOT_FOUND.into_response(
            "git",
            "refs",
            "delete-a-reference",
        ));
    };

    for p in find_prs(&tx, (repo_id, &ref_)) {
        prs::update(&tx, p).state(prs::State::Closed).call();
        super::send_hook(
            &tx,
            crate::model::repos::by_id(&tx, repo_id),
            &st,
            HookEvent::PullRequest,
            &user,
            || {
                let pull_request @ PullRequestResponse { number, .. } =
                    super::issues::pr_response(&tx, &st, p);
                webhooks::WebhookEvent::PullRequest(webhooks::PullRequest {
                    action: webhooks::PullRequestAction::Closed,
                    number,
                    pull_request,
                })
            },
        );
    }

    let refname = format!("refs/{}", ref_.as_str());
    if crate::model::git::refs::delete_unchecked(&tx, repo_id, &refname) {
        tx.commit();
        Ok(http::StatusCode::NO_CONTENT)
    } else {
        Err(Error::unprocessable("Reference does not exist", &[])
            .into_response("git", "refs", "delete-a-reference"))
    }
}
