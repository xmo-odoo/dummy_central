use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use bytes::Buf;
use flate2::read::ZlibDecoder;
use flate2::FlushDecompress;
use git_features::decode::leb64_from_read;
use git_hash::ObjectId;
use git_object::{Data, Kind, ObjectRef};
use git_pack::data::input::{
    BytesToEntriesIter, EntryDataMode, LookupRefDeltaObjectsIter, Mode,
};
use git_pack::data::output::bytes::FromEntriesIter;
use git_pack::data::output::{Count, Entry as PackEntry};
use git_pack::data::Version;
use guard::guard;
use headers::HeaderMap;
use http::StatusCode;
use std::collections::HashMap;
use std::io::{BufReader, Read, Write};
use std::sync::RwLock;

use crate::github::{Authorization, Error, St};
use crate::model::users::find_current_user;
use crate::model::Source;

pub use github_types::git::*;

pub fn routes() -> Router<St> {
    // FIXME: add middleware because parent may extract the repo name w/
    // extension which needs to be stripped
    // https://docs.rs/axum/latest/axum/middleware/index.html#passing-state-from-middleware-to-handlers
    // TODO: add extractor for the Protocol instead of doing it by hand
    Router::new()
        .route("/info/refs", get(git_refs))
        .route("/git-upload-pack", post(git_upload_pack))
        .route("/git-receive-pack", post(git_receive_pack))
}

#[derive(serde::Deserialize)]
struct Service {
    service: String,
}
fn write_ref<W: std::io::Write>(
    mut buf: W,
    refname: &str,
    oid: &git_hash::oid,
    capabilities: Option<&str>,
) -> std::io::Result<()> {
    let (caplen, capsep, caps) =
        capabilities.map_or((0, "", ""), |c| (c.len() + 1, "\0", c));

    // we want the newline in the format string for clarity
    #[allow(clippy::write_with_newline)]
    write!(
        buf,
        "{:04x}{} {}{}{}\n",
        4 + oid.kind().len_in_hex() + 1 + refname.len() + caplen + 1,
        oid.to_hex(),
        refname,
        capsep,
        caps,
    )
}
async fn git_refs(
    auth: Option<Authorization>,
    State(st): State<St>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Query(Service { service }): Query<Service>,
) -> Response {
    let protocol = headers.get("git-protocol");
    let mut db = Source::get();
    let tx = &db.token();
    let name = name.strip_suffix(".git").unwrap_or(&name);
    guard!(let Some(repo) = crate::model::repos::by_name(tx, &owner, name) else {
        return http::StatusCode::NOT_FOUND.into_response();
    });

    let mut capabilities = match service.as_str() {
        "git-upload-pack" => Some("multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not deepen-relative no-progress include-tag multi_ack_detailed allow-tip-sha1-in-want allow-reachable-sha1-in-want no-done filter object-format=sha1"),
        "git-receive-pack" => {
            if auth.is_none() {
                return (
                    http::StatusCode::UNAUTHORIZED,
                    [(http::header::WWW_AUTHENTICATE, "Basic realm=\"GitHub\"")],
                    b"No anonymous write access.".as_slice(),
                ).into_response();
            }
            Some("no-thin delete-refs quiet side-band-64k ofs-delta")
        },
        _ => return http::StatusCode::NOT_FOUND.into_response(),
    };

    let service_len = "0000".len() + "# service=".len() + service.len() + 1;
    let mut resp =
        format!("{service_len:04x}# service={service}\n0000").into_bytes();
    if protocol.and_then(|h| h.to_str().ok()) == Some("version=1") {
        resp.extend(b"000eversion 1\n")
    }

    let default = format!("refs/heads/{}", repo.default_branch);
    if let Some(oid) = crate::model::git::refs::resolve(tx, repo.id, &default) {
        write_ref(&mut resp, "HEAD", &oid, capabilities.take()).unwrap();
    }
    crate::model::git::refs::list(tx, repo.id, |refname, oid| {
        write_ref(&mut resp, refname, oid, capabilities.take()).unwrap();
    });
    // TODO: can apparently also send a bunch of `.have` pseudo-refs for
    //       detached heads
    resp.extend(b"0000");

    (
        [(
            "Content-Type",
            format!("application/x-{service}-advertisement"),
        )],
        resp,
    )
        .into_response()
}

#[repr(u8)]
enum Sideband {
    Data = 1,
    Progress = 2,
    Error = 3,
}
async fn git_upload_pack(
    State(st): State<St>,
    Path((owner, name)): Path<(String, String)>,
) -> Response {
    let mut db = Source::get();
    let tx = &db.token();
    let name = name.strip_suffix(".git").unwrap_or(&name);
    guard!(let Some(repo) = crate::model::repos::by_name(tx, &owner, name) else {
        return http::StatusCode::NOT_FOUND.into_response()
    });

    // TODO: parse options
    // TODO: parse want/have, eventually we probably want to handle updates
    //       (= look at the body) but for now only handle the initial clone
    let objects = crate::model::git::get_objects(tx, repo.network);
    let count = objects.len();
    let mut buf = Vec::new();
    let mut pack = Vec::<u8>::new();
    let mut entries_writer = FromEntriesIter::new(
        objects.into_iter().map(
            |oid| -> Result<
                Vec<PackEntry>,
                git_pack::data::output::entry::Error,
            > {
                buf.clear();
                let (kind, data) =
                    crate::model::git::get_in(tx, repo.network, &oid, &mut buf)
                        .unwrap();
                Ok(vec![PackEntry::from_data(
                    &Count::from_data(oid, None),
                    &Data::new(kind, data),
                )
                .unwrap()])
            },
        ),
        &mut pack,
        count.try_into().unwrap(),
        Version::V2,
        git_hash::Kind::Sha1,
    );

    for _ in entries_writer.by_ref() {}
    let hash = entries_writer.digest().expect("iteration should be done");

    assert!(
        pack.len() < 65000,
        "doesn't support splitting pack data yet"
    );

    let mut response = Vec::with_capacity(pack.len() + 100);
    response.extend(b"0008NAK\n");

    write!(&mut response, "{:04x}", 4 + 1 + pack.len());
    response.push(Sideband::Data as _);
    response.extend(pack);
    response.extend(b"0000");

    (
        [("Content-Type", "application/x-git-upload-pack-result")],
        response,
    )
        .into_response()
}

async fn git_receive_pack(
    auth: Authorization,
    State(st): State<St>,
    Path((owner, name)): Path<(String, String)>,
    data: bytes::Bytes,
) -> Response {
    // FIXME: how is auth supposed to pass to receive-pack? The auth doesn't
    //        seem to be getting passed in which seems odd...
    // FIXME: differentiate between unauth and incorrect auth?
    let mut db = Source::get();
    let tx = db.token_eager();
    let name = name.strip_suffix(".git").unwrap_or(&name);
    guard!(let Some(user) = crate::github::auth_to_user(&tx, auth) else {
        return (
            http::StatusCode::UNAUTHORIZED,
            [(http::header::WWW_AUTHENTICATE, "Basic realm=\"GitHub\"")],
            b"No anonymous write access.".as_slice(),
        ).into_response();
    });
    guard!(let Some(repo) = crate::model::repos::by_name(&tx, &owner, name) else {
        // FIXME: how does that react?
        return http::StatusCode::NOT_FOUND.into_response();
    });

    let mut len = [0u8; 4];
    let mut line_buf = Vec::new();
    let mut r = BufReader::new(data.reader());

    let mut ref_updates = Vec::new();
    while let Ok(()) = r.read_exact(&mut len) {
        if &len == b"0000" {
            break;
        }

        let len = u16::from_be_bytes(
            hex::decode(len)
                .ok()
                .and_then(|bytes| bytes.as_slice().try_into().ok())
                .unwrap_or_else(|| {
                    panic!(
                        "Unable to parse {}",
                        std::str::from_utf8(&len).unwrap()
                    )
                }),
        ) - 4;
        line_buf.clear();
        line_buf.resize(len as _, 0);

        // pkt(command NUL cap_list)
        // pkt(command)*
        // command = 0000000 $new_id $refname
        //         | $old_id 0000000 $refname
        //         | $old_id $new_id $refname
        r.read_exact(&mut line_buf).unwrap();
        assert_eq!(line_buf[40], b' ');
        assert_eq!(line_buf[81], b' ');
        let from = ObjectId::from_hex(&line_buf[..40]).unwrap();
        let to = ObjectId::from_hex(&line_buf[41..81]).unwrap();
        let refname = line_buf[82..]
            .split(|&v| v == b'\0' || v == b'\n')
            .next()
            .unwrap();
        assert!(refname.starts_with(b"refs/"));
        let refname = std::str::from_utf8(refname).unwrap();

        ref_updates.push((from, to, refname.to_string()));
    }

    // PACK(data)
    let mut entries = BytesToEntriesIter::new_from_header(
        r,
        Mode::Verify,
        EntryDataMode::Keep,
        git_hash::Kind::Sha1,
    )
    .unwrap();
    let mut entries_offset_cache = HashMap::<_, ObjectId>::new();
    let mut entry_buf = Vec::new();
    let mut copy_spec_buf = [0u8; 7];
    let mut parent_buf = Vec::new();
    for entry in entries {
        let entry = entry.expect("Could not decode entry");
        entry_buf.clear();
        let compressed = entry.compressed.unwrap();

        let (kind, filled) = match entry.header {
            git_pack::data::entry::Header::Commit => (Kind::Commit, false),
            git_pack::data::entry::Header::Tree => (Kind::Tree, false),
            git_pack::data::entry::Header::Blob => (Kind::Blob, false),
            git_pack::data::entry::Header::Tag => (Kind::Tag, false),
            git_pack::data::entry::Header::RefDelta { base_id } => todo!(),
            git_pack::data::entry::Header::OfsDelta { base_distance } => {
                let oid =
                    entries_offset_cache[&(entry.pack_offset - base_distance)];
                parent_buf.clear();
                let (kind, parent_data) = crate::model::git::get_in(
                    &tx,
                    repo.network,
                    &oid,
                    &mut parent_buf,
                )
                .unwrap();
                let mut inflater = ZlibDecoder::new(&compressed[..]);
                // first I have the size of the base object and the size of the new object (?)
                let (base_length, _) = leb64_from_read(&mut inflater).unwrap();
                let (new_length, _) = leb64_from_read(&mut inflater).unwrap();

                entry_buf.reserve(new_length as usize);

                let mut command = [0; 1];
                while let Ok(()) = inflater.read_exact(&mut command) {
                    if command[0] & 0x80 == 0 {
                        let bytes = command[0] & 0x7f;
                        inflater
                            .by_ref()
                            .take(bytes as _)
                            .read_to_end(&mut entry_buf)
                            .unwrap();
                    } else {
                        let bytes = command[0].count_ones() - 1;
                        let spec = &mut copy_spec_buf[..bytes as _];
                        inflater.read_exact(spec).unwrap();
                        let mut spec = spec.iter_mut();
                        let offset = (command[0] & 0b1 != 0)
                            .then(|| *spec.next().unwrap() as usize)
                            .unwrap_or(0)
                            | (command[0] & 0b10 != 0)
                                .then(|| (*spec.next().unwrap() as usize) << 8)
                                .unwrap_or(0)
                            | (command[0] & 0b100 != 0)
                                .then(|| (*spec.next().unwrap() as usize) << 16)
                                .unwrap_or(0)
                            | (command[0] & 0b1000 != 0)
                                .then(|| (*spec.next().unwrap() as usize) << 24)
                                .unwrap_or(0);
                        let size = (command[0] & 0b1_0000 != 0)
                            .then(|| *spec.next().unwrap() as usize)
                            .unwrap_or(0)
                            | (command[0] & 0b10_0000 != 0)
                                .then(|| (*spec.next().unwrap() as usize) << 8)
                                .unwrap_or(0)
                            | (command[0] & 0b100_0000 != 0)
                                .then(|| (*spec.next().unwrap() as usize) << 16)
                                .unwrap_or(0);
                        let size = if size == 0 { 0x10000 } else { size };

                        entry_buf.extend(&parent_data[offset..offset + size]);
                    }
                }
                (kind, true)
            }
        };
        if !filled {
            entry_buf.reserve(entry.decompressed_size as usize);
            flate2::Decompress::new(true)
                .decompress_vec(
                    &compressed,
                    &mut entry_buf,
                    FlushDecompress::Finish,
                )
                .unwrap();
        }

        let oid = crate::model::git::store(
            &tx,
            repo.network,
            ObjectRef::from_bytes(kind, &entry_buf).unwrap(),
        );
        entries_offset_cache.insert(entry.pack_offset, oid);
    }

    // TODO: count entries with a from *and* a to in the first iteration instead?
    let mut updates = Vec::with_capacity(ref_updates.len());
    for (from, to, refname) in ref_updates {
        if from.is_null() {
            crate::model::git::refs::create(&tx, repo.id, &refname, &to);
        } else if to.is_null() {
            // The pack-file MUST NOT be sent if the only command used is delete.
            crate::model::git::refs::delete(&tx, repo.id, &refname, &from);
        } else {
            crate::model::git::refs::update(&tx, repo.id, &refname, &from, &to);
            updates.push((
                Box::<str>::from(refname.strip_prefix("refs/heads/").unwrap()),
                to,
                true, // FIXME: compute forced updates correctly
            ));
        }
    }

    for (branch, oid, forced) in updates.iter() {
        // Update PRs and send webhooks
        let branch: super::git::BranchRef = (repo.id, branch);
        super::git::find_and_update_pr(&tx, &st, &user, *oid, branch, *forced);
    }
    tx.commit().unwrap();

    /*
    After receiving the pack data from the sender, the receiver sends a report if
    report-status capability is in effect. It is a short listing of what happened
    in that update. It will first list the status of the packfile unpacking as
    either unpack ok or unpack [error]. Then it will list the status for each of
    the references that it tried to update. Each line is either ok [refname] if
    the update was successful, or ng [refname] [error] if the update was not.

       000eunpack ok\n
       0018ok refs/heads/debug\n
       002ang refs/heads/master non-fast-forward\n

    Apparently the HTTP smart protocol then wraps the entire thing into a pack data


    0013\x01000eunpack ok
    002d\x010028ok refs/heads/b-conflicting-0BGh-fw
    00a5\x02
    Create a pull request for 'b-conflicting-0BGh-fw' on GitHub by visiting:
         https://github.com/xmo-odoo/ignore_proj_Xnu5C5bN/pull/new/b-conflicting-0BGh-fw
    0009\x0100000000
         */
    // the first line is always the same and just tells the client that the pack
    // upload worked, "unpack [err]" says it failed and why
    let mut response = b"0013\x01000eunpack ok\n".to_vec();
    for (branch, _, _) in updates {
        let len_line = 4 + "ok refs/heads/".len() + branch.len() + 1;
        let len_pack = 4 + 1 + len_line;
        // clearer with an explicit newline as that's part of the payload length
        #[allow(clippy::write_with_newline)]
        write!(
            &mut response,
            "{len_pack:04x}\x01{len_line:04x}ok refs/heads/{branch}\n",
        )
        .unwrap();
    }
    // end of inner message
    response.extend(b"0009\x010000");
    // end of outer message
    response.extend(b"0000");

    (
        [("Content-Type", "application/x-git-receive-pack-result")],
        response,
    )
        .into_response()
}
