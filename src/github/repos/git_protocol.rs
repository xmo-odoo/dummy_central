use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read as _, Write as _};
use std::ops::BitOr;

use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, http};
use bytes::Buf;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::{Compression, FlushDecompress};
use gix_features::decode::leb64_from_read;
use gix_hash::ObjectId;
use gix_object::{Data, Kind, ObjectRef, WriteTo};
use gix_pack::data::Version;
use gix_pack::data::input::{BytesToEntriesIter, EntryDataMode, Mode};
use gix_pack::data::output::bytes::FromEntriesIter;
use gix_pack::data::output::{Count, Entry as PackEntry};
use headers::HeaderMap;
use tracing::instrument;

use crate::github::{Authorization, St};
use crate::model::{Read, Token, Write};

pub fn routes() -> Router<St> {
    Router::new()
        .route("/info/refs", get(git_refs))
        .route("/git-upload-pack", post(git_upload_pack))
        .route("/git-receive-pack", post(git_receive_pack))
        .route("/HEAD", get(get_head))
        .route("/objects/{s}/{ha}", get(get_object))
        .layer(axum::middleware::map_request(check_repo_name))
}

#[derive(serde::Deserialize)]
struct Repo {
    name: String,
}
/// Repository name may or may not use a `.git` extension,
/// normalising via a middleware does not seem to work so
/// just ban it
async fn check_repo_name(
    Path(Repo { name }): Path<Repo>,
    request: axum::extract::Request,
) -> Result<axum::extract::Request, impl IntoResponse> {
    if name.ends_with(".git") {
        Err((
            http::StatusCode::BAD_REQUEST,
            "Repository names must not end with `.git` in git operations.",
        ))
    } else {
        Ok(request)
    }
}

#[instrument(skip(tx))]
async fn get_head(
    _: Option<Authorization>,
    State(_): State<St>,
    tx: Token<Read>,
    Path((owner, name)): Path<(String, String)>,
) -> Result<String, http::StatusCode> {
    crate::model::repos::by_name(&tx, &owner, &name)
        .map(|repo| format!("ref: refs/heads/{}", repo.default_branch))
        .ok_or(http::StatusCode::NOT_FOUND)
}

#[instrument(skip(tx))]
async fn get_object(
    _: Option<Authorization>,
    State(_): State<St>,
    tx: Token<Read>,
    Path((owner, name, s, ha)): Path<(String, String, String, String)>,
) -> Result<Vec<u8>, http::StatusCode> {
    let repo = crate::model::repos::by_name(&tx, &owner, &name)
        .ok_or(http::StatusCode::NOT_FOUND)?;

    let mut oid = ObjectId::null(gix_hash::Kind::Sha1);
    hex::decode_to_slice(s, &mut oid.as_mut_slice()[..1])
        .and_then(|()| hex::decode_to_slice(ha, &mut oid.as_mut_slice()[1..]))
        .or(Err(http::StatusCode::BAD_REQUEST))?;

    let obj = crate::model::git::load(&tx, repo.network, &oid)
        .ok_or(http::StatusCode::NOT_FOUND)?;

    let mut encoder = ZlibEncoder::new(
        Vec::with_capacity(2 + 28 + obj.size() as usize + 4),
        Compression::none(),
    );
    encoder
        .write(&obj.loose_header())
        .and_then(|_| obj.write_to(&mut encoder))
        .and_then(|_| encoder.finish())
        .or(Err(http::StatusCode::BAD_REQUEST))
}
#[allow(clippy::write_with_newline)]
fn write_ref<W: std::io::Write>(
    mut buf: W,
    refname: &str,
    oid: &gix_hash::oid,
    capabilities: Option<&str>,
) -> std::io::Result<()> {
    let (caplen, capsep, caps) =
        capabilities.map_or((0, "", ""), |c| (c.len() + 1, "\0", c));

    // we want the newline in the format string for clarity
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

#[derive(serde::Deserialize, Debug)]
struct Service {
    service: Option<String>,
}

#[allow(clippy::type_complexity)]
#[instrument(skip(tx))]
async fn git_refs(
    auth: Option<Authorization>,
    State(_): State<St>,
    tx: Token<Read>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    q: Query<Service>,
) -> Result<([(&'static str, String); 1], Vec<u8>), Response> {
    let protocol = headers.get("git-protocol");
    let repo = crate::model::repos::by_name(&tx, &owner, &name)
        .ok_or(http::StatusCode::NOT_FOUND.into_response())?;

    let Some(service) = q.service.as_deref() else {
        // dumb http protocol
        let mut resp = Vec::new();
        // FIXME: The file SHOULD be sorted by name according to the C locale ordering.
        crate::model::git::refs::list(&tx, repo.id, |refname, oid| {
            writeln!(&mut resp, "{oid}\t{refname}")
                .expect("writing to a vec never fails");
        });
        return Ok((
            [("Content-Type", "text/plain;charset=utf-8".into())],
            resp,
        ));
    };
    // FIXME: private repos & auth for upload-pack (fetch) as well
    let mut capabilities = match service {
        "git-upload-pack" => Some(
            "multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since \
            deepen-not deepen-relative no-progress include-tag multi_ack_detailed \
            allow-tip-sha1-in-want allow-reachable-sha1-in-want no-done filter object-format=sha1",
        ),
        "git-receive-pack" if auth.is_none() => {
            return Err((
                http::StatusCode::UNAUTHORIZED,
                [(http::header::WWW_AUTHENTICATE, "Basic realm=\"GitHub\"")],
                "No anonymous write access.",
            )
                .into_response());
        }
        "git-receive-pack" => Some(
            "no-thin delete-refs quiet side-band side-band-64k ofs-delta report-status",
        ),
        _ => return Err(http::StatusCode::NOT_FOUND.into_response()),
    };

    let service_len = 4 + "# service=".len() + service.len() + 1;
    let mut resp =
        format!("{service_len:04x}# service={service}\n0000").into_bytes();
    // TODO: v2 protocol?
    if let Some(p) = protocol.and_then(|h| h.to_str().ok()) {
        for e in p.split(':') {
            // TODO: doc says unknown keys are ignored but what if value not supported?
            if let Some(("version", "1")) = e.split_once('=') {
                resp.extend(b"000eversion 1\n");
            }
        }
    }

    let default = format!("refs/heads/{}", repo.default_branch);

    // Tells the client what the default branch is, otherwise on clone it'll set the
    // the first ref whose oid matches HEAD as the default branch, which gets awkward
    // when we lazily create refs with the same oid as the true default branch *then*
    // clone the repo.
    // TODO: identify what happens if the default branch does not exist...
    let caps;
    let mut capabilities = if let Some(cap) = capabilities.take() {
        caps = format!("{cap} symref=HEAD:{default}");
        Some(caps.as_str())
    } else {
        None
    };

    if let Some(oid) = crate::model::git::refs::resolve(&tx, repo.id, &default)
    {
        write_ref(&mut resp, "HEAD", &oid, capabilities.take()).unwrap();
    }
    crate::model::git::refs::list(&tx, repo.id, |refname, oid| {
        write_ref(&mut resp, refname, oid, capabilities.take()).unwrap();
    });
    // TODO: can apparently also send a bunch of `.have` pseudo-refs for
    //       detached heads
    resp.extend(b"0000");

    Ok((
        [(
            "Content-Type",
            format!("application/x-{service}-advertisement"),
        )],
        resp,
    ))
}

#[repr(u8)]
enum Sideband {
    Data = 1,
    Progress = 2,
    Error = 3,
}

fn write_progress(buf: &mut Vec<u8>, msg: impl std::fmt::Display) {
    let write_at = buf.len();
    writeln!(buf, "0000\x02{msg}").expect("write! to vec to succeed");
    let written = buf.len() - write_at;
    write!(&mut buf[write_at..], "{written:04x}")
        .expect("write to slice to succeed");
}

fn write_data(buf: &mut Vec<u8>, msg: impl std::fmt::Display) {
    let write_at = buf.len();
    writeln!(buf, "0000\x010000{msg}").expect("write! to vec to succeed");
    let written = buf.len() - write_at;
    write!(
        &mut buf[write_at..],
        "{:04x}\x01{:04x}",
        written,
        written - 5
    )
    .expect("write to slice to succeed");
}

#[instrument(skip(tx))]
async fn git_upload_pack(
    State(_): State<St>,
    tx: Token<Read>,
    Path((owner, name)): Path<(String, String)>,
) -> Response {
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return http::StatusCode::NOT_FOUND.into_response();
    };

    // TODO: parse options (cap-list) to know how to reply
    // TODO: parse want/have, eventually we probably want to handle updates
    //       (= look at the body) but for now only handle the initial clone
    let mut objects = crate::model::git::get_objects(&tx, repo.network);
    let Ok(count) = objects.len().try_into() else {
        todo!("Handle pack splitting (?)");
    };
    objects.sort();
    let mut buf = Vec::new();
    let mut pack = Vec::<u8>::new();
    let mut entries_writer = FromEntriesIter::new(
        objects.into_iter().map(
            |oid| -> Result<
                Vec<PackEntry>,
                gix_pack::data::output::entry::Error,
            > {
                buf.clear();
                let (kind, data) = crate::model::git::get_in(
                    &tx,
                    repo.network,
                    &oid,
                    &mut buf,
                )
                .unwrap();
                Ok(vec![PackEntry::from_data(
                    &Count::from_data(oid, None),
                    &Data::new(kind, data),
                )?])
            },
        ),
        &mut pack,
        count,
        Version::V2,
        gix_hash::Kind::Sha1,
    );

    for e in entries_writer.by_ref() {
        e.unwrap();
    }
    entries_writer.digest().expect("iteration should be done");

    assert!(
        pack.len() < 65000,
        "doesn't support splitting pack data yet ({} > 65000)",
        pack.len(),
    );

    let mut response = Vec::with_capacity(pack.len() + 100);
    response.extend(b"0008NAK\n");

    write!(&mut response, "{:04x}", 4 + 1 + pack.len())
        .expect("writing to a vec should always work");
    response.push(Sideband::Data as _);
    response.extend(pack);
    response.extend(b"0000");

    (
        [("Content-Type", "application/x-git-upload-pack-result")],
        response,
    )
        .into_response()
}

#[instrument(skip(st, tx))]
async fn git_receive_pack(
    auth: Authorization,
    State(st): State<St>,
    tx: Token<Write>,
    Path((owner, name)): Path<(String, String)>,
    data: bytes::Bytes,
) -> Response {
    // FIXME: how is auth supposed to pass to receive-pack? The auth doesn't
    //        seem to be getting passed in which seems odd...
    // FIXME: differentiate between unauth and incorrect auth?
    let Some(user) = crate::github::auth_to_user(&tx, auth) else {
        return (
            http::StatusCode::UNAUTHORIZED,
            [(http::header::WWW_AUTHENTICATE, "Basic realm=\"GitHub\"")],
            b"No anonymous write access.".as_slice(),
        )
            .into_response();
    };
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        // FIXME: how does that react?
        return http::StatusCode::NOT_FOUND.into_response();
    };

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

        ref_updates.push((from, to, refname.to_string(), true));
    }

    load_pack_data(&tx, &repo, r);

    // the first line is always the same and just tells the client that the pack
    // upload worked, "unpack [err]" says it failed and why
    let mut response = b"0013\x01000eunpack ok\n".to_vec();

    // TODO: count entries with a from *and* a to in the first iteration instead?
    let mut updates = Vec::with_capacity(ref_updates.len());
    for (from, to, refname, success) in &mut ref_updates {
        if from.is_null() {
            *success = crate::model::git::refs::create(&tx, &repo, refname, to);
            if !*success {
                write_progress(
                    &mut response,
                    format_args!(
                        concat!(
                            "error: GH013: Repository rule violations found for {}.\n",
                            "Review all repository rules\n",
                            "\n",
                            "- Cannot create ref due to creations being restricted.\n",
                        ),
                        refname,
                    ),
                );
            }
        } else if to.is_null() {
            // The pack-file MUST NOT be sent if the only command used is delete.
            crate::model::git::refs::delete(&tx, repo.id, refname, from);
        } else {
            *success =
                crate::model::git::refs::update(&tx, &repo, refname, from, to);
            if !*success {
                write_progress(
                    &mut response,
                    format_args!(
                        concat!(
                            "error: GH013: Repository rule violations found for {}.\n",
                            "Review all repository rules\n",
                            "\n",
                            "- Cannot update this protected ref.\n",
                        ),
                        refname,
                    ),
                );
            } else {
                // FIXME: handling of non-head refs
                updates.push((
                    Box::<str>::from(
                        refname.strip_prefix("refs/heads/").unwrap(),
                    ),
                    to,
                    true, // FIXME: compute forced updates correctly
                ));
            }
        }
    }

    for (branch, oid, forced) in updates {
        // Update PRs and send webhooks
        let branch: super::git::BranchRef = (repo.id, &branch);
        super::git::find_and_update_pr(&tx, &st, &user, *oid, branch, forced);
    }
    tx.commit();

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
    for (_, _, branch, success) in ref_updates {
        write_data(
            &mut response,
            format_args!(
                "{} {}{}",
                if success { "ok" } else { "ng" },
                branch,
                if success {
                    ""
                } else {
                    " push declined due to repository rule violations"
                },
            ),
        );
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

fn load_pack_data(
    tx: &Token<Write>,
    repo: &crate::model::repos::Repository,
    mut r: BufReader<bytes::buf::Reader<bytes::Bytes>>,
) {
    // fill_buf (of BufReader) only refills the buffer if it's *empty*
    if r.fill_buf().unwrap().is_empty() {
        return;
    }
    // PACK(data)
    let entries = BytesToEntriesIter::new_from_header(
        r,
        Mode::Verify,
        EntryDataMode::Keep,
        gix_hash::Kind::Sha1,
    )
    .unwrap();
    let mut entries_offset_cache = HashMap::<_, ObjectId>::new();
    let mut entry_buf = Vec::new();
    let mut parent_buf = Vec::new();
    for entry in entries {
        let entry = entry.expect("Could not decode entry");
        entry_buf.clear();
        let compressed = entry.compressed.unwrap();

        let (kind, filled) = match entry.header {
            gix_pack::data::entry::Header::Commit => (Kind::Commit, false),
            gix_pack::data::entry::Header::Tree => (Kind::Tree, false),
            gix_pack::data::entry::Header::Blob => (Kind::Blob, false),
            gix_pack::data::entry::Header::Tag => (Kind::Tag, false),
            gix_pack::data::entry::Header::RefDelta { base_id: _ } => {
                todo!("Implement unpacking of ref-delta entries");
            }
            gix_pack::data::entry::Header::OfsDelta { base_distance } => {
                let oid =
                    entries_offset_cache[&(entry.pack_offset - base_distance)];
                parent_buf.clear();
                let (kind, parent_data) = crate::model::git::get_in(
                    tx,
                    repo.network,
                    &oid,
                    &mut parent_buf,
                )
                .unwrap();
                let mut inflater = ZlibDecoder::new(&compressed[..]);
                // first I have the size of the base object and the size of the new object (?)
                // TODO: reorder to reserve capacity in parent_buf
                let (_base_length, _) = leb64_from_read(&mut inflater).unwrap();
                let (new_length, _) = leb64_from_read(&mut inflater).unwrap();

                entry_buf.reserve(new_length as usize);

                let mut command = 0;
                while let Ok(()) =
                    inflater.read_exact(std::slice::from_mut(&mut command))
                {
                    if command & 0x80 == 0 {
                        // add literal data
                        let bytes = command & 0x7f;
                        inflater
                            .by_ref()
                            .take(bytes as _)
                            .read_to_end(&mut entry_buf)
                            .unwrap();
                    } else {
                        // copy data from base object

                        // the header is a sparse buffer of 0-7 bytes, with the
                        // leading byte indicating which of the bytes are
                        // nonzero

                        // bitmap of relevant header bytes
                        let bytes = command.count_ones() - 1;
                        // spec is $bytes bytes, providing up to 4 bytes of
                        // offset into the base and up to 3 bytes of length
                        let mut copy_spec_buf = [0u8; 7];
                        let spec = &mut copy_spec_buf[..bytes as _];
                        inflater.read_exact(spec).unwrap();
                        let mut spec = spec.iter();

                        // the low 4 bits indicate which of the first 4 bytes
                        // are present, and those are OR-ed to get the offset
                        let offset = (0..4)
                            .filter(|idx| (command & (1 << idx)) != 0)
                            .zip(spec.by_ref())
                            .map(|(idx, byte)| (*byte as usize) << (8 * idx))
                            .fold(0, usize::bitor);

                        // the high 3 bits indicate which of the next 3 bytes
                        // are present and those are OR-ed to get the size
                        let size = (0..3)
                            .filter(|idx| (command & (16 << idx)) != 0)
                            .zip(spec)
                            .map(|(idx, byte)| (*byte as usize) << (8 * idx))
                            .fold(0, usize::bitor);
                        // TODO: is this a final size of 0 or a bitmap value of 0
                        // TODO: why 0x10000?
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
            tx,
            repo.network,
            ObjectRef::from_bytes(kind, &entry_buf).unwrap(),
        );
        entries_offset_cache.insert(entry.pack_offset, oid);
    }
}
