#![allow(dead_code)]

use std::collections::HashMap;
use std::fs;
use std::future::IntoFuture;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use clap::*;
use serde::Deserialize;
use serde_json::Deserializer;
use tokio::net::TcpListener;
use tower::{make::Shared, ServiceBuilder};
use tower_http::timeout::TimeoutLayer;
use tower_http::{
    catch_panic::CatchPanicLayer,
    set_header::response::SetResponseHeaderLayer,
    trace::{DefaultMakeSpan, DefaultOnResponse, TraceLayer},
    LatencyUnit,
};
use tracing::*;
use tracing_subscriber::fmt::format::FmtSpan;

mod github;
mod model;

#[derive(Parser)]
#[command(author, version, about)]
struct Opt {
    /// Users configuration, JSON data sent either through a file or
    /// through stdin (if `-`), should be a map of login to [`User`]
    users: PathBuf,
    /// Port on which to bind the server, if `0` ask the OS for an
    /// ephemeral port
    #[arg(short, long, default_value_t = 0)]
    port: u16,
    /// File in which to write the port listening on, mostly useful if
    /// using `0`
    #[arg(long)]
    portfile: Option<PathBuf>,
    /// One of trace, debug, info, warn, or error
    #[arg(long, default_value = "warn")]
    log: Level,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opt = Opt::parse();
    // TODO:  should have a big dynamic fallback route for all the
    //        github stuff, and a bunch of static routes for its own
    //        internal stuff.  This is necessary in order for the
    //        "github application" to be script-able / allow scenarios
    //        e.g. triggering errors on endpoints.

    /* TODO:
       tracing_subscriber::registry()
           .with(fmt::layer())
           .with(EnvFilter::from_default_env())
           .init();

       or something (may want to configure EnvFilter to not use RUST_LOG),
       also add custom filters for sub-crates
    */
    tracing_subscriber::fmt()
        .compact()
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_max_level(opt.log)
        .init();

    load_users(&opt.users)?;

    // TODO: support for domains (e.g. so we can generate URLs for
    //       locahost)
    let listener =
        TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], opt.port))).await?;
    let addr = listener.local_addr()?;

    let url = format!("http://{addr}");
    let (conf, webhooks) = github::Config::new(url.clone())?;
    let handler = github::routes(conf)
        .layer(
            ServiceBuilder::new()
            // Add high level tracing/logging to all requests
            .layer(
                TraceLayer::new_for_http()
                    .on_body_chunk(|chunk: &Bytes, latency: Duration, _: &tracing::Span| {
                        tracing::trace!(size_bytes = chunk.len(), latency = ?latency, "sending body chunk")
                    })
                    .make_span_with(DefaultMakeSpan::new().include_headers(true))
                    .on_response(DefaultOnResponse::new().include_headers(true).latency_unit(LatencyUnit::Micros)),
            )
            .layer(SetResponseHeaderLayer::if_not_present(
                axum::http::HeaderName::from_static("x_oauth_scopes"),
                axum::http::HeaderValue::from_static("admin:repo_hook, delete_repo, public_repo, user:email")
            ))
            .layer(CatchPanicLayer::new())
            // Set a timeout
            .layer(TimeoutLayer::new(Duration::from_secs(10)))
        );

    info!("listening on {}", url);
    if let Some(portfile) = opt.portfile {
        let mut f = fs::File::create(portfile)?;
        write!(f, "{}", addr.port())?;
        f.flush()?;
    }

    let _ = tokio::join![
        axum::serve(listener, Shared::new(handler)).into_future(),
        webhooks
    ];

    Ok(())
}

#[derive(Deserialize, Debug)]
pub struct User {
    #[serde(default)]
    login: String,
    r#type: github_types::users::UserType,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    token: Vec<String>,
    #[serde(default)]
    email: String,
}

#[instrument(level = "debug")]
fn load_users(p: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let users = if p == Path::new("-") {
        let mut de = Deserializer::from_reader(io::stdin());
        HashMap::<String, User>::deserialize(&mut de)?
    } else {
        let mut de = Deserializer::from_reader(fs::File::open(p)?);
        HashMap::<String, User>::deserialize(&mut de)?
    };

    model::users::load(users.into_iter().map(|(login, user)| {
        debug!(?user);
        (
            if user.login.is_empty() {
                login
            } else {
                user.login
            },
            user.name.filter(|n| !n.is_empty()),
            match user.r#type {
                github_types::users::UserType::User => "user",
                github_types::users::UserType::Organization => "organization",
            },
            user.token,
            user.email,
        )
    }))
    .map_err(|e| {
        debug!(error = ?e);
        e
    })?;
    Ok(())
}
