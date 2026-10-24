use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;

use argh::FromArgs;
use hyper::Uri;
use snafu::{ResultExt, Whatever};
use tokio::net::UdpSocket;

use iroh_udp_relay::proto;
use iroh_udp_relay::server::{self, Access, Metrics};

const DEFAULT_BIND_ADDR: SocketAddr = SocketAddr::V4(
    SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, proto::DEFAULT_PORT)
);

/// UDP relay, it forwards traffic between iroh endpoints when hole punching fails
#[derive(FromArgs)]
struct Args {
    /// udp address to listen on
    #[argh(option, default = "DEFAULT_BIND_ADDR")]
    bind_addr: SocketAddr,
    /// url of an http access check, the same as `access.http.url` of an iroh relay,
    /// any endpoint is allowed if not set
    #[argh(option)]
    access_url: Option<Uri>,
    /// path to a file with a bearer token for the access check
    #[argh(option)]
    access_token_file: Option<PathBuf>,
    /// tcp address to serve prometheus metrics on (`/metrics`), disabled if not set
    #[argh(option)]
    metrics_addr: Option<SocketAddr>,
}

#[tokio::main]
async fn main() -> Result<(), Whatever> {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let args: Args = argh::from_env();
    let token = args.access_token_file
        .map(|path| {
            let token = std::fs::read_to_string(&path)
                .with_whatever_context(|_| format!("Cannot read access token: {path:?}"))?;
            Ok::<_, Whatever>(token.trim().to_string())
        })
        .transpose()?;
    let access = match args.access_url {
        Some(url) => {
            if url.scheme_str() != Some("http") {
                snafu::whatever!("Only http access urls are supported: {url}");
            }
            Access::Http { url, token }
        }
        None => {
            log::warn!("No access check, any endpoint can use the relay");
            Access::AllowAll
        }
    };

    let metrics = Arc::new(Metrics::default());
    let _metrics_server = match args.metrics_addr {
        Some(addr) => {
            let mut registry = iroh_metrics::Registry::default();
            registry.register(metrics.clone());
            let server = iroh_metrics::service::MetricsServer::spawn(addr, Arc::new(registry)).await
                .with_whatever_context(|_| format!("Cannot start metrics server: {addr}"))?;
            log::info!("Serving metrics on {}", server.local_addr());
            Some(server)
        }
        None => None,
    };

    let socket = UdpSocket::bind(args.bind_addr).await
        .with_whatever_context(|_| format!("Cannot bind: {}", args.bind_addr))?;
    log::info!("Listening on {}", args.bind_addr);
    tokio::select! {
        res = server::run(socket, access, metrics) => res.whatever_context("Relay failed"),
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}
