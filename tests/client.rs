use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{presets, Connection};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{EndpointAddr, RelayMode, SecretKey, TransportAddr};
use tokio::net::UdpSocket;

use iroh_udp_relay::client::{self as udp_relay, DirectFirstPathSelector, UdpRelayTransport};
use iroh_udp_relay::server::{self, Access};

const ALPN: &[u8] = b"iroh-udp-relay-test/echo";

#[derive(Debug, Clone)]
struct Echo;

impl ProtocolHandler for Echo {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let (mut send, mut recv) = conn.accept_bi().await?;
        tokio::io::copy(&mut recv, &mut send).await?;
        send.finish()?;
        conn.closed().await;
        Ok(())
    }
}

async fn start_relay() -> String {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(server::run(socket, Access::AllowAll, Default::default()));
    addr.to_string()
}

async fn endpoint(seed: u8, udp_relay: &str) -> iroh::Endpoint {
    let secret_key = SecretKey::from_bytes(&[seed; 32]);
    iroh::Endpoint::builder(presets::Minimal)
        .secret_key(secret_key.clone())
        .relay_mode(RelayMode::Disabled)
        .path_selector(Arc::new(DirectFirstPathSelector))
        .add_custom_transport(Arc::new(UdpRelayTransport::new(udp_relay.to_string(), secret_key)))
        .bind_addr("127.0.0.1:0").unwrap()
        .bind().await.unwrap()
}

async fn echo(conn: &Connection, msg: &[u8]) -> Vec<u8> {
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(msg).await.unwrap();
    send.finish().unwrap();
    recv.read_to_end(1024).await.unwrap()
}

/// Waits until the selected path matches
async fn wait_selected(conn: &Connection, f: impl Fn(&TransportAddr) -> bool) -> TransportAddr {
    let mut selected = None;
    for _ in 0..100 {
        selected = conn.paths().iter()
            .find(|p| p.is_selected())
            .map(|p| p.remote_addr().clone());
        if selected.as_ref().is_some_and(&f) {
            return selected.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("Unexpected selected path: {selected:?}");
}

#[tokio::test]
async fn test_connect_via_udp_relay() {
    let relay = start_relay().await;
    let server = Router::builder(endpoint(1, &relay).await).accept(ALPN, Echo).spawn();
    let client = endpoint(2, &relay).await;

    // Only the relay address: as if hole punching failed
    let server_id = server.endpoint().id();
    let server_addr = EndpointAddr::from_parts(server_id, [udp_relay::peer_addr(server_id)]);
    let conn = tokio::time::timeout(Duration::from_secs(10), client.connect(server_addr, ALPN)).await
        .expect("Connect timed out")
        .unwrap();
    assert_eq!(echo(&conn, b"hello relay").await, b"hello relay");
    wait_selected(&conn, TransportAddr::is_custom).await;

    conn.close(0u32.into(), b"done");
    client.close().await;
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_unreachable_direct_addr() {
    let relay = start_relay().await;
    let server = Router::builder(endpoint(5, &relay).await).accept(ALPN, Echo).spawn();
    let client = endpoint(6, &relay).await;

    // Nobody listens on the direct address
    let unused = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let unreachable_addr = unused.local_addr().unwrap();
    drop(unused);
    let server_id = server.endpoint().id();
    let server_addr = EndpointAddr::new(server_id)
        .with_ip_addr(unreachable_addr)
        .with_addrs([udp_relay::peer_addr(server_id)]);
    let conn = tokio::time::timeout(Duration::from_secs(10), client.connect(server_addr, ALPN)).await
        .expect("Connect timed out")
        .unwrap();
    assert_eq!(echo(&conn, b"hello fallback").await, b"hello fallback");
    wait_selected(&conn, TransportAddr::is_custom).await;

    conn.close(0u32.into(), b"done");
    client.close().await;
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn test_direct_path_wins() {
    let relay = start_relay().await;
    let server = Router::builder(endpoint(3, &relay).await).accept(ALPN, Echo).spawn();
    let client = endpoint(4, &relay).await;

    let server_id = server.endpoint().id();
    let server_addr = server.endpoint().addr()
        .with_addrs([udp_relay::peer_addr(server_id)]);
    assert!(server_addr.ip_addrs().next().is_some(), "{server_addr:?}");
    let conn = tokio::time::timeout(Duration::from_secs(10), client.connect(server_addr, ALPN)).await
        .expect("Connect timed out")
        .unwrap();
    assert_eq!(echo(&conn, b"hello direct").await, b"hello direct");
    wait_selected(&conn, TransportAddr::is_ip).await;

    conn.close(0u32.into(), b"done");
    client.close().await;
    server.shutdown().await.unwrap();
}
