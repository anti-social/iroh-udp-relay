//! Relay server: binds public keys of nodes to their UDP addresses
//! and forwards data packets between them.

pub mod metrics;

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::header::{AUTHORIZATION, HOST};
use hyper::{Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;

use iroh_base::PublicKey;

use crate::proto::{self, Key, Message, Nonce};

pub use self::metrics::{Metrics, NodeLabels};
use self::metrics::NodeCounters;

/// The same header as an iroh relay sends to its HTTP access check
const ENDPOINT_ID_HEADER: &str = "X-Iroh-Endpoint-Id";
const ACCESS_CHECK_TIMEOUT: Duration = Duration::from_secs(5);
/// Access decisions are cached and sessions are rechecked after this time
const ACCESS_CACHE_TTL: Duration = Duration::from_secs(60);
const CHALLENGE_TTL: Duration = Duration::from_secs(5);
/// Limits memory used by spoofed `Hello` messages
const MAX_PENDING_CHALLENGES: usize = 4096;
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Decides which nodes may use the relay
pub enum Access {
    AllowAll,
    /// The same HTTP access check as for an iroh relay (`access.http` in its config):
    /// a POST request with the `X-Iroh-Endpoint-Id` header, `200` with `true` allows a node
    Http { url: Uri, token: Option<String> },
}

impl Access {
    async fn check(&self, key: &PublicKey) -> Result<bool, String> {
        match self {
            Access::AllowAll => Ok(true),
            Access::Http { url, token } => {
                tokio::time::timeout(ACCESS_CHECK_TIMEOUT, check_http(url, token.as_deref(), key)).await
                    .map_err(|_| "timed out".to_string())?
            }
        }
    }
}

async fn check_http(url: &Uri, token: Option<&str>, key: &PublicKey) -> Result<bool, String> {
    let authority = url.authority().ok_or("No host in the access url")?;
    let host = authority.host().trim_start_matches('[').trim_end_matches(']');
    let port = authority.port_u16().unwrap_or(80);
    let stream = TcpStream::connect((host, port)).await
        .map_err(|e| format!("Cannot connect: {e}"))?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await
        .map_err(|e| format!("HTTP handshake failed: {e}"))?;
    tokio::spawn(conn);

    let mut req = Request::post(url.path_and_query().map(|p| p.as_str()).unwrap_or("/"))
        .header(HOST, authority.as_str())
        .header(ENDPOINT_ID_HEADER, key.to_string());
    if let Some(token) = token {
        req = req.header(AUTHORIZATION, format!("Bearer {token}"));
    }
    let req = req.body(Empty::<Bytes>::new())
        .map_err(|e| format!("Invalid request: {e}"))?;
    let resp = sender.send_request(req).await
        .map_err(|e| format!("Request failed: {e}"))?;
    if resp.status() != StatusCode::OK {
        return Err(format!("Unexpected status: {}", resp.status()));
    }
    let body = resp.into_body().collect().await
        .map_err(|e| format!("Cannot read response: {e}"))?
        .to_bytes();
    Ok(body.as_ref() == b"true")
}

struct Session {
    addr: SocketAddr,
    last_seen: Instant,
    checked_at: Instant,
    counters: NodeCounters,
}

struct Challenge {
    key: Key,
    nonce: Nonce,
    expires: Instant,
}

/// Result of an access check, `None` if the check failed
type AccessResult = (Key, Option<bool>);

struct Relay {
    socket: UdpSocket,
    is_v6: bool,
    access: Arc<Access>,
    access_tx: mpsc::Sender<AccessResult>,
    sessions: HashMap<Key, Session>,
    by_addr: HashMap<SocketAddr, Key>,
    challenges: HashMap<SocketAddr, Challenge>,
    /// Authenticated nodes waiting for an access check
    authorizing: HashMap<Key, SocketAddr>,
    access_cache: HashMap<Key, (bool, Instant)>,
    metrics: Arc<Metrics>,
}

pub async fn run(socket: UdpSocket, access: Access, metrics: Arc<Metrics>) -> io::Result<()> {
    let (access_tx, mut access_rx) = mpsc::channel(256);
    let mut relay = Relay {
        is_v6: socket.local_addr()?.is_ipv6(),
        socket,
        access: Arc::new(access),
        access_tx,
        sessions: HashMap::new(),
        by_addr: HashMap::new(),
        challenges: HashMap::new(),
        authorizing: HashMap::new(),
        access_cache: HashMap::new(),
        metrics,
    };
    let mut buf = vec![0; proto::MAX_PACKET_LEN];
    let mut sweep = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        tokio::select! {
            res = relay.recv(&mut buf) => match res {
                Ok((len, src)) => relay.handle_packet(&mut buf[..len], src).await,
                // ICMP errors of previous sends are reported on some platforms
                Err(e) => log::debug!("Receive error: {e}"),
            },
            Some((key, allowed)) = access_rx.recv() => relay.handle_access(key, allowed).await,
            _ = sweep.tick() => relay.sweep(),
        }
    }
}

impl Relay {
    async fn handle_packet(&mut self, buf: &mut [u8], src: SocketAddr) {
        match proto::decode(buf) {
            Some(Message::Data { key, .. }) => {
                let dst = *key;
                self.forward(buf, src, &dst).await;
            }
            Some(Message::Keepalive) => {
                self.metrics.other_packets_recv.inc();
                self.metrics.got_keepalive.inc();
                if self.touch(&src).is_some() {
                    if self.send_control(&proto::encode_keepalive_ack(), src).await {
                        self.metrics.sent_keepalive_ack.inc();
                    }
                } else {
                    self.send_not_registered(src).await;
                }
            }
            Some(Message::Hello { version, key }) => {
                if version != proto::VERSION {
                    self.metrics.unknown_packets.inc();
                    log::debug!("Unsupported version {version} from {src}");
                    return;
                }
                self.metrics.other_packets_recv.inc();
                if self.challenges.len() >= MAX_PENDING_CHALLENGES && !self.challenges.contains_key(&src) {
                    self.metrics.challenges_dropped.inc();
                    log::debug!("Too many pending challenges, dropping hello from {src}");
                    return;
                }
                let nonce = proto::random_nonce();
                self.challenges.insert(src, Challenge { key, nonce, expires: Instant::now() + CHALLENGE_TTL });
                self.send_control(&proto::encode_challenge(&nonce, &src), src).await;
            }
            Some(Message::Auth { key, nonce, signature }) => {
                self.metrics.other_packets_recv.inc();
                let is_expected = self.challenges.get(&src)
                    .is_some_and(|c| c.key == key && c.nonce == nonce && c.expires > Instant::now());
                if !is_expected {
                    self.metrics.auth_failures.inc();
                    return;
                }
                self.challenges.remove(&src);
                let Some(public_key) = proto::verify_auth(&key, &nonce, &signature, &src) else {
                    self.metrics.auth_failures.inc();
                    log::info!("Invalid signature from {src}");
                    return;
                };
                match self.access_cache.get(&key) {
                    Some((true, _)) => self.bind(key, src).await,
                    Some((false, _)) => {
                        self.metrics.access_denied.inc();
                        log::debug!("Access denied: {} ({src})", public_key.fmt_short());
                    }
                    None => {
                        self.authorizing.insert(key, src);
                        self.spawn_access_check(key, public_key);
                    }
                }
            }
            Some(Message::Challenge { .. } | Message::Registered | Message::KeepaliveAck | Message::NotRegistered)
            | None => {
                self.metrics.unknown_packets.inc();
            }
        }
    }

    async fn forward(&mut self, buf: &mut [u8], src: SocketAddr, dst: &Key) {
        let Some(src_session) = self.touch(&src).and_then(|key| self.sessions.get(&key).map(|s| (key, s))) else {
            let counters = self.metrics.node(&NodeLabels::unregistered());
            counters.recv(buf.len());
            counters.data_packets_dropped.inc();
            self.send_not_registered(src).await;
            return;
        };
        let (src_key, src_counters) = (src_session.0, &src_session.1.counters);
        src_counters.recv(buf.len());
        let Some(dst_session) = self.sessions.get(dst) else {
            src_counters.data_packets_dropped.inc();
            return;
        };
        proto::encode_data_header(buf, &src_key);
        if self.send(buf, dst_session.addr).await {
            dst_session.counters.sent(buf.len());
        } else {
            src_counters.data_packets_dropped.inc();
        }
    }

    /// Refreshes a session of a node and returns its key
    fn touch(&mut self, addr: &SocketAddr) -> Option<Key> {
        let key = *self.by_addr.get(addr)?;
        if let Some(session) = self.sessions.get_mut(&key) {
            session.last_seen = Instant::now();
        }
        Some(key)
    }

    async fn bind(&mut self, key: Key, addr: SocketAddr) {
        let now = Instant::now();
        let counters = self.metrics.node(&node_labels(&key));
        let old_session = self.sessions.insert(key, Session { addr, last_seen: now, checked_at: now, counters });
        if let Some(old_session) = old_session {
            if old_session.addr != addr {
                self.by_addr.remove(&old_session.addr);
            }
        }
        if let Some(old_key) = self.by_addr.insert(addr, key) {
            if old_key != key && self.sessions.remove(&old_key).is_some() {
                self.metrics.remove_node(&node_labels(&old_key));
            }
        }
        self.metrics.registrations.inc();
        self.metrics.sessions.set(self.sessions.len() as i64);
        log::info!("Registered {} from {addr}", fmt_key(&key));
        self.send_control(&proto::encode_registered(), addr).await;
    }

    fn remove_session(&mut self, key: &Key) {
        if let Some(session) = self.sessions.remove(key) {
            self.by_addr.remove(&session.addr);
            self.metrics.remove_node(&node_labels(key));
        }
        self.metrics.sessions.set(self.sessions.len() as i64);
    }

    fn spawn_access_check(&self, key: Key, public_key: PublicKey) {
        let access = self.access.clone();
        let access_tx = self.access_tx.clone();
        let metrics = self.metrics.clone();
        tokio::spawn(async move {
            let allowed = match access.check(&public_key).await {
                Ok(allowed) => Some(allowed),
                Err(e) => {
                    metrics.access_check_errors.inc();
                    log::warn!("Access check of {} failed: {e}", public_key.fmt_short());
                    None
                }
            };
            let _ = access_tx.send((key, allowed)).await;
        });
    }

    async fn handle_access(&mut self, key: Key, allowed: Option<bool>) {
        if let Some(allowed) = allowed {
            self.access_cache.insert(key, (allowed, Instant::now()));
        }
        match (self.authorizing.remove(&key), allowed) {
            (Some(addr), Some(true)) => self.bind(key, addr).await,
            (Some(addr), Some(false)) => {
                self.metrics.access_denied.inc();
                log::info!("Access denied: {} ({addr})", fmt_key(&key));
            }
            (Some(addr), None) => log::info!("Access denied: {} ({addr})", fmt_key(&key)),
            // A failed recheck keeps the session, so the relay survives restarts of the check service
            (None, Some(false)) if self.sessions.contains_key(&key) => {
                self.metrics.access_revoked.inc();
                log::info!("Access revoked: {}", fmt_key(&key));
                self.remove_session(&key);
            }
            (None, _) => {}
        }
    }

    fn sweep(&mut self) {
        let now = Instant::now();
        self.challenges.retain(|_, c| c.expires > now);
        self.access_cache.retain(|_, (_, checked_at)| now.duration_since(*checked_at) < ACCESS_CACHE_TTL);

        let expired = self.sessions.iter()
            .filter(|(_, s)| now.duration_since(s.last_seen) > proto::SESSION_TTL)
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        for key in expired {
            self.metrics.sessions_expired.inc();
            log::info!("Session expired: {}", fmt_key(&key));
            self.remove_session(&key);
        }

        let mut recheck = Vec::new();
        for (key, session) in self.sessions.iter_mut() {
            if now.duration_since(session.checked_at) >= ACCESS_CACHE_TTL {
                session.checked_at = now;
                recheck.push(*key);
            }
        }
        for key in recheck {
            if let Ok(public_key) = PublicKey::from_bytes(&key) {
                self.spawn_access_check(key, public_key);
            }
        }
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (len, src) = self.socket.recv_from(buf).await?;
        Ok((len, proto::canonical_addr(src)))
    }

    async fn send_not_registered(&self, addr: SocketAddr) {
        if self.send_control(&proto::encode_not_registered(), addr).await {
            self.metrics.sent_not_registered.inc();
        }
    }

    /// Sends a packet that is not `Data`
    async fn send_control(&self, packet: &[u8], addr: SocketAddr) -> bool {
        let sent = self.send(packet, addr).await;
        if sent {
            self.metrics.other_packets_sent.inc();
        }
        sent
    }

    /// Returns `false` if sending failed
    async fn send(&self, packet: &[u8], addr: SocketAddr) -> bool {
        match self.socket.send_to(packet, proto::socket_addr(self.is_v6, addr)).await {
            Ok(_) => true,
            Err(e) => {
                self.metrics.send_errors.inc();
                log::debug!("Cannot send to {addr}: {e}");
                false
            }
        }
    }
}

fn fmt_key(key: &Key) -> String {
    match PublicKey::from_bytes(key) {
        Ok(key) => key.fmt_short().to_string(),
        Err(_) => "<invalid key>".to_string(),
    }
}

/// Only keys of registered nodes are passed, they are verified
fn node_labels(key: &Key) -> NodeLabels {
    NodeLabels { endpoint: fmt_key(key) }
}

#[cfg(test)]
mod tests {
    use iroh_base::SecretKey;
    use iroh_metrics::{Counter, Family, MetricsSource};

    use super::*;

    fn count(family: &Family<NodeLabels, Counter>, labels: &NodeLabels) -> u64 {
        family.get(labels).map_or(0, |counter| counter.get())
    }

    struct Node {
        socket: UdpSocket,
        secret_key: SecretKey,
    }

    impl Node {
        async fn new(seed: u8) -> Self {
            Node {
                socket: UdpSocket::bind("127.0.0.1:0").await.unwrap(),
                secret_key: SecretKey::from_bytes(&[seed; 32]),
            }
        }

        fn key(&self) -> Key {
            *self.secret_key.public().as_bytes()
        }

        fn labels(&self) -> NodeLabels {
            node_labels(&self.key())
        }

        async fn recv(&self) -> Vec<u8> {
            let mut buf = vec![0; proto::MAX_PACKET_LEN];
            let len = tokio::time::timeout(Duration::from_secs(2), self.socket.recv(&mut buf)).await
                .expect("Receive timed out")
                .unwrap();
            buf.truncate(len);
            buf
        }

        async fn register(&self, relay: SocketAddr) {
            self.socket.send_to(&proto::encode_hello(&self.secret_key.public()), relay).await.unwrap();
            let challenge = self.recv().await;
            let Some(Message::Challenge { nonce, observed_addr }) = proto::decode(&challenge) else {
                panic!("Expected a challenge: {challenge:?}");
            };
            assert_eq!(observed_addr, self.socket.local_addr().unwrap());
            self.socket.send_to(&proto::encode_auth(&self.secret_key, &nonce, &observed_addr), relay).await
                .unwrap();
            assert_eq!(proto::decode(&self.recv().await), Some(Message::Registered));
        }

        async fn send_data(&self, relay: SocketAddr, dst: &Key, payload: &[u8]) {
            let mut packet = vec![0; proto::DATA_HEADER_LEN];
            proto::encode_data_header(&mut packet, dst);
            packet.extend_from_slice(payload);
            self.socket.send_to(&packet, relay).await.unwrap();
        }
    }

    async fn start_relay() -> (SocketAddr, Arc<Metrics>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let metrics = Arc::new(Metrics::default());
        tokio::spawn(run(socket, Access::AllowAll, metrics.clone()));
        (addr, metrics)
    }

    #[tokio::test]
    async fn test_forward() {
        let (relay, metrics) = start_relay().await;
        let a = Node::new(1).await;
        let b = Node::new(2).await;
        a.register(relay).await;
        b.register(relay).await;

        a.send_data(relay, &b.key(), b"hello").await;
        let packet = b.recv().await;
        assert_eq!(proto::decode(&packet), Some(Message::Data { key: &a.key(), payload: b"hello" }));

        b.send_data(relay, &a.key(), b"world").await;
        let packet = a.recv().await;
        assert_eq!(proto::decode(&packet), Some(Message::Data { key: &b.key(), payload: b"world" }));

        a.socket.send_to(&proto::encode_keepalive(), relay).await.unwrap();
        assert_eq!(proto::decode(&a.recv().await), Some(Message::KeepaliveAck));

        // Packets are processed in order, so the ack means the forwarded packets are counted
        assert_eq!(metrics.sessions.get(), 2);
        assert_eq!(metrics.registrations.get(), 2);
        assert_eq!(metrics.got_keepalive.get(), 1);
        let packet_len = proto::DATA_HEADER_LEN as u64 + 5;
        for node in [&a, &b] {
            assert_eq!(count(&metrics.data_packets_recv, &node.labels()), 1);
            assert_eq!(count(&metrics.bytes_recv, &node.labels()), packet_len);
            assert_eq!(count(&metrics.data_packets_sent, &node.labels()), 1);
            assert_eq!(count(&metrics.bytes_sent, &node.labels()), packet_len);
            assert_eq!(count(&metrics.data_packets_dropped, &node.labels()), 0);
        }
    }

    #[tokio::test]
    async fn test_node_metrics() {
        let (relay, metrics) = start_relay().await;
        let a = Node::new(1).await;
        let b = Node::new(2).await;
        a.register(relay).await;
        b.register(relay).await;

        a.send_data(relay, &b.key(), b"one").await;
        a.send_data(relay, &b.key(), b"two").await;
        b.recv().await;
        b.recv().await;
        // Nobody is registered with this key
        a.send_data(relay, &[0; proto::KEY_LEN], b"lost").await;
        a.socket.send_to(&proto::encode_keepalive(), relay).await.unwrap();
        assert_eq!(proto::decode(&a.recv().await), Some(Message::KeepaliveAck));

        // The sender sends, the recipient receives
        assert_eq!(count(&metrics.data_packets_recv, &a.labels()), 3);
        assert_eq!(count(&metrics.data_packets_dropped, &a.labels()), 1);
        assert_eq!(count(&metrics.data_packets_sent, &a.labels()), 0);
        assert_eq!(count(&metrics.data_packets_recv, &b.labels()), 0);
        assert_eq!(count(&metrics.data_packets_sent, &b.labels()), 2);
        assert_eq!(count(&metrics.bytes_sent, &b.labels()), 2 * (proto::DATA_HEADER_LEN as u64 + 3));
        // The destination key of the lost packet is not a label
        assert_eq!(metrics.data_packets_recv.len(), 2);

        // Another key from the same address replaces the session of `a` with its labels
        let a_labels = a.labels();
        let c = Node { socket: a.socket, secret_key: SecretKey::from_bytes(&[3; 32]) };
        c.register(relay).await;
        assert!(metrics.data_packets_recv.get(&a_labels).is_none());
        assert!(metrics.bytes_sent.get(&a_labels).is_none());
        assert!(metrics.data_packets_recv.get(&c.labels()).is_some());
        assert_eq!(metrics.sessions.get(), 2);

        let mut registry = iroh_metrics::Registry::default();
        registry.register(metrics.clone());
        let output = registry.encode_openmetrics_to_string().unwrap();
        let b_bytes = format!("udprelay_bytes_sent_total{{endpoint=\"{}\"}} 72", b.labels().endpoint);
        assert!(output.contains(&b_bytes), "{output}");
    }

    #[tokio::test]
    async fn test_not_registered() {
        let (relay, metrics) = start_relay().await;
        let a = Node::new(1).await;
        let b = Node::new(2).await;
        b.register(relay).await;

        a.send_data(relay, &b.key(), b"hello").await;
        assert_eq!(proto::decode(&a.recv().await), Some(Message::NotRegistered));
        a.socket.send_to(&proto::encode_keepalive(), relay).await.unwrap();
        assert_eq!(proto::decode(&a.recv().await), Some(Message::NotRegistered));

        let unregistered = NodeLabels::unregistered();
        assert_eq!(count(&metrics.data_packets_recv, &unregistered), 1);
        assert_eq!(count(&metrics.data_packets_dropped, &unregistered), 1);
        assert_eq!(count(&metrics.data_packets_sent, &b.labels()), 0);
        assert_eq!(metrics.sent_not_registered.get(), 2);
    }

    #[tokio::test]
    async fn test_invalid_auth() {
        let (relay, metrics) = start_relay().await;
        let a = Node::new(1).await;
        let b = Node::new(2).await;
        b.register(relay).await;

        // Claims the key of `b` but signs with its own key
        a.socket.send_to(&proto::encode_hello(&b.secret_key.public()), relay).await.unwrap();
        let Some(Message::Challenge { nonce, observed_addr }) = proto::decode(&a.recv().await) else {
            panic!("Expected a challenge");
        };
        let mut auth = proto::encode_auth(&a.secret_key, &nonce, &observed_addr);
        auth[1..1 + proto::KEY_LEN].copy_from_slice(&b.key());
        a.socket.send_to(&auth, relay).await.unwrap();

        // `b` is still bound to its own address
        let c = Node::new(3).await;
        c.register(relay).await;
        c.send_data(relay, &b.key(), b"to b").await;
        assert_eq!(proto::decode(&b.recv().await), Some(Message::Data { key: &c.key(), payload: b"to b" }));
        a.socket.send_to(&proto::encode_keepalive(), relay).await.unwrap();
        assert_eq!(proto::decode(&a.recv().await), Some(Message::NotRegistered));

        assert_eq!(metrics.auth_failures.get(), 1);
        assert_eq!(metrics.registrations.get(), 2);
    }

    #[tokio::test]
    async fn test_rebind() {
        let (relay, metrics) = start_relay().await;
        let a = Node::new(1).await;
        let b = Node::new(2).await;
        b.register(relay).await;
        a.register(relay).await;
        // The same key from a new address, e.g. after a NAT rebinding
        let a2 = Node::new(1).await;
        a2.register(relay).await;

        b.send_data(relay, &a.key(), b"hello").await;
        assert_eq!(proto::decode(&a2.recv().await), Some(Message::Data { key: &b.key(), payload: b"hello" }));
        a.send_data(relay, &b.key(), b"stale").await;
        assert_eq!(proto::decode(&a.recv().await), Some(Message::NotRegistered));

        // The new address replaces the old one, the node keeps its counters
        assert_eq!(metrics.sessions.get(), 2);
        assert_eq!(metrics.registrations.get(), 3);
        assert_eq!(count(&metrics.data_packets_sent, &a.labels()), 1);
        assert_eq!(count(&metrics.data_packets_dropped, &NodeLabels::unregistered()), 1);
    }
}
