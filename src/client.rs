//! Iroh custom transport that sends packets through the UDP relay.
//!
//! It is a fallback for connections where NAT hole punching fails:
//! [`DirectFirstPathSelector`] prefers any direct path over the relay.
//! A relay address of a peer is not exchanged by iroh itself, so a connecting
//! side adds it to the peer address with [`peer_addr`].

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use iroh::endpoint::transports::{
    CustomEndpoint, CustomSender, CustomTransport, FourTuple, PathSelection, PathSelectionContext,
    PathSelector, RecvInfo, Transmit,
};
use iroh::{EndpointId, SecretKey, TransportAddr};
use iroh_base::CustomAddr;
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::{CancellationToken, DropGuard};

use crate::proto::{self, Key, Message, Nonce};

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);
const REGISTER_ATTEMPTS: usize = 3;
const MIN_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(10);
/// Registration is considered lost after this many keepalives without an answer
const MAX_MISSED_KEEPALIVES: u32 = 3;
/// The same stickiness as iroh's default path selector has, it avoids flapping
const RTT_SWITCHING_MIN: Duration = Duration::from_millis(5);

/// Address of a peer behind the relay
pub fn peer_addr(id: EndpointId) -> TransportAddr {
    TransportAddr::Custom(custom_addr(id.as_bytes()))
}

fn custom_addr(key: &Key) -> CustomAddr {
    CustomAddr::from_parts(proto::TRANSPORT_ID, key)
}

pub struct UdpRelayTransport {
    /// `host:port` of the relay, it's resolved on every registration
    relay: String,
    secret_key: SecretKey,
}

impl UdpRelayTransport {
    pub fn new(relay: String, secret_key: SecretKey) -> Self {
        Self { relay, secret_key }
    }
}

impl fmt::Debug for UdpRelayTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpRelayTransport").field("relay", &self.relay).finish()
    }
}

impl CustomTransport for UdpRelayTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let runtime = tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        // Only IPv4: a dual stack socket is not portable (it's IPv6 only on Windows by default)
        let socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        socket.set_nonblocking(true)?;
        let socket = {
            let _guard = runtime.enter();
            UdpSocket::from_std(socket)?
        };
        let shared = Arc::new(Shared {
            socket,
            relay_addr: RwLock::new(None),
            registered: AtomicBool::new(false),
        });
        let (control_tx, control_rx) = mpsc::channel(16);
        let cancel = CancellationToken::new();
        // Does not fail when the relay is unreachable, an endpoint can start before its uplink
        runtime.spawn(cancel.clone().run_until_cancelled_owned(
            control(shared.clone(), self.relay.clone(), self.secret_key.clone(), control_rx)
        ));
        let local_addr = custom_addr(self.secret_key.public().as_bytes());
        Ok(Box::new(RelayEndpoint {
            shared,
            control_tx,
            local_addrs: n0_watcher::Watchable::new(vec![local_addr.clone()]),
            local_addr,
            _cancel: cancel.drop_guard(),
        }))
    }
}

#[derive(Debug)]
struct Shared {
    socket: UdpSocket,
    relay_addr: RwLock<Option<SocketAddr>>,
    registered: AtomicBool,
}

impl Shared {
    fn relay_addr(&self) -> Option<SocketAddr> {
        *self.relay_addr.read().expect("poisoned")
    }
}

/// Messages from the relay for the control task
enum Control {
    Challenge { nonce: Nonce, observed_addr: SocketAddr },
    Registered,
    KeepaliveAck,
    NotRegistered,
}

struct RelayEndpoint {
    shared: Arc<Shared>,
    control_tx: mpsc::Sender<Control>,
    local_addr: CustomAddr,
    local_addrs: n0_watcher::Watchable<Vec<CustomAddr>>,
    _cancel: DropGuard,
}

impl fmt::Debug for RelayEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayEndpoint").field("shared", &self.shared).finish()
    }
}

impl CustomEndpoint for RelayEndpoint {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.local_addrs.watch()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(RelaySender { shared: self.shared.clone() })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        recv_infos: &mut [RecvInfo],
    ) -> Poll<io::Result<usize>> {
        let mut filled = 0;
        while filled < bufs.len() {
            let mut read_buf = ReadBuf::new(&mut bufs[filled]);
            let src = match self.shared.socket.poll_recv_from(cx, &mut read_buf) {
                Poll::Pending if filled == 0 => return Poll::Pending,
                Poll::Pending => break,
                Poll::Ready(Ok(src)) => proto::canonical_addr(src),
                // ICMP errors of previous sends are reported on some platforms
                Poll::Ready(Err(e)) => {
                    log::debug!("UDP relay receive error: {e}");
                    continue;
                }
            };
            let len = read_buf.filled().len();
            if Some(src) != self.shared.relay_addr() {
                continue;
            }
            let control = match proto::decode(&bufs[filled][..len]) {
                Some(Message::Data { key, payload }) => {
                    let (remote, payload_len) = (custom_addr(key), payload.len());
                    bufs[filled].copy_within(proto::DATA_HEADER_LEN..len, 0);
                    metas[filled].len = payload_len;
                    metas[filled].stride = payload_len;
                    recv_infos[filled] = RecvInfo::new(remote, Some(self.local_addr.clone()));
                    filled += 1;
                    continue;
                }
                Some(Message::Challenge { nonce, observed_addr }) => Control::Challenge { nonce, observed_addr },
                Some(Message::Registered) => Control::Registered,
                Some(Message::KeepaliveAck) => Control::KeepaliveAck,
                Some(Message::NotRegistered) => Control::NotRegistered,
                Some(Message::Hello { .. } | Message::Auth { .. } | Message::Keepalive) | None => continue,
            };
            let _ = self.control_tx.try_send(control);
        }
        Poll::Ready(Ok(filled))
    }
}

#[derive(Debug)]
struct RelaySender {
    shared: Arc<Shared>,
}

impl CustomSender for RelaySender {
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        addr.id() == proto::TRANSPORT_ID && addr.data().len() == proto::KEY_LEN
    }

    fn poll_send(
        &self,
        cx: &mut Context,
        dst: &CustomAddr,
        _src: Option<&CustomAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        let Ok(key) = <&Key>::try_from(dst.data()) else {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidInput, "Invalid udp relay address")));
        };
        // Packets are dropped until the registration, QUIC retransmits them
        let relay_addr = match self.shared.relay_addr() {
            Some(relay_addr) if self.shared.registered.load(Ordering::Acquire) => relay_addr,
            _ => return Poll::Ready(Ok(())),
        };
        let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len()).max(1);
        let mut buf = [0; proto::MAX_PACKET_LEN];
        for segment in transmit.contents.chunks(segment_size) {
            let len = proto::DATA_HEADER_LEN + segment.len();
            if len > buf.len() {
                log::warn!("Packet of {} bytes is too large for the udp relay", segment.len());
                continue;
            }
            proto::encode_data_header(&mut buf, key);
            buf[proto::DATA_HEADER_LEN..len].copy_from_slice(segment);
            match self.shared.socket.poll_send_to(cx, &buf[..len], relay_addr) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// Keeps the endpoint registered at the relay
async fn control(
    shared: Arc<Shared>, relay: String, secret_key: SecretKey, mut control_rx: mpsc::Receiver<Control>,
) {
    let mut backoff = MIN_BACKOFF;
    let mut last_error = None;
    loop {
        match register(&shared, &relay, &secret_key, &mut control_rx).await {
            Ok(relay_addr) => {
                log::info!("Registered at udp relay {relay} ({relay_addr})");
                backoff = MIN_BACKOFF;
                last_error = None;
                shared.registered.store(true, Ordering::Release);
                keep_alive(&shared, relay_addr, &mut control_rx).await;
                shared.registered.store(false, Ordering::Release);
                log::warn!("Lost registration at udp relay {relay}");
            }
            Err(e) => {
                // An unreachable relay should not flood logs
                if last_error.as_ref() != Some(&e) {
                    log::warn!("Cannot register at udp relay {relay}: {e}");
                    last_error = Some(e);
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

async fn register(
    shared: &Shared, relay: &str, secret_key: &SecretKey, control_rx: &mut mpsc::Receiver<Control>,
) -> Result<SocketAddr, String> {
    let relay_addr = tokio::net::lookup_host(relay).await
        .map_err(|e| format!("Cannot resolve: {e}"))?
        .find(SocketAddr::is_ipv4)
        .ok_or("No IPv4 address")?;
    *shared.relay_addr.write().expect("poisoned") = Some(relay_addr);
    // Answers of previous attempts
    while control_rx.try_recv().is_ok() {}

    let hello = proto::encode_hello(&secret_key.public());
    for _ in 0..REGISTER_ATTEMPTS {
        shared.socket.send_to(&hello, relay_addr).await
            .map_err(|e| format!("Cannot send: {e}"))?;
        let challenge = wait_for(control_rx, |msg| match msg {
            Control::Challenge { nonce, observed_addr } => Some((nonce, observed_addr)),
            _ => None,
        }).await;
        let Some((nonce, observed_addr)) = challenge else {
            continue;
        };
        shared.socket.send_to(&proto::encode_auth(secret_key, &nonce, &observed_addr), relay_addr).await
            .map_err(|e| format!("Cannot send: {e}"))?;
        if wait_for(control_rx, |msg| matches!(msg, Control::Registered).then_some(())).await.is_some() {
            return Ok(relay_addr);
        }
    }
    Err("No answer, is the relay running and the endpoint allowed to use it?".to_string())
}

async fn wait_for<T>(control_rx: &mut mpsc::Receiver<Control>, f: impl Fn(Control) -> Option<T>) -> Option<T> {
    let wait = async {
        while let Some(msg) = control_rx.recv().await {
            if let Some(res) = f(msg) {
                return Some(res);
            }
        }
        None
    };
    tokio::time::timeout(RESPONSE_TIMEOUT, wait).await.ok().flatten()
}

/// Completes when the registration is lost
async fn keep_alive(shared: &Shared, relay_addr: SocketAddr, control_rx: &mut mpsc::Receiver<Control>) {
    let mut last_ack = Instant::now();
    let mut interval = tokio::time::interval_at(
        tokio::time::Instant::now() + proto::KEEPALIVE_INTERVAL, proto::KEEPALIVE_INTERVAL
    );
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if last_ack.elapsed() > proto::KEEPALIVE_INTERVAL * MAX_MISSED_KEEPALIVES {
                    return;
                }
                if let Err(e) = shared.socket.send_to(&proto::encode_keepalive(), relay_addr).await {
                    log::debug!("Cannot send keepalive to udp relay: {e}");
                }
            }
            msg = control_rx.recv() => match msg {
                Some(Control::KeepaliveAck) => last_ack = Instant::now(),
                Some(Control::NotRegistered) | None => return,
                Some(Control::Challenge { .. } | Control::Registered) => {}
            }
        }
    }
}

/// Prefers direct paths, then the udp relay, then the iroh relay.
/// Within the same kind a path with the lowest RTT wins.
///
/// Unlike iroh's default selector, the udp relay never wins over a direct path
/// even if its RTT is lower.
#[derive(Debug, Default)]
pub struct DirectFirstPathSelector;

impl PathSelector for DirectFirstPathSelector {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        let current = ctx.current();
        // Paths whose stats cannot be read are closed concurrently
        let paths = ctx.paths()
            .filter_map(|p| p.stats().map(|stats| (p, stats.rtt)))
            .collect::<Vec<_>>();
        let candidates = paths.iter().map(|(p, rtt)| Candidate {
            rank: rank(p.network_path()),
            rtt: *rtt,
            is_current: Some(p.network_path()) == current,
        });
        let mut selection = PathSelection::none();
        if let Some(i) = choose(candidates) {
            selection.set(&paths[i].0);
        }
        selection
    }
}

fn rank(path: &FourTuple) -> u8 {
    match path {
        FourTuple::Ip { .. } => 0,
        FourTuple::Custom { .. } => 1,
        FourTuple::Relay { .. } => 2,
    }
}

struct Candidate {
    rank: u8,
    rtt: Duration,
    is_current: bool,
}

/// Returns an index of a candidate to switch to, `None` keeps the current path
fn choose(candidates: impl Iterator<Item = Candidate>) -> Option<usize> {
    let mut best: Option<(usize, (u8, Duration))> = None;
    let mut current: Option<(u8, Duration)> = None;
    for (i, candidate) in candidates.enumerate() {
        let key = (candidate.rank, candidate.rtt);
        // The same path can be on multiple connections
        if candidate.is_current && current.is_none_or(|c| key < c) {
            current = Some(key);
        }
        if best.is_none_or(|(_, b)| key < b) {
            best = Some((i, key));
        }
    }
    let (best_i, (best_rank, best_rtt)) = best?;
    match current {
        Some((current_rank, current_rtt))
            if current_rank == best_rank && best_rtt + RTT_SWITCHING_MIN > current_rtt => None,
        _ => Some(best_i),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidates(paths: &[(u8, u64, bool)]) -> impl Iterator<Item = Candidate> + '_ {
        paths.iter().map(|&(rank, rtt_ms, is_current)| Candidate {
            rank,
            rtt: Duration::from_millis(rtt_ms),
            is_current,
        })
    }

    #[test]
    fn test_choose() {
        assert_eq!(choose(candidates(&[])), None);
        // No current path
        assert_eq!(choose(candidates(&[(1, 10, false), (0, 50, false)])), Some(1));
        // A direct path wins over a faster relayed one
        assert_eq!(choose(candidates(&[(1, 10, true), (0, 50, false)])), Some(1));
        // The udp relay wins over the iroh relay
        assert_eq!(choose(candidates(&[(2, 10, true), (1, 50, false)])), Some(1));
        // Falls back to the udp relay when there is no direct path
        assert_eq!(choose(candidates(&[(1, 50, false), (2, 10, false)])), Some(0));
        // Stickiness within the same kind
        assert_eq!(choose(candidates(&[(0, 20, true), (0, 17, false)])), None);
        assert_eq!(choose(candidates(&[(0, 20, true), (0, 15, false)])), Some(1));
        // The current path is the best one
        assert_eq!(choose(candidates(&[(0, 10, true), (1, 5, false)])), None);
    }
}
