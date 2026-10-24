# iroh-udp-relay

A UDP relay for [iroh](https://iroh.computer) connections, and an iroh custom transport that uses it.

When NAT hole punching fails, iroh sends traffic through the iroh relay over a TCP WebSocket. Then one lost packet delays every packet behind it, which hurts real-time traffic such as video or remote control. This relay forwards each QUIC packet as a single UDP datagram instead, so a lost packet only loses itself.

The relay is a fallback. A direct path always wins when there is one. The iroh relay is still needed for hole punching (address discovery and coordination), but it no longer has to carry data.

## How it works

Every endpoint keeps a registration at the relay:

1. **Hello:** the endpoint sends its public key.
2. **Challenge:** the relay answers with a random nonce and the endpoint's address as the relay sees it.
3. **Auth:** the endpoint signs the nonce and that address with its secret key.
4. **Registered:** the relay checks the signature, asks the optional access check, and binds the key to the address.

After that, the endpoint sends a keepalive every 5 seconds. A session without traffic expires after 30 seconds.

**Forwarding:** a data packet carries the destination key. The relay replaces it with the sender's key, taken from the registration rather than from the packet, and forwards it to the destination's address. So an endpoint cannot pretend to be another one.

**Unknown senders:** a packet from an unregistered address is answered with `NotRegistered`, and the endpoint registers again right away. This covers NAT rebinding and relay restarts.

**Amplification:** a `Hello` is padded to at least the size of a `Challenge`, so a spoofed `Hello` can't be used to amplify traffic.

**Packet size:** each data packet carries a 33-byte header. QUIC's path MTU discovery measures the relay path with the header included, so datagram sizes adjust on their own.

## Server

```sh
cargo build --release --features server
./target/release/iroh-udp-relay --access-url http://localhost:8080/ --metrics-addr 127.0.0.1:9091
```

| Option | Description |
|---|---|
| `--bind-addr` | UDP address to listen on, `0.0.0.0:7843` by default, next to the iroh relay's QUIC address discovery port (7842) |
| `--access-url` | HTTP access check, see below. Without it any endpoint may use the relay |
| `--access-token-file` | File with a bearer token for the access check |
| `--metrics-addr` | TCP address to serve Prometheus metrics on (`/metrics`). Disabled if not set |
| `--endpoint-labels` | Label traffic metrics with endpoint ids, see [Metrics](#metrics). Disabled by default |

Set the log level with `RUST_LOG` (`info` by default).

### Access check

This is the same HTTP check iroh-relay uses (`access.http` in its config), so one service can serve both relays.

- **Request:** the relay sends a `POST` with the endpoint id in the `X-Iroh-Endpoint-Id` header. With a token file, it also sends `Authorization: Bearer <token>`.
- **Answer:** a `200` response with the body `true` allows the endpoint. Anything else denies it.
- **Caching:** answers are cached for 60 seconds. Registered endpoints are checked again every 60 seconds, so revoking access drops a session within a minute.
- **Failures:** if a recheck fails (for example the check service is down), the session is kept.
- **Plain HTTP only:** only `http://` URLs are supported. The check is meant to run on the same host or a private network.

### Metrics

The metrics follow iroh-relay's `relayserver` group, with the prefix `udprelay_`.

| Metric | Description |
|---|---|
| `bytes_relayed_total` | Relayed traffic, including the data header |
| `data_packets_relayed_total`, `data_packets_dropped_total` | Relayed and dropped data packets |
| `other_packets_recv_total`, `other_packets_sent_total` | Control packets |
| `unknown_packets_total`, `send_errors_total` | Unknown packets and failed sends |
| `got_keepalive_total`, `sent_keepalive_ack_total` | Keepalives |
| `sent_not_registered_total` | Requests for an endpoint to register again |
| `sessions` | Registered endpoints (gauge) |
| `registrations_total`, `sessions_expired_total` | Session changes |
| `auth_failures_total`, `challenges_dropped_total` | Failed signatures, and `Hello`s dropped when too many challenges are pending |
| `access_denied_total`, `access_revoked_total`, `access_check_errors_total` | Access check results |

The traffic and data packet metrics have `src_endpoint` and `dst_endpoint` labels for the sender and the recipient.

- **Endpoint ids:** with `--endpoint-labels`, a registered endpoint is labeled with its short endpoint id, as iroh prints it in logs. For example `udprelay_bytes_relayed_total{src_endpoint="b2f36aadd4",dst_endpoint="5e0c1a9f3b"}`. This shows which endpoints talk to each other and how much, so it's better kept disabled on a public relay.
- **Without endpoint ids** (the default), every registered endpoint is labeled `registered`. The totals and drop reasons still work.
- **Unregistered endpoints:** a sender address or a recipient key without a registration is labeled `unregistered`.
- **Drop reasons:** the labels of a dropped packet tell why it was dropped. Either the sender or the recipient is `unregistered`, or both are registered and sending failed.
- **Bounded:** only registered endpoints get their own label, so there are at most as many series as pairs of endpoints that exchange traffic. The recipient key of a packet only becomes a label when that endpoint is registered, because a sender can put anything there.
- **Cleanup:** with endpoint ids, the series of an endpoint, as a sender or a recipient, are removed when its session expires, is revoked or is replaced. After that, its counters start from zero, which `rate()` and `increase()` handle as a reset.

Useful queries:
- traffic between endpoints: `sum by (src_endpoint, dst_endpoint) (rate(udprelay_bytes_relayed_total[5m]))`;
- sent or received by each endpoint: `sum by (src_endpoint)` or `sum by (dst_endpoint)`;
- total: `sum(rate(udprelay_bytes_relayed_total[5m]))`.

To use the server from your own code, call `server::run(socket, access, metrics, options)` with the `server` feature enabled.

## Client

```toml
[dependencies]
iroh-udp-relay = { git = "<repository url>", features = ["client"] }
```

Add the transport and the path selector to the endpoint:

```rust
use std::sync::Arc;

use iroh::endpoint::presets;
use iroh::{Endpoint, SecretKey};
use iroh_udp_relay::client::{DirectFirstPathSelector, UdpRelayTransport};

let secret_key = SecretKey::generate();
let endpoint = Endpoint::builder(presets::Minimal)
    .secret_key(secret_key.clone())
    .path_selector(Arc::new(DirectFirstPathSelector))
    .add_custom_transport(Arc::new(UdpRelayTransport::new(
        "relay.example.com:7843".to_string(),
        secret_key,
    )))
    .bind()
    .await?;
```

The connecting side has to add the peer's relay address itself, because iroh doesn't exchange custom transport addresses:

```rust
use iroh_udp_relay::client::peer_addr;

let addr = peer_endpoint_addr.with_addrs([peer_addr(peer_endpoint_addr.id)]);
let conn = endpoint.connect(addr, ALPN).await?;
```

Only the connecting side opens paths. The accepting side just needs the transport, so it is registered at the relay.

**Transport behaviour:**
- It registers in the background and keeps the registration alive.
- `bind` doesn't fail when the relay is unreachable, so an endpoint can start before its network is up.
- The relay host name is resolved again on every registration attempt.
- Packets are dropped while the endpoint is not registered. QUIC retransmits them.

**`DirectFirstPathSelector`** ranks paths: direct first, then the UDP relay, then the iroh relay. Within a rank, the lowest RTT wins, with 5 ms of stickiness to avoid flapping. iroh's default selector compares custom transports with direct paths by RTT, so it could pick the relay over a working direct path.

To keep relayed data off the iroh relay entirely, remove `TransportAddr::Relay` entries from the address you connect to.

## Limitations

- **Unstable API:** the client uses iroh's custom transport API (`unstable-custom-transports`), which can change in any iroh release. That's why iroh is pinned to an exact version.
- **IPv4 only:** the client reaches the relay over IPv4, because dual-stack sockets don't behave the same on every platform. The server listens on IPv4 by default; use `--bind-addr [::]:7843` to also accept IPv6.

## Testing

```sh
cargo test --all-features
```

The tests in `tests/client.rs` connect real iroh endpoints through an in-process relay. They check three cases:
- with only a relay address, the connection goes through the relay;
- with a dead direct address, it falls back to the relay;
- with a working direct address, the direct path wins.
