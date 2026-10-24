//! UDP relay for iroh connections when NAT hole punching fails.
//!
//! Unlike the iroh relay, which tunnels packets through a TCP WebSocket,
//! this relay forwards every QUIC datagram as a single UDP datagram,
//! so a lost packet does not delay the following ones.

#[cfg(feature = "client")]
pub mod client;
pub mod proto;
#[cfg(feature = "server")]
pub mod server;
