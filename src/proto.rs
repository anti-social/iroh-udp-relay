//! Wire format of the relay. Every message is a single UDP datagram,
//! its first byte is a message type.
//!
//! Registration of a node:
//! 1. node → relay: `Hello` with its public key
//! 2. relay → node: `Challenge` with a random nonce and the node address seen by the relay
//! 3. node → relay: `Auth` with a signature of the nonce and the address
//! 4. relay → node: `Registered`, the public key is now bound to the address
//!
//! Then the node sends `Keepalive` to keep its session and NAT mapping alive,
//! and `Data` with a destination key. The relay forwards `Data` replacing
//! the destination key with the key bound to the source address, so a node
//! cannot impersonate another one. A packet from an unknown address
//! is answered with `NotRegistered`, then the node registers again.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use iroh_base::{PublicKey, SecretKey, Signature};

pub const VERSION: u8 = 1;

/// Next to the QUIC address discovery port of an iroh relay (7842)
pub const DEFAULT_PORT: u16 = 7843;

/// Id of the iroh custom transport that uses the relay
pub const TRANSPORT_ID: u64 = 0x0049_5544_5052_4c59; // "IUDPRLY"

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 16;
pub const SIGNATURE_LEN: usize = 64;
/// Message type and a key
pub const DATA_HEADER_LEN: usize = 1 + KEY_LEN;
/// Enough for any QUIC packet plus the data header
pub const MAX_PACKET_LEN: usize = 2048;

/// Also keeps a NAT mapping of a node alive
pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
/// A session is dropped after this time without packets from a node
pub const SESSION_TTL: Duration = Duration::from_secs(30);

const DOMAIN_SEP: &[u8] = b"iroh-udp-relay v1 auth";

const HELLO: u8 = 1;
const CHALLENGE: u8 = 2;
const AUTH: u8 = 3;
const REGISTERED: u8 = 4;
const KEEPALIVE: u8 = 5;
const KEEPALIVE_ACK: u8 = 6;
const DATA: u8 = 7;
const NOT_REGISTERED: u8 = 8;

/// `Hello` is padded so that a spoofed one cannot be amplified by a larger `Challenge`
const HELLO_LEN: usize = 48;

pub type Key = [u8; KEY_LEN];
pub type Nonce = [u8; NONCE_LEN];

#[derive(Debug, PartialEq, Eq)]
pub enum Message<'a> {
    Hello { version: u8, key: Key },
    Challenge { nonce: Nonce, observed_addr: SocketAddr },
    Auth { key: Key, nonce: Nonce, signature: [u8; SIGNATURE_LEN] },
    Registered,
    Keepalive,
    KeepaliveAck,
    /// Destination key when sent by a node, source key when sent by the relay
    Data { key: &'a Key, payload: &'a [u8] },
    NotRegistered,
}

pub fn decode(packet: &[u8]) -> Option<Message<'_>> {
    let (&msg_type, body) = packet.split_first()?;
    let msg = match msg_type {
        HELLO => {
            if packet.len() < HELLO_LEN {
                return None;
            }
            Message::Hello { version: body[0], key: body[1..1 + KEY_LEN].try_into().ok()? }
        }
        CHALLENGE => {
            let nonce = body.get(..NONCE_LEN)?.try_into().ok()?;
            let observed_addr = decode_addr(&body[NONCE_LEN..])?;
            Message::Challenge { nonce, observed_addr }
        }
        AUTH => {
            if body.len() != KEY_LEN + NONCE_LEN + SIGNATURE_LEN {
                return None;
            }
            let (key, rest) = body.split_at(KEY_LEN);
            let (nonce, signature) = rest.split_at(NONCE_LEN);
            Message::Auth {
                key: key.try_into().ok()?,
                nonce: nonce.try_into().ok()?,
                signature: signature.try_into().ok()?,
            }
        }
        REGISTERED => Message::Registered,
        KEEPALIVE => Message::Keepalive,
        KEEPALIVE_ACK => Message::KeepaliveAck,
        DATA => {
            let key = body.get(..KEY_LEN)?.try_into().ok()?;
            Message::Data { key, payload: &body[KEY_LEN..] }
        }
        NOT_REGISTERED => Message::NotRegistered,
        _ => return None,
    };
    Some(msg)
}

pub fn encode_hello(key: &PublicKey) -> Vec<u8> {
    let mut buf = vec![0; HELLO_LEN];
    buf[0] = HELLO;
    buf[1] = VERSION;
    buf[2..2 + KEY_LEN].copy_from_slice(key.as_bytes());
    buf
}

pub fn encode_challenge(nonce: &Nonce, observed_addr: &SocketAddr) -> Vec<u8> {
    let mut buf = vec![CHALLENGE];
    buf.extend_from_slice(nonce);
    encode_addr(&mut buf, observed_addr);
    buf
}

/// Signs a challenge proving that the node owns the key and receives packets on the address
pub fn encode_auth(secret_key: &SecretKey, nonce: &Nonce, observed_addr: &SocketAddr) -> Vec<u8> {
    let signature = secret_key.sign(&signed_message(nonce, observed_addr));
    let mut buf = vec![AUTH];
    buf.extend_from_slice(secret_key.public().as_bytes());
    buf.extend_from_slice(nonce);
    buf.extend_from_slice(&signature.to_bytes());
    buf
}

/// Returns the public key if the signature of the challenge is valid
pub fn verify_auth(
    key: &Key, nonce: &Nonce, signature: &[u8; SIGNATURE_LEN], observed_addr: &SocketAddr,
) -> Option<PublicKey> {
    let public_key = PublicKey::from_bytes(key).ok()?;
    public_key.verify(&signed_message(nonce, observed_addr), &Signature::from_bytes(signature)).ok()?;
    Some(public_key)
}

pub fn encode_registered() -> [u8; 1] {
    [REGISTERED]
}

pub fn encode_keepalive() -> [u8; 1] {
    [KEEPALIVE]
}

pub fn encode_keepalive_ack() -> [u8; 1] {
    [KEEPALIVE_ACK]
}

pub fn encode_not_registered() -> [u8; 1] {
    [NOT_REGISTERED]
}

/// Writes a data header into the first [`DATA_HEADER_LEN`] bytes of the buffer
pub fn encode_data_header(buf: &mut [u8], key: &Key) {
    buf[0] = DATA;
    buf[1..DATA_HEADER_LEN].copy_from_slice(key);
}

pub fn random_nonce() -> Nonce {
    rand::random()
}

fn signed_message(nonce: &Nonce, observed_addr: &SocketAddr) -> Vec<u8> {
    let mut msg = DOMAIN_SEP.to_vec();
    msg.extend_from_slice(nonce);
    encode_addr(&mut msg, observed_addr);
    msg
}

fn encode_addr(buf: &mut Vec<u8>, addr: &SocketAddr) {
    match canonical_addr(*addr).ip() {
        IpAddr::V4(ip) => {
            buf.push(4);
            buf.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buf.push(6);
            buf.extend_from_slice(&ip.octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
}

fn decode_addr(buf: &[u8]) -> Option<SocketAddr> {
    let (&family, rest) = buf.split_first()?;
    let (ip, rest): (IpAddr, _) = match family {
        4 => {
            let octets: [u8; 4] = rest.get(..4)?.try_into().ok()?;
            (Ipv4Addr::from(octets).into(), &rest[4..])
        }
        6 => {
            let octets: [u8; 16] = rest.get(..16)?.try_into().ok()?;
            (Ipv6Addr::from(octets).into(), &rest[16..])
        }
        _ => return None,
    };
    let port = u16::from_be_bytes(rest.try_into().ok()?);
    Some(SocketAddr::new(ip, port))
}

/// Converts an IPv4-mapped IPv6 address of a dual stack socket into IPv4
pub fn canonical_addr(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}

/// Converts an address into a form that a socket of the family accepts
pub fn socket_addr(socket_is_v6: bool, addr: SocketAddr) -> SocketAddr {
    match addr.ip() {
        IpAddr::V4(ip) if socket_is_v6 => SocketAddr::new(ip.to_ipv6_mapped().into(), addr.port()),
        _ => addr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let secret_key = SecretKey::from_bytes(&[1; 32]);
        let key = *secret_key.public().as_bytes();
        let nonce = [7; NONCE_LEN];
        let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let addr6: SocketAddr = "[2001:db8::1]:443".parse().unwrap();

        assert_eq!(
            decode(&encode_hello(&secret_key.public())),
            Some(Message::Hello { version: VERSION, key }),
        );
        for observed_addr in [addr, addr6] {
            let challenge = encode_challenge(&nonce, &observed_addr);
            assert!(challenge.len() <= HELLO_LEN);
            assert_eq!(decode(&challenge), Some(Message::Challenge { nonce, observed_addr }));
        }
        assert_eq!(decode(&encode_registered()), Some(Message::Registered));
        assert_eq!(decode(&encode_keepalive()), Some(Message::Keepalive));
        assert_eq!(decode(&encode_keepalive_ack()), Some(Message::KeepaliveAck));
        assert_eq!(decode(&encode_not_registered()), Some(Message::NotRegistered));

        let mut data = vec![0; DATA_HEADER_LEN + 3];
        encode_data_header(&mut data, &key);
        data[DATA_HEADER_LEN..].copy_from_slice(b"abc");
        assert_eq!(decode(&data), Some(Message::Data { key: &key, payload: b"abc" }));

        assert_eq!(decode(&[]), None);
        assert_eq!(decode(&[HELLO, VERSION]), None);
        assert_eq!(decode(&[DATA, 1, 2]), None);
        assert_eq!(decode(&[0xff]), None);
    }

    #[test]
    fn test_auth() {
        let secret_key = SecretKey::from_bytes(&[1; 32]);
        let nonce = [7; NONCE_LEN];
        let addr: SocketAddr = "1.2.3.4:5678".parse().unwrap();
        let Some(Message::Auth { key, nonce: auth_nonce, signature }) =
            decode(&encode_auth(&secret_key, &nonce, &addr))
        else {
            panic!("Not an auth message");
        };
        assert_eq!(auth_nonce, nonce);
        assert_eq!(verify_auth(&key, &nonce, &signature, &addr), Some(secret_key.public()));
        // A mapped address of a dual stack socket is the same address
        let mapped_addr: SocketAddr = "[::ffff:1.2.3.4]:5678".parse().unwrap();
        assert_eq!(verify_auth(&key, &nonce, &signature, &mapped_addr), Some(secret_key.public()));

        assert_eq!(verify_auth(&key, &[8; NONCE_LEN], &signature, &addr), None);
        assert_eq!(verify_auth(&key, &nonce, &signature, &"1.2.3.4:5679".parse().unwrap()), None);
        let other_key = SecretKey::from_bytes(&[2; 32]).public();
        assert_eq!(verify_auth(other_key.as_bytes(), &nonce, &signature, &addr), None);
    }
}
