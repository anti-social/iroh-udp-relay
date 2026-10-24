use iroh_metrics::{Counter, Gauge, MetricsGroup};

/// Metrics tracked by the relay server
#[derive(Debug, Default, MetricsGroup)]
#[metrics(name = "udprelay")]
#[non_exhaustive]
pub struct Metrics {
    /*
     * Metrics about packets
     */
    /// Bytes of `Data` packets received from nodes, including the data header
    #[metrics(help = "Number of bytes received.")]
    pub bytes_recv: Counter,
    /// Bytes of `Data` packets forwarded to nodes, including the data header
    #[metrics(help = "Number of bytes sent.")]
    pub bytes_sent: Counter,

    #[metrics(help = "Number of 'data' packets received.")]
    pub data_packets_recv: Counter,
    #[metrics(help = "Number of 'data' packets relayed.")]
    pub data_packets_sent: Counter,
    /// `Data` packets that were not forwarded: the sender or the recipient is not registered
    /// or sending failed
    #[metrics(help = "Number of 'data' packets dropped.")]
    pub data_packets_dropped: Counter,

    #[metrics(help = "Number of packets received that were not 'data' packets.")]
    pub other_packets_recv: Counter,
    #[metrics(help = "Number of packets sent that were not 'data' packets.")]
    pub other_packets_sent: Counter,
    /// Packets that cannot be decoded, have an unsupported version or are not expected by the relay
    #[metrics(help = "Number of unknown packets sent to this server.")]
    pub unknown_packets: Counter,
    #[metrics(help = "Number of failed sends.")]
    pub send_errors: Counter,

    #[metrics(help = "Number of times the server has received a Keepalive from a node.")]
    pub got_keepalive: Counter,
    #[metrics(help = "Number of times the server has sent a KeepaliveAck to a node.")]
    pub sent_keepalive_ack: Counter,
    /// Answers to packets from unknown addresses, a node registers again after it,
    /// e.g. after a NAT rebinding or a restart of the relay
    #[metrics(help = "Number of times the server has sent NotRegistered to a node.")]
    pub sent_not_registered: Counter,

    /*
     * Metrics about nodes
     */
    #[metrics(help = "Number of registered nodes.")]
    pub sessions: Gauge,
    /// Includes registrations of an already registered node, e.g. from a new address
    #[metrics(help = "Number of successful registrations.")]
    pub registrations: Counter,
    #[metrics(help = "Number of sessions expired without packets from a node.")]
    pub sessions_expired: Counter,

    /// `Hello` messages dropped because there are too many pending challenges
    #[metrics(help = "Number of dropped challenges.")]
    pub challenges_dropped: Counter,
    /// `Auth` messages without a matching challenge or with an invalid signature
    #[metrics(help = "Number of failed authentications.")]
    pub auth_failures: Counter,
    #[metrics(help = "Number of registrations denied by the access check.")]
    pub access_denied: Counter,
    #[metrics(help = "Number of sessions removed because the access was revoked.")]
    pub access_revoked: Counter,
    #[metrics(help = "Number of access checks that failed with an error.")]
    pub access_check_errors: Counter,
}
