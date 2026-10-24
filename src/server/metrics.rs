use std::sync::Arc;

use iroh_metrics::{Counter, EncodeLabelSet, Family, Gauge, MetricsGroup};

/// Labels of per node metrics
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, EncodeLabelSet)]
pub struct NodeLabels {
    /// Short endpoint id of a registered node, as iroh prints it in logs,
    /// or [`NodeLabels::UNREGISTERED`]
    pub endpoint: String,
}

impl NodeLabels {
    /// Packets from addresses without a registration
    pub const UNREGISTERED: &str = "unregistered";

    pub fn unregistered() -> Self {
        Self { endpoint: Self::UNREGISTERED.to_string() }
    }
}

/// Metrics tracked by the relay server
///
/// Per node metrics are labeled only with keys of registered nodes, so their
/// number is bounded by the sessions. Labels of a node are removed with its session.
#[derive(Debug, Default, MetricsGroup)]
#[metrics(name = "udprelay")]
#[non_exhaustive]
pub struct Metrics {
    /*
     * Metrics about packets, by node
     */
    /// Bytes of `Data` packets received from a node, including the data header
    #[metrics(help = "Number of bytes received.")]
    pub bytes_recv: Family<NodeLabels, Counter>,
    /// Bytes of `Data` packets forwarded to a node, including the data header
    #[metrics(help = "Number of bytes sent.")]
    pub bytes_sent: Family<NodeLabels, Counter>,

    /// `Data` packets received from a node
    #[metrics(help = "Number of 'data' packets received.")]
    pub data_packets_recv: Family<NodeLabels, Counter>,
    /// `Data` packets forwarded to a node
    #[metrics(help = "Number of 'data' packets relayed.")]
    pub data_packets_sent: Family<NodeLabels, Counter>,
    /// `Data` packets of a node that were not forwarded: the sender or the recipient
    /// is not registered or sending failed. Labeled with the sender because a recipient
    /// key comes from a packet and can be anything
    #[metrics(help = "Number of 'data' packets dropped.")]
    pub data_packets_dropped: Family<NodeLabels, Counter>,

    /*
     * Metrics about other packets
     */

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

impl Metrics {
    /// Returns counters of a node, they are cached to avoid a label lookup per packet
    pub(crate) fn node(&self, labels: &NodeLabels) -> NodeCounters {
        NodeCounters {
            bytes_recv: self.bytes_recv.get_or_create(labels),
            bytes_sent: self.bytes_sent.get_or_create(labels),
            data_packets_recv: self.data_packets_recv.get_or_create(labels),
            data_packets_sent: self.data_packets_sent.get_or_create(labels),
            data_packets_dropped: self.data_packets_dropped.get_or_create(labels),
        }
    }

    pub(crate) fn remove_node(&self, labels: &NodeLabels) {
        self.bytes_recv.remove(labels);
        self.bytes_sent.remove(labels);
        self.data_packets_recv.remove(labels);
        self.data_packets_sent.remove(labels);
        self.data_packets_dropped.remove(labels);
    }
}

/// Per node counters of [`Metrics`]
#[derive(Debug)]
pub(crate) struct NodeCounters {
    pub bytes_recv: Arc<Counter>,
    pub bytes_sent: Arc<Counter>,
    pub data_packets_recv: Arc<Counter>,
    pub data_packets_sent: Arc<Counter>,
    pub data_packets_dropped: Arc<Counter>,
}

impl NodeCounters {
    pub fn recv(&self, len: usize) {
        self.data_packets_recv.inc();
        self.bytes_recv.inc_by(len as u64);
    }

    pub fn sent(&self, len: usize) {
        self.data_packets_sent.inc();
        self.bytes_sent.inc_by(len as u64);
    }
}
