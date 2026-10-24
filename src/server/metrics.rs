use std::sync::Arc;

use iroh_metrics::{Counter, EncodeLabelSet, Family, Gauge, MetricsGroup};

/// Labels of metrics about traffic between two nodes
#[derive(Debug, Clone, Hash, PartialEq, Eq, PartialOrd, Ord, EncodeLabelSet)]
pub struct LinkLabels {
    /// Short endpoint id of the sender as iroh prints it in logs,
    /// [`LinkLabels::REGISTERED`] or [`LinkLabels::UNREGISTERED`]
    pub src_endpoint: String,
    /// The same for the recipient
    pub dst_endpoint: String,
}

impl LinkLabels {
    /// A sender address without a registration, or a recipient key without one.
    /// Such keys are not labels because a packet can contain anything
    pub const UNREGISTERED: &str = "unregistered";
    /// Any registered endpoint, when endpoint labels are disabled
    pub const REGISTERED: &str = "registered";

    pub fn new(src_endpoint: &str, dst_endpoint: &str) -> Self {
        Self { src_endpoint: src_endpoint.to_string(), dst_endpoint: dst_endpoint.to_string() }
    }
}

/// Metrics tracked by the relay server
///
/// Traffic metrics are labeled only with keys of registered nodes, so their
/// number is bounded by pairs of sessions. Labels of a node are removed with its session.
/// Endpoint ids are labels only if [`Options::endpoint_labels`](super::Options) is enabled.
#[derive(Debug, Default, MetricsGroup)]
#[metrics(name = "udprelay")]
#[non_exhaustive]
pub struct Metrics {
    /*
     * Metrics about packets, by sender and recipient
     */
    /// Bytes of forwarded `Data` packets, including the data header
    #[metrics(help = "Number of bytes relayed.")]
    pub bytes_relayed: Family<LinkLabels, Counter>,
    #[metrics(help = "Number of 'data' packets relayed.")]
    pub data_packets_relayed: Family<LinkLabels, Counter>,
    /// `Data` packets that were not forwarded. The labels tell why: the sender
    /// or the recipient is unregistered, otherwise sending failed
    #[metrics(help = "Number of 'data' packets dropped.")]
    pub data_packets_dropped: Family<LinkLabels, Counter>,

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
    /// Returns counters of a link, they are cached to avoid a label lookup per packet
    pub(crate) fn link(&self, labels: &LinkLabels) -> LinkCounters {
        LinkCounters {
            bytes: self.bytes_relayed.get_or_create(labels),
            packets: self.data_packets_relayed.get_or_create(labels),
        }
    }

    /// Drops are rare, so their counters are not cached
    pub(crate) fn dropped(&self, src_endpoint: &str, dst_endpoint: &str) {
        self.data_packets_dropped.get_or_create(&LinkLabels::new(src_endpoint, dst_endpoint)).inc();
    }

    /// Removes metrics of links between a node and its `peers`, itself and unregistered nodes
    pub(crate) fn remove_endpoint<'a>(&self, endpoint: &'a str, peers: impl IntoIterator<Item = &'a str>) {
        for peer in peers.into_iter().chain([endpoint, LinkLabels::UNREGISTERED]) {
            for labels in [LinkLabels::new(endpoint, peer), LinkLabels::new(peer, endpoint)] {
                self.bytes_relayed.remove(&labels);
                self.data_packets_relayed.remove(&labels);
                self.data_packets_dropped.remove(&labels);
            }
        }
    }
}

/// Counters of [`Metrics`] for traffic from one node to another
#[derive(Debug)]
pub(crate) struct LinkCounters {
    bytes: Arc<Counter>,
    packets: Arc<Counter>,
}

impl LinkCounters {
    pub fn relayed(&self, len: usize) {
        self.packets.inc();
        self.bytes.inc_by(len as u64);
    }
}
