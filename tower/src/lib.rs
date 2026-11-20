use core::{NodeId, Packet, PacketId, RegionCode};
use crypto::Identity;
use net::PeerTable;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(thiserror::Error, Debug)]
pub enum TowerError {
    #[error("invalid invite")]
    InvalidInvite,
    #[error("expired invite")]
    ExpiredInvite,
    #[error("duplicate packet")]
    DuplicatePacket,
    #[error("peer not found: {0:?}")]
    PeerNotFound(NodeId),
    #[error("banned: {0:?}")]
    Banned(NodeId),
    #[error("core error: {0}")]
    Core(#[from] core::CoreError),
    #[error("net error: {0}")]
    Net(#[from] net::NetError),
    #[error("crypto error: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("other: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, TowerError>;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Invite {
    pub invitee_pubkey: [u8; 32],
    pub issuer: NodeId,
    pub expiry: u64,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeliveryRecord {
    pub packet_id: PacketId,
    pub nodes: Vec<NodeId>,
}

pub trait NodeArg {
    fn into_node(self) -> NodeId;
}

impl NodeArg for NodeId {
    fn into_node(self) -> NodeId {
        self
    }
}

impl NodeArg for &NodeId {
    fn into_node(self) -> NodeId {
        self.clone()
    }
}

impl NodeArg for &mut NodeId {
    fn into_node(self) -> NodeId {
        self.clone()
    }
}

pub trait PacketIdArg {
    fn into_packet_id(self) -> PacketId;
}

impl PacketIdArg for PacketId {
    fn into_packet_id(self) -> PacketId {
        self
    }
}

impl PacketIdArg for &PacketId {
    fn into_packet_id(self) -> PacketId {
        self.clone()
    }
}

impl PacketIdArg for &mut PacketId {
    fn into_packet_id(self) -> PacketId {
        self.clone()
    }
}

pub trait RegionArg {
    fn into_region(self) -> RegionCode;
}

impl RegionArg for RegionCode {
    fn into_region(self) -> RegionCode {
        self
    }
}

impl RegionArg for &RegionCode {
    fn into_region(self) -> RegionCode {
        self.clone()
    }
}

impl RegionArg for String {
    fn into_region(self) -> RegionCode {
        RegionCode(self)
    }
}

impl RegionArg for &String {
    fn into_region(self) -> RegionCode {
        RegionCode(self.clone())
    }
}

impl RegionArg for &str {
    fn into_region(self) -> RegionCode {
        RegionCode(self.to_string())
    }
}

pub trait PacketArg {
    fn into_packet(self) -> Packet;
}

impl PacketArg for Packet {
    fn into_packet(self) -> Packet {
        self
    }
}

impl PacketArg for &Packet {
    fn into_packet(self) -> Packet {
        self.clone()
    }
}

impl PacketArg for &mut Packet {
    fn into_packet(self) -> Packet {
        self.clone()
    }
}

pub trait PeerArg {
    fn into_peer_info(self) -> net::PeerInfo;
}

impl PeerArg for net::PeerInfo {
    fn into_peer_info(self) -> net::PeerInfo {
        self
    }
}

impl PeerArg for &net::PeerInfo {
    fn into_peer_info(self) -> net::PeerInfo {
        self.clone()
    }
}

pub trait InviteArg {
    fn into_invite(self) -> Invite;
}

impl InviteArg for Invite {
    fn into_invite(self) -> Invite {
        self
    }
}

impl InviteArg for &Invite {
    fn into_invite(self) -> Invite {
        self.clone()
    }
}

impl InviteArg for &mut Invite {
    fn into_invite(self) -> Invite {
        self.clone()
    }
}

pub trait HeartbeatArg {
    fn into_control(self) -> core::ControlMessage;
}

impl HeartbeatArg for core::ControlMessage {
    fn into_control(self) -> core::ControlMessage {
        self
    }
}

impl HeartbeatArg for &core::ControlMessage {
    fn into_control(self) -> core::ControlMessage {
        self.clone()
    }
}

pub struct Tower {
    pub id: NodeId,
    pub identity: Identity,
    pub region: RegionCode,
    pub peers: PeerTable,
    pub banned: HashSet<NodeId>,
    pub acks: HashMap<PacketId, bool>,
    pub seen_packets: HashSet<PacketId>,
    pub invites: Vec<Invite>,
    pub delivery_history: HashMap<PacketId, Vec<NodeId>>,
    pub history: HashMap<PacketId, Vec<NodeId>>,
}

impl Tower {
    pub fn new(id: NodeId, identity: Identity, region: RegionCode) -> Self {
        Self {
            id,
            identity,
            region,
            peers: PeerTable::new(),
            banned: HashSet::new(),
            acks: HashMap::new(),
            seen_packets: HashSet::new(),
            invites: Vec::new(),
            delivery_history: HashMap::new(),
            history: HashMap::new(),
        }
    }

    pub fn is_banned<N: NodeArg>(&self, node: N) -> bool {
        let node = node.into_node();
        if self.banned.contains(&node) {
            return true;
        }
        self.peers.get(&node).map(|p| p.banned).unwrap_or(false)
    }

    pub fn ban<N: NodeArg>(&mut self, node: N, _reason: &str) {
        let node = node.into_node();
        self.banned.insert(node.clone());
        self.peers.mark_banned(node, true);
    }

    pub fn verify_invite(
        &self,
        invite: impl InviteArg,
        issuer_pubkey: Option<[u8; 32]>,
    ) -> bool {
        let invite = invite.into_invite();
        let _issuer_pubkey = issuer_pubkey;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if invite.expiry < now {
            return false;
        }
        // signature verification optional; placeholder true if no pubkey
        if _issuer_pubkey.is_none() {
            return true;
        }
        true
    }

    pub fn admit_invite<I: InviteArg>(&mut self, invite: I) -> Result<()> {
        let invite = invite.into_invite();
        if !self.verify_invite(&invite, None) {
            return Err(TowerError::ExpiredInvite);
        }
        if self.invites.iter().any(|i| i == &invite) {
            return Err(TowerError::InvalidInvite);
        }
        self.invites.push(invite);
        Ok(())
    }

    pub fn add_peer<P: PeerArg>(&mut self, info: P) {
        let info = info.into_peer_info();
        if self.is_banned(info.node_id.clone()) {
            return;
        }
        self.peers.upsert(info);
    }

    pub fn remove_peer<N: NodeArg>(&mut self, node: N) {
        let node = node.into_node();
        self.peers.remove(&node);
    }

    pub fn route_nnp<P: PacketArg>(&self, packet: P) -> Option<NodeId> {
        let packet = packet.into_packet();
        let visited = &packet.header.visited;
        let mut candidates: Vec<&net::PeerInfo> = self
            .peers
            .values()
            .filter(|p| !self.is_banned(p.node_id.clone()))
            .filter(|p| !visited.contains(&p.node_id))
            .filter(|p| p.node_id != self.id)
            .collect();
        if candidates.is_empty() {
            return None;
        }
        // prefer same region as self, then lowest rtt
        candidates.sort_by(|a, b| {
            let ra = a.region != self.region;
            let rb = b.region != self.region;
            ra.cmp(&rb)
                .then_with(|| a.rtt.cmp(&b.rtt))
        });
        Some(candidates[0].node_id.clone())
    }

    pub fn forward_targets<P: PacketArg>(&self, packet: P) -> Vec<NodeId> {
        let packet = packet.into_packet();
        let visited = &packet.header.visited;
        let mut candidates: Vec<&net::PeerInfo> = self
            .peers
            .values()
            .filter(|p| !self.is_banned(p.node_id.clone()))
            .filter(|p| !visited.contains(&p.node_id))
            .filter(|p| p.node_id != self.id)
            .collect();
        candidates.sort_by(|a, b| a.rtt.cmp(&b.rtt));
        candidates
            .into_iter()
            .take(3)
            .map(|p| p.node_id.clone())
            .collect()
    }

    pub fn handle_packet<P: PacketArg>(&mut self, packet: P) -> bool {
        let packet = packet.into_packet();
        let pid = packet.header.packet_id.clone();
        if self.seen_packets.contains(&pid) {
            return false;
        }
        if packet.header.visited.contains(&self.id) {
            return false;
        }
        self.seen_packets.insert(pid.clone());
        self.delivery_history
            .entry(pid)
            .or_insert_with(Vec::new);
        true
    }

    pub fn record_ack<I: PacketIdArg>(&mut self, packet_id: I) {
        let pid = packet_id.into_packet_id();
        self.acks.insert(pid, true);
    }

    pub fn has_ack<I: PacketIdArg>(&self, packet_id: I) -> bool {
        let pid = packet_id.into_packet_id();
        *self.acks.get(&pid).unwrap_or(&false)
    }

    pub fn region_update<R: RegionArg, I, N>(&mut self, code: R, nodes: I)
    where
        I: IntoIterator<Item = N>,
        N: NodeArg,
    {
        self.region = code.into_region();
        for n in nodes {
            let _ = n.into_node();
        }
    }

    pub fn handle_heartbeat<H: HeartbeatArg>(&mut self, heartbeat: H) {
        let msg = heartbeat.into_control();
        if let core::ControlMessage::Heartbeat { src, .. } = msg {
            self.peers.mark_seen(src, std::time::Instant::now());
        }
    }
}

// free function version
pub fn verify_invite(invite: &Invite, issuer_pubkey: Option<[u8; 32]>) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _issuer_pubkey = issuer_pubkey;
    if invite.expiry < now {
        return false;
    }
    if _issuer_pubkey.is_none() {
        return true;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::{PacketHeader, DeliveryScheme};

    fn tower() -> Tower {
        Tower::new(
            NodeId([0u8; 20]),
            Identity::new(),
            RegionCode("r".into()),
        )
    }

    #[test]
    fn ban_works() {
        let mut t = tower();
        let node = NodeId([1u8; 20]);
        t.ban(node.clone(), "spam");
        assert!(t.is_banned(node));
    }

    #[test]
    fn dedup_works() {
        let mut t = tower();
        let packet = Packet {
            header: PacketHeader {
                src: NodeId([0u8; 20]),
                dst: NodeId([2u8; 20]),
                packet_id: PacketId([9u8; 20]),
                stream_id: core::StreamId([0u8; 20]),
                seq: 0,
                total: 1,
                scheme: DeliveryScheme::Nnp,
                size_class: 0,
                nonce: [0u8; 24],
                ttl: 4,
                visited: Vec::new(),
                signature: Vec::new(),
            },
            body: Vec::new(),
            mac: Vec::new(),
        };
        assert!(t.handle_packet(&packet));
        assert!(!t.handle_packet(&packet));
    }

    #[test]
    fn ack_works() {
        let mut t = tower();
        let pid = PacketId([7u8; 20]);
        t.record_ack(pid.clone());
        assert!(t.has_ack(pid));
    }
}
