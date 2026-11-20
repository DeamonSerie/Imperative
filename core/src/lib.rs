use crypto::ripemd160;
use serde::{Deserialize, Serialize};
pub use std::fmt;
pub use std::convert;
pub use std::option;
pub use std::result;
pub use std::write;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CoreError {
    #[error("invalid address format")]
    InvalidAddress,
    #[error("invalid packet size")]
    InvalidPacketSize,
    #[error("invalid character in address")]
    InvalidAddressChar,
    #[error("serialization error")]
    Serialization,
    #[error("deserialization error")]
    Deserialization,
}

pub type Result<T> = std::result::Result<T, CoreError>;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 20]);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TowerId(pub NodeId);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PacketId(pub [u8; 20]);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StreamId(pub [u8; 20]);

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegionCode(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketSize(pub u32);

impl Default for PacketSize {
    fn default() -> Self {
        PacketSize(1024)
    }
}

impl PacketSize {
    pub fn new(size: u32) -> Result<Self> {
        if size >= 256 && size <= 65536 {
            Ok(PacketSize(size))
        } else {
            Err(CoreError::InvalidPacketSize)
        }
    }

    pub fn get(&self) -> u32 {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryScheme {
    Nnp,
    Anps,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketHeader {
    pub src: NodeId,
    pub dst: NodeId,
    pub packet_id: PacketId,
    pub stream_id: StreamId,
    pub seq: u32,
    pub total: u32,
    pub scheme: DeliveryScheme,
    pub size_class: u32,
    pub nonce: [u8; 24],
    pub ttl: u8,
    pub visited: Vec<NodeId>,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Packet {
    pub header: PacketHeader,
    pub body: Vec<u8>,
    pub mac: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ControlMessage {
    Ack {
        packet_id: PacketId,
        src: NodeId,
        dst: NodeId,
    },
    Nak {
        packet_id: PacketId,
        src: NodeId,
        dst: NodeId,
        reason: String,
    },
    Invite {
        src: NodeId,
        dst: NodeId,
        tower_id: TowerId,
        proof: Vec<u8>,
    },
    Propose {
        src: NodeId,
        dst: NodeId,
        proposal_id: [u8; 20],
        payload: Vec<u8>,
    },
    Vote {
        src: NodeId,
        dst: NodeId,
        proposal_id: [u8; 20],
        approve: bool,
        signature: Vec<u8>,
    },
    Commit {
        src: NodeId,
        dst: NodeId,
        proposal_id: [u8; 20],
        proof: Vec<u8>,
    },
    Ban {
        src: NodeId,
        dst: NodeId,
        target: NodeId,
        reason: String,
        signature: Vec<u8>,
    },
    DhtFindNode {
        src: NodeId,
        dst: NodeId,
        key: [u8; 20],
    },
    DhtFindValue {
        src: NodeId,
        dst: NodeId,
        key: [u8; 20],
    },
    DhtStore {
        src: NodeId,
        dst: NodeId,
        key: [u8; 20],
        value: Vec<u8>,
    },
    RegionUpdate {
        src: NodeId,
        dst: NodeId,
        region: RegionCode,
        nodes: Vec<NodeId>,
    },
    Heartbeat {
        src: NodeId,
        dst: NodeId,
        seq: u64,
    },
}

pub fn node_id_from_pubkey(pubkey: &[u8; 32]) -> NodeId {
    NodeId(ripemd160(pubkey))
}

pub fn packet_id(
    src: &NodeId,
    dst: &NodeId,
    stream_id: &StreamId,
    seq: u32,
    payload_hash: &[u8],
    nonce: &[u8; 24],
) -> PacketId {
    let mut data = Vec::new();
    data.extend_from_slice(&src.0);
    data.extend_from_slice(&dst.0);
    data.extend_from_slice(&stream_id.0);
    data.extend_from_slice(&seq.to_be_bytes());
    data.extend_from_slice(payload_hash);
    data.extend_from_slice(nonce);
    PacketId(ripemd160(&data))
}

fn is_valid_addr_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'
}

pub fn parse_address(addr: &str) -> Result<(String, String, String)> {
    // protocol://name@extension
    if let Some(proto_sep) = addr.find("://") {
        let protocol = addr[..proto_sep].to_string();
        let rest = &addr[proto_sep + 3..];
        if let Some(at_pos) = rest.find('@') {
            let name = &rest[..at_pos];
            let extension = &rest[at_pos + 1..];
            for c in protocol.chars() {
                if !is_valid_addr_char(c) {
                    return Err(CoreError::InvalidAddressChar);
                }
            }
            for c in name.chars() {
                if !is_valid_addr_char(c) {
                    return Err(CoreError::InvalidAddressChar);
                }
            }
            for c in extension.chars() {
                if !is_valid_addr_char(c) {
                    return Err(CoreError::InvalidAddressChar);
                }
            }
            if protocol.is_empty() || name.is_empty() || extension.is_empty() {
                return Err(CoreError::InvalidAddress);
            }
            Ok((protocol, name.to_string(), extension.to_string()))
        } else {
            Err(CoreError::InvalidAddress)
        }
    } else {
        Err(CoreError::InvalidAddress)
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_id_from_pubkey() {
        let pubkey = [0u8; 32];
        let id = node_id_from_pubkey(&pubkey);
        assert_eq!(id.0.len(), 20);
    }

    #[test]
    fn test_packet_id() {
        let src = NodeId([1u8; 20]);
        let dst = NodeId([2u8; 20]);
        let stream = StreamId([3u8; 20]);
        let payload_hash = [4u8; 20];
        let nonce = [5u8; 24];
        let pid = packet_id(&src, &dst, &stream, 1, &payload_hash, &nonce);
        assert_eq!(pid.0.len(), 20);
    }

    #[test]
    fn test_parse_address() {
        let res = parse_address("tcp://alice@example.com").unwrap();
        assert_eq!(res.0, "tcp");
        assert_eq!(res.1, "alice");
        assert_eq!(res.2, "example.com");
    }

    #[test]
    fn test_packet_size() {
        assert!(PacketSize::new(1024).is_ok());
        assert!(PacketSize::new(255).is_err());
        assert!(PacketSize::new(65537).is_err());
        assert_eq!(PacketSize::default().0, 1024);
    }
}
