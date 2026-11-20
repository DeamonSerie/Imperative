use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

pub const RETRANSMIT_TIMEOUT: Duration = Duration::from_secs(2);

pub trait NodeIdArg {
    fn node_id(&self) -> core::NodeId;
}

impl NodeIdArg for core::NodeId {
    fn node_id(&self) -> core::NodeId {
        self.clone()
    }
}

impl NodeIdArg for &core::NodeId {
    fn node_id(&self) -> core::NodeId {
        (*self).clone()
    }
}

pub trait StreamIdArg {
    fn stream_id(&self) -> core::StreamId;
}

impl StreamIdArg for core::StreamId {
    fn stream_id(&self) -> core::StreamId {
        self.clone()
    }
}

impl StreamIdArg for &core::StreamId {
    fn stream_id(&self) -> core::StreamId {
        (*self).clone()
    }
}

pub trait PacketSizeArg {
    fn packet_size(&self) -> core::PacketSize;
}

impl PacketSizeArg for core::PacketSize {
    fn packet_size(&self) -> core::PacketSize {
        self.clone()
    }
}

impl PacketSizeArg for &core::PacketSize {
    fn packet_size(&self) -> core::PacketSize {
        (*self).clone()
    }
}

pub fn new_stream_id<S: NodeIdArg, D: NodeIdArg>(
    src: S,
    dst: D,
    timestamp: u64,
    counter: u64,
) -> core::StreamId {
    let src = src.node_id();
    let dst = dst.node_id();
    let mut data = Vec::new();
    data.extend_from_slice(&src.0);
    data.extend_from_slice(&dst.0);
    data.extend_from_slice(&timestamp.to_be_bytes());
    data.extend_from_slice(&counter.to_be_bytes());
    core::StreamId(crypto::ripemd160(&data))
}

pub fn chunk_size<P: PacketSizeArg>(packet_size: P) -> usize {
    packet_size.packet_size().get() as usize
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Chunker {
    packet_size: core::PacketSize,
}

impl Chunker {
    pub fn new<P: PacketSizeArg>(packet_size: P) -> Self {
        Self {
            packet_size: packet_size.packet_size(),
        }
    }

    pub fn chunk<S: NodeIdArg, D: NodeIdArg, I: StreamIdArg>(
        &self,
        src: S,
        dst: D,
        stream_id: I,
        data: &[u8],
    ) -> Vec<core::Packet> {
        let src = src.node_id();
        let dst = dst.node_id();
        let stream_id = stream_id.stream_id();
        let cs = chunk_size(&self.packet_size);
        let chunks: Vec<&[u8]> = if cs == 0 {
            vec![data]
        } else {
            data.chunks(cs).collect()
        };
        let total = chunks.len() as u32;
        let nonce = [0u8; 24];
        let mut out = Vec::with_capacity(chunks.len());
        for (i, chunk) in chunks.into_iter().enumerate() {
            let body = chunk.to_vec();
            let payload_hash = crypto::ripemd160(&body);
            let packet_id = core::packet_id(&src, &dst, &stream_id, i as u32, &payload_hash, &nonce);
            let header = core::PacketHeader {
                src: src.clone(),
                dst: dst.clone(),
                packet_id,
                stream_id: stream_id.clone(),
                seq: i as u32,
                total,
                scheme: core::DeliveryScheme::Nnp,
                size_class: self.packet_size.get(),
                nonce,
                ttl: 8,
                visited: Vec::new(),
                signature: Vec::new(),
            };
            out.push(core::Packet {
                header,
                body,
                mac: Vec::new(),
            });
        }
        out
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceivedChunks {
    pub total: u32,
    pub chunks: BTreeMap<u32, Vec<u8>>,
}

impl ReceivedChunks {
    pub fn new(total: u32) -> Self {
        Self {
            total,
            chunks: BTreeMap::new(),
        }
    }

    pub fn insert<P: AsRef<[u8]>>(&mut self, seq: u32, payload: P) -> bool {
        if seq >= self.total {
            return false;
        }
        if self.chunks.contains_key(&seq) {
            return false;
        }
        self.chunks.insert(seq, payload.as_ref().to_vec());
        true
    }

    pub fn is_complete(&self) -> bool {
        self.chunks.len() as u32 == self.total
    }

    pub fn reassemble(&self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }
        let mut out = Vec::new();
        for seq in 0..self.total {
            match self.chunks.get(&seq) {
                Some(b) => out.extend_from_slice(b),
                None => return None,
            }
        }
        Some(out)
    }

    pub fn missing(&self) -> Vec<u32> {
        (0..self.total).filter(|seq| !self.chunks.contains_key(seq)).collect()
    }
}

pub fn missing_seqs(received: &ReceivedChunks) -> Vec<u32> {
    received.missing()
}

pub trait ReasmKey {
    fn key(&self) -> (core::NodeId, core::NodeId, core::StreamId);
}

impl ReasmKey for (core::NodeId, core::NodeId, core::StreamId) {
    fn key(&self) -> (core::NodeId, core::NodeId, core::StreamId) {
        (self.0.clone(), self.1.clone(), self.2.clone())
    }
}

impl ReasmKey for &(core::NodeId, core::NodeId, core::StreamId) {
    fn key(&self) -> (core::NodeId, core::NodeId, core::StreamId) {
        (self.0.clone(), self.1.clone(), self.2.clone())
    }
}

impl ReasmKey for (&core::NodeId, &core::NodeId, &core::StreamId) {
    fn key(&self) -> (core::NodeId, core::NodeId, core::StreamId) {
        (self.0.clone(), self.1.clone(), self.2.clone())
    }
}

pub trait PacketRef {
    fn packet(&self) -> &core::Packet;
}

impl PacketRef for core::Packet {
    fn packet(&self) -> &core::Packet {
        self
    }
}

impl PacketRef for &core::Packet {
    fn packet(&self) -> &core::Packet {
        *self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reassembler {
    streams: HashMap<(core::NodeId, core::NodeId, core::StreamId), ReceivedChunks>,
}

impl Reassembler {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    pub fn on_packet<P: PacketRef>(&mut self, packet: P) -> Option<Vec<u8>> {
        let p = packet.packet();
        let key = (
            p.header.src.clone(),
            p.header.dst.clone(),
            p.header.stream_id.clone(),
        );
        let entry = self
            .streams
            .entry(key)
            .or_insert_with(|| ReceivedChunks::new(p.header.total));
        entry.insert(p.header.seq, p.body.clone());
        if entry.is_complete() {
            entry.reassemble()
        } else {
            None
        }
    }

    pub fn missing_for<K: ReasmKey>(&self, key: K) -> Vec<u32> {
        let k = key.key();
        self.streams
            .get(&k)
            .map(|r| r.missing())
            .unwrap_or_default()
    }
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let src = core::NodeId([1u8; 20]);
        let dst = core::NodeId([2u8; 20]);
        let sid = new_stream_id(&src, &dst, 123, 1);
        let data = vec![7u8; 500];
        let chunker = Chunker::new(core::PacketSize::new(256).unwrap());
        let packets = chunker.chunk(&src, &dst, &sid, &data);
        let mut reasm = Reassembler::new();
        let mut out = None;
        for pkt in &packets {
            out = reasm.on_packet(pkt);
        }
        assert_eq!(out, Some(data.clone()));

        // owned calls
        let packets2 = chunker.chunk(src.clone(), dst.clone(), sid.clone(), &data);
        let mut reasm2 = Reassembler::default();
        let mut out2 = None;
        for pkt in packets2 {
            out2 = reasm2.on_packet(pkt);
        }
        assert_eq!(out2, Some(data));
    }

    #[test]
    fn missing_detection() {
        let src = core::NodeId([1u8; 20]);
        let dst = core::NodeId([2u8; 20]);
        let sid = new_stream_id(&src, &dst, 123, 1);
        let data = vec![7u8; 500];
        let chunker = Chunker::new(core::PacketSize::new(256).unwrap());
        let packets = chunker.chunk(&src, &dst, &sid, &data);
        let mut reasm = Reassembler::new();
        for (i, pkt) in packets.iter().enumerate() {
            if i != 1 {
                reasm.on_packet(pkt.clone());
            }
        }
        let missing = reasm.missing_for((src.clone(), dst.clone(), sid.clone()));
        assert_eq!(missing, vec![1]);
        let missing2 = reasm.missing_for(&(src, dst, sid));
        assert_eq!(missing2, vec![1]);
    }
}
