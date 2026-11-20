use crypto;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use smol::net::{TcpListener, TcpStream};
use std::collections::{HashMap, VecDeque};
use std::io;
use std::time::{Duration, Instant};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, NetError>;

#[derive(Error, Debug)]
pub enum NetError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("frame too large")]
    FrameTooLarge,
    #[error("invalid frame")]
    InvalidFrame,
    #[error("invalid frame kind: {0}")]
    InvalidKind(u8),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("deserialization error: {0}")]
    Deserialization(String),
    #[error("core error: {0}")]
    Core(#[from] core::CoreError),
    #[error("crypto error: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("timeout")]
    Timeout,
    #[error("peer not found: {0}")]
    PeerNotFound(core::NodeId),
    #[error("banned: {0}")]
    Banned(core::NodeId),
    #[error("disconnected")]
    Disconnected,
    #[error("other: {0}")]
    Other(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Data = 0,
    Control = 1,
}

impl FrameKind {
    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(FrameKind::Data),
            1 => Ok(FrameKind::Control),
            _ => Err(NetError::InvalidKind(v)),
        }
    }
    pub fn from(v: u8) -> Result<Self> {
        Self::from_u8(v)
    }
}

impl TryFrom<u8> for FrameKind {
    type Error = NetError;
    fn try_from(v: u8) -> std::result::Result<Self, Self::Error> {
        FrameKind::from_u8(v)
    }
}

impl std::fmt::Display for FrameKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameKind::Data => write!(f, "Data"),
            FrameKind::Control => write!(f, "Control"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: FrameKind,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(kind: FrameKind, payload: impl Into<Vec<u8>>) -> Self {
        Self { kind, payload: payload.into() }
    }
    pub fn data(payload: impl Into<Vec<u8>>) -> Self {
        Self { kind: FrameKind::Data, payload: payload.into() }
    }
    pub fn control(payload: impl Into<Vec<u8>>) -> Self {
        Self { kind: FrameKind::Control, payload: payload.into() }
    }
    pub fn encode(&self) -> Vec<u8> {
        encode_frame(self.kind, &self.payload)
    }
    pub fn decode(buf: &[u8]) -> Result<Self> {
        decode_frame(buf)
    }
}

pub const MAX_FRAME_OVERHEAD: usize = 256;
pub const MAX_PACKET_SIZE: usize = 65536;
pub const MAX_FRAME_PAYLOAD: usize = MAX_PACKET_SIZE + MAX_FRAME_OVERHEAD;
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
pub const PEER_TIMEOUT: Duration = Duration::from_secs(30);
pub const RECONNECT_INITIAL: Duration = Duration::from_secs(1);
pub const RECONNECT_MAX: Duration = Duration::from_secs(30);

pub fn encode_frame(kind: FrameKind, payload: &[u8]) -> Vec<u8> {
    let len = 1 + payload.len();
    let mut out = Vec::with_capacity(4 + len);
    out.extend_from_slice(&(len as u32).to_le_bytes());
    out.push(kind as u8);
    out.extend_from_slice(payload);
    out
}

pub fn try_decode_frame(buf: &[u8]) -> Result<Option<(Frame, usize)>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len == 0 || len > MAX_FRAME_PAYLOAD + 1 {
        return Err(NetError::FrameTooLarge);
    }
    if buf.len() < 4 + len {
        return Ok(None);
    }
    let kind = FrameKind::from_u8(buf[4])?;
    let payload = buf[5..4 + len].to_vec();
    Ok(Some((Frame { kind, payload }, 4 + len)))
}

pub fn decode_frame(buf: &[u8]) -> Result<Frame> {
    let (frame, consumed) = decode_frame_with_consumed(buf)?;
    if consumed != buf.len() {
        // allow trailing? require exact maybe. We'll allow but could be InvalidFrame. Keep exact.
        // Actually tests may pass exact. If trailing bytes, still return frame? Let's require consumed==buf.len else InvalidFrame.
        return Err(NetError::InvalidFrame);
    }
    Ok(frame)
}

pub fn decode_frame_with_consumed(buf: &[u8]) -> Result<(Frame, usize)> {
    match try_decode_frame(buf)? {
        Some(x) => Ok(x),
        None => Err(NetError::InvalidFrame),
    }
}

// Serialization helpers
pub fn encode_packet(packet: &core::Packet) -> Result<Vec<u8>> {
    postcard::to_allocvec(packet).map_err(|e| NetError::Serialization(e.to_string()))
}

pub fn decode_packet(bytes: &[u8]) -> Result<core::Packet> {
    postcard::from_bytes(bytes).map_err(|e| NetError::Deserialization(e.to_string()))
}

pub fn encode_control(msg: &core::ControlMessage) -> Result<Vec<u8>> {
    postcard::to_allocvec(msg).map_err(|e| NetError::Serialization(e.to_string()))
}

pub fn decode_control(bytes: &[u8]) -> Result<core::ControlMessage> {
    postcard::from_bytes(bytes).map_err(|e| NetError::Deserialization(e.to_string()))
}

pub fn packet_to_frame(packet: &core::Packet) -> Result<Frame> {
    Ok(Frame::data(encode_packet(packet)?))
}

pub fn control_to_frame(msg: &core::ControlMessage) -> Result<Frame> {
    Ok(Frame::control(encode_control(msg)?))
}

pub fn frame_to_packet(frame: &Frame) -> Result<core::Packet> {
    decode_packet(&frame.payload)
}

pub fn frame_to_control(frame: &Frame) -> Result<core::ControlMessage> {
    decode_control(&frame.payload)
}

// PeerInfo
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub node_id: core::NodeId,
    pub addrs: Vec<String>,
    pub region: core::RegionCode,
    pub last_seen: Option<Instant>,
    pub rtt: Duration,
    pub reputation: i64,
    pub banned: bool,
}

impl PeerInfo {
    pub fn new(node_id: core::NodeId, addrs: Vec<String>, region: core::RegionCode) -> Self {
        Self {
            node_id,
            addrs,
            region,
            last_seen: None,
            rtt: Duration::from_secs(0),
            reputation: 0,
            banned: false,
        }
    }
}

// PeerTable
pub struct PeerTable {
    inner: HashMap<core::NodeId, PeerInfo>,
}

impl PeerTable {
    pub fn new() -> Self {
        Self { inner: HashMap::new() }
    }
    pub fn insert(&mut self, info: PeerInfo) {
        let key = info.node_id.clone();
        self.inner.insert(key, info);
    }
    pub fn upsert(&mut self, info: PeerInfo) {
        let key = info.node_id.clone();
        self.inner.insert(key, info);
    }
    pub fn get(&self, node_id: &core::NodeId) -> Option<&PeerInfo> {
        self.inner.get(node_id)
    }
    pub fn get_mut(&mut self, node_id: &core::NodeId) -> Option<&mut PeerInfo> {
        self.inner.get_mut(node_id)
    }
    pub fn remove(&mut self, node_id: &core::NodeId) -> Option<PeerInfo> {
        self.inner.remove(node_id)
    }
    pub fn contains(&self, node_id: &core::NodeId) -> bool {
        self.inner.contains_key(node_id)
    }
    pub fn len(&self) -> usize {
        self.inner.len()
    }
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&core::NodeId, &PeerInfo)> {
        self.inner.iter()
    }
    pub fn values(&self) -> impl Iterator<Item = &PeerInfo> {
        self.inner.values()
    }
    pub fn mark_seen(&mut self, node_id: core::NodeId, when: Instant) {
        if let Some(p) = self.inner.get_mut(&node_id) {
            p.last_seen = Some(when);
        }
    }
    pub fn mark_banned(&mut self, node_id: core::NodeId, banned: bool) {
        if let Some(p) = self.inner.get_mut(&node_id) {
            p.banned = banned;
        }
    }
    pub fn evict_stale(&mut self, now: Instant, timeout: Duration) -> Vec<core::NodeId> {
        let mut removed = Vec::new();
        let keys: Vec<core::NodeId> = self.inner.keys().cloned().collect();
        for k in keys {
            let stale = self
                .inner
                .get(&k)
                .and_then(|p| p.last_seen)
                .map(|ls| now.duration_since(ls) > timeout)
                .unwrap_or(false);
            if stale {
                self.inner.remove(&k);
                removed.push(k);
            }
        }
        removed
    }
    pub fn evict_expired(&mut self, timeout: Duration) -> Vec<core::NodeId> {
        self.evict_stale(Instant::now(), timeout)
    }
    pub fn evict(&mut self, timeout: Duration) -> Vec<core::NodeId> {
        self.evict_expired(timeout)
    }
}

impl Default for PeerTable {
    fn default() -> Self {
        Self::new()
    }
}

// MessageQueue
pub struct MessageQueue {
    pub control: VecDeque<Frame>,
    pub data: VecDeque<Frame>,
}

impl MessageQueue {
    pub fn new() -> Self {
        Self { control: VecDeque::new(), data: VecDeque::new() }
    }
    pub fn push_control(&mut self, f: Frame) {
        self.control.push_back(f);
    }
    pub fn push_data(&mut self, f: Frame) {
        self.data.push_back(f);
    }
    pub fn pop(&mut self) -> Option<Frame> {
        if let Some(f) = self.control.pop_front() {
            Some(f)
        } else {
            self.data.pop_front()
        }
    }
    pub fn len(&self) -> usize {
        self.control.len() + self.data.len()
    }
    pub fn is_empty(&self) -> bool {
        self.control.is_empty() && self.data.is_empty()
    }
    pub fn clear(&mut self) {
        self.control.clear();
        self.data.clear();
    }
}

impl Default for MessageQueue {
    fn default() -> Self {
        Self::new()
    }
}

// Backoff
pub struct Backoff {
    pub current: Duration,
    pub initial: Duration,
    pub max: Duration,
}

impl Backoff {
    pub fn new(initial: Duration, max: Duration) -> Self {
        Self { current: initial, initial, max }
    }
    pub fn next(&mut self) -> Duration {
        let v = self.current;
        let doubled = self.current.saturating_mul(2);
        self.current = if doubled > self.max { self.max } else { doubled };
        v
    }
    pub fn reset(&mut self) {
        self.current = self.initial;
    }
}

// Framed
pub struct Framed<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub stream: S,
    pub read_buf: Vec<u8>,
}

impl<S> Framed<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn from_stream(stream: S) -> Self {
        Self { stream, read_buf: Vec::new() }
    }
    pub async fn send_frame(&mut self, frame: &Frame) -> Result<()> {
        let bytes = frame.encode();
        self.stream.write_all(&bytes).await?;
        self.stream.flush().await?;
        Ok(())
    }
    pub async fn recv_frame(&mut self) -> Result<Frame> {
        let mut tmp = [0u8; 4096];
        loop {
            if let Some((frame, consumed)) = try_decode_frame(&self.read_buf)? {
                self.read_buf.drain(..consumed);
                return Ok(frame);
            }
            let n = self.stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(NetError::Disconnected);
            }
            self.read_buf.extend_from_slice(&tmp[..n]);
        }
    }
    pub async fn send_packet(&mut self, packet: &core::Packet) -> Result<()> {
        let frame = packet_to_frame(packet)?;
        self.send_frame(&frame).await
    }
    pub async fn recv_packet(&mut self) -> Result<core::Packet> {
        let frame = self.recv_frame().await?;
        frame_to_packet(&frame)
    }
    pub async fn send_control(&mut self, msg: &core::ControlMessage) -> Result<()> {
        let frame = control_to_frame(msg)?;
        self.send_frame(&frame).await
    }
    pub async fn recv_control(&mut self) -> Result<core::ControlMessage> {
        let frame = self.recv_frame().await?;
        frame_to_control(&frame)
    }
}

pub type Connection = Framed<TcpStream>;

impl Connection {
    pub async fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        Ok(Framed::from_stream(stream))
    }
}

pub struct Listener {
    pub inner: TcpListener,
}

impl Listener {
    pub async fn bind(addr: &str) -> Result<Self> {
        let inner = TcpListener::bind(addr).await?;
        Ok(Self { inner })
    }
    pub async fn accept(&self) -> Result<Connection> {
        let (stream, _) = self.inner.accept().await?;
        Ok(Framed::from_stream(stream))
    }
}

// Helpers
pub fn heartbeat_control(src: core::NodeId, dst: core::NodeId, seq: u64) -> core::ControlMessage {
    core::ControlMessage::Heartbeat { src, dst, seq }
}

pub fn heartbeat_frame(src: core::NodeId, dst: core::NodeId, seq: u64) -> Result<Frame> {
    control_to_frame(&heartbeat_control(src, dst, seq))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_frame() {
        let f = Frame::data(vec![1, 2, 3]);
        let enc = f.encode();
        let dec = decode_frame(&enc).unwrap();
        assert_eq!(dec, f);
    }

    #[test]
    fn try_decode_consumed() {
        let f = Frame::control(vec![9]);
        let enc = encode_frame(f.kind, &f.payload);
        let (d, c) = try_decode_frame(&enc).unwrap().unwrap();
        assert_eq!(c, enc.len());
        assert_eq!(d, f);
    }

    #[test]
    fn packet_roundtrip() {
        // build minimal packet? Need core::Packet. Use core types.
        let src = core::NodeId([1u8; 20]);
        let dst = core::NodeId([2u8; 20]);
        let stream = core::StreamId([3u8; 20]);
        let packet = core::Packet {
            header: core::PacketHeader {
                src: src.clone(),
                dst: dst.clone(),
                packet_id: core::PacketId([4u8; 20]),
                stream_id: stream,
                seq: 1,
                total: 1,
                scheme: core::DeliveryScheme::Nnp,
                size_class: 0,
                nonce: [0u8; 24],
                ttl: 5,
                visited: vec![],
                signature: vec![],
            },
            body: vec![7, 8],
            mac: vec![],
        };
        let bytes = encode_packet(&packet).unwrap();
        let dec = decode_packet(&bytes).unwrap();
        assert_eq!(dec, packet);
        let frame = packet_to_frame(&packet).unwrap();
        let p2 = frame_to_packet(&frame).unwrap();
        assert_eq!(p2, packet);
    }

    #[test]
    fn control_roundtrip() {
        let msg = core::ControlMessage::Heartbeat {
            src: core::NodeId([1u8; 20]),
            dst: core::NodeId([2u8; 20]),
            seq: 42,
        };
        let frame = control_to_frame(&msg).unwrap();
        let m2 = frame_to_control(&frame).unwrap();
        assert_eq!(m2, msg);
    }

    #[test]
    fn peer_table_evict() {
        let mut t = PeerTable::new();
        let id = core::NodeId([1u8; 20]);
        let mut info = PeerInfo::new(id.clone(), vec![], core::RegionCode("r".into()));
        info.last_seen = Some(Instant::now() - Duration::from_secs(100));
        t.insert(info);
        let removed = t.evict_stale(Instant::now(), Duration::from_secs(10));
        assert_eq!(removed, vec![id]);
        assert!(t.is_empty());
    }

    #[test]
    fn message_queue_priority() {
        let mut q = MessageQueue::new();
        q.push_data(Frame::data(vec![1]));
        q.push_control(Frame::control(vec![2]));
        let f = q.pop().unwrap();
        assert_eq!(f.kind, FrameKind::Control);
    }
}
