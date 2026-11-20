use core;
use crypto;
use net;
use std::time::{Duration, Instant};

pub type Result<T> = net::Result<T>;

pub struct BotIdentity {
    pub identity: crypto::Identity,
}

impl BotIdentity {
    pub fn new() -> Self {
        Self {
            identity: crypto::Identity::new(),
        }
    }
}

impl std::ops::Deref for BotIdentity {
    type Target = crypto::Identity;
    fn deref(&self) -> &Self::Target {
        &self.identity
    }
}

pub struct Bot {
    pub identity: crypto::Identity,
    pub node_id: core::NodeId,
    pub rate_limit_pps: u32,
    pub sent_timestamps: Vec<Instant>,
}

impl Bot {
    pub fn new() -> Self {
        let identity = crypto::Identity::new();
        let node_id = core::node_id_from_pubkey(&identity.verifying_key().to_bytes());
        Self {
            identity,
            node_id,
            rate_limit_pps: 10,
            sent_timestamps: Vec::new(),
        }
    }

    pub fn node_id(&self) -> core::NodeId {
        self.node_id.clone()
    }

    pub fn identity(&self) -> &crypto::Identity {
        &self.identity
    }

    pub fn can_send(&mut self, now: Instant) -> bool {
        self.sent_timestamps.retain(|t| {
            match now.checked_duration_since(*t) {
                Some(d) => d < Duration::from_secs(1),
                None => true,
            }
        });
        (self.sent_timestamps.len() as u32) < self.rate_limit_pps
    }

    pub fn record_send(&mut self, now: Instant) {
        self.sent_timestamps.push(now);
    }

    pub fn relay_allowed<P: PacketRef>(&self, packet: P) -> bool {
        let _ = packet.packet();
        true
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

#[derive(Clone, Debug, PartialEq)]
pub struct Reputation {
    pub node_id: core::NodeId,
    pub score: i64,
}

impl Reputation {
    pub fn new(node_id: core::NodeId) -> Self {
        Self { node_id, score: 0 }
    }

    pub fn adjust(&mut self, delta: i64) {
        self.score += delta;
    }

    pub fn adjust_score(&mut self, delta: i64) {
        self.adjust(delta);
    }

    pub fn add(&mut self, delta: i64) {
        self.adjust(delta);
    }
}

pub struct BotClient {
    pub connection: net::Connection,
}

impl BotClient {
    pub async fn connect(addr: &str) -> net::Result<Self> {
        let connection = net::Connection::connect(addr).await?;
        Ok(Self { connection })
    }
}

impl BotClient {
    pub fn new(connection: net::Connection) -> Self {
        Self { connection }
    }
}

impl Bot {
    pub async fn connect(addr: &str) -> net::Result<net::Connection> {
        net::Connection::connect(addr).await
    }

    pub async fn connect_client(addr: &str) -> net::Result<BotClient> {
        BotClient::connect(addr).await
    }
}

pub async fn connect(addr: &str) -> net::Result<net::Connection> {
    net::Connection::connect(addr).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limit_basic() {
        let mut bot = Bot::new();
        let now = Instant::now();
        for _ in 0..10 {
            assert!(bot.can_send(now));
            bot.record_send(now);
        }
        assert!(!bot.can_send(now));
    }

    #[test]
    fn rate_limit_window() {
        let mut bot = Bot::new();
        let now = Instant::now();
        for _ in 0..10 {
            assert!(bot.can_send(now));
            bot.record_send(now);
        }
        let later = now + Duration::from_secs(1);
        assert!(bot.can_send(later));
    }

    #[test]
    fn node_id_nonzero() {
        let bot = Bot::new();
        assert_eq!(bot.node_id().0.len(), 20);
    }
}
