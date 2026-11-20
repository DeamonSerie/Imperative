use core::{NodeId, PacketId};
use crypto::ripemd160;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Trigger {
    PacketLossSpike { threshold: f64 },
    FakeAckDetected { packet_id: PacketId },
    CongestionHigh,
    BlockchainEvent { kind: String },
    NodeMisbehavior { node_id: NodeId },
    Custom { event_name: String },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Condition {
    QueueDepthAbove { threshold: u32 },
    LossRateAbove { threshold: f64 },
    ReputationBelow { threshold: i64 },
    BlockHeightDelta { threshold: u64 },
    TransferAmountAbove { threshold: u64 },
    Always,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Action {
    AdjustPacketSize { factor: f64 },
    BanNode { node_id: NodeId, reason: String },
    IncreaseRedundancy { factor: f64 },
    ThrottlePeer { node_id: NodeId, rate: u32 },
    SwitchToAnps,
    Alert { message: String },
    EnableInvestigationMode,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RuleSet {
    pub id: [u8; 20],
    pub name: String,
    pub version: u32,
    pub priority: u8,
    pub triggers: Vec<Trigger>,
    pub conditions: Vec<Condition>,
    pub actions: Vec<Action>,
    pub approved_by: Vec<NodeId>,
    pub active: bool,
}

impl RuleSet {
    pub fn new(
        name: impl Into<String>,
        version: u32,
        priority: u8,
        triggers: Vec<Trigger>,
        conditions: Vec<Condition>,
        actions: Vec<Action>,
    ) -> Self {
        let name = name.into();
        let mut buf = Vec::with_capacity(name.len() + 4);
        buf.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(&version.to_le_bytes());
        let id = ripemd160(&buf);
        Self {
            id,
            name,
            version,
            priority,
            triggers,
            conditions,
            actions,
            approved_by: Vec::new(),
            active: false,
        }
    }

    pub fn approve(&mut self, approver: NodeId) {
        if !self.approved_by.contains(&approver) {
            self.approved_by.push(approver);
        }
    }

    pub fn activate(&mut self) {
        self.active = true;
    }

    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub kind: String,
    pub data: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RuleContext {
    pub queue_depth: u32,
    pub loss_rate: f64,
    pub reputation: i64,
    pub block_height_delta: u64,
    pub transfer_amount: u64,
}

impl Condition {
    pub fn holds(&self, ctx: &RuleContext) -> bool {
        match self {
            Condition::QueueDepthAbove { threshold } => ctx.queue_depth > *threshold,
            Condition::LossRateAbove { threshold } => ctx.loss_rate > *threshold,
            Condition::ReputationBelow { threshold } => ctx.reputation < *threshold,
            Condition::BlockHeightDelta { threshold } => ctx.block_height_delta > *threshold,
            Condition::TransferAmountAbove { threshold } => ctx.transfer_amount > *threshold,
            Condition::Always => true,
        }
    }
}

fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

fn trigger_matches(t: &Trigger, event_kind: &str) -> bool {
    let k = norm(event_kind);
    match t {
        Trigger::PacketLossSpike { .. } => k == "packetlossspike",
        Trigger::FakeAckDetected { .. } => k == "fakeackdetected",
        Trigger::CongestionHigh => k == "congestionhigh",
        Trigger::BlockchainEvent { kind } => k == norm(kind) || k == "blockchainevent",
        Trigger::NodeMisbehavior { .. } => k == "nodemisbehavior",
        Trigger::Custom { event_name } => k == norm(event_name),
    }
}

#[derive(Clone, Debug, Default)]
pub struct RuleEngine {
    pub rules: Vec<RuleSet>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, rule: RuleSet) {
        self.rules.push(rule);
    }

    pub fn approve_rule<I>(&mut self, rule_id: I, approver: NodeId)
    where
        I: AsRef<[u8]>,
    {
        let bytes = rule_id.as_ref();
        let mut id = [0u8; 20];
        id.copy_from_slice(&bytes[..20]);
        if let Some(r) = self.rules.iter_mut().find(|r| r.id == id) {
            if !r.approved_by.contains(&approver) {
                r.approved_by.push(approver);
            }
        }
    }

    pub fn activate<I>(&mut self, rule_id: I)
    where
        I: AsRef<[u8]>,
    {
        let bytes = rule_id.as_ref();
        let mut id = [0u8; 20];
        id.copy_from_slice(&bytes[..20]);
        if let Some(r) = self.rules.iter_mut().find(|r| r.id == id) {
            r.active = true;
        }
    }

    pub fn deactivate<I>(&mut self, rule_id: I)
    where
        I: AsRef<[u8]>,
    {
        let bytes = rule_id.as_ref();
        let mut id = [0u8; 20];
        id.copy_from_slice(&bytes[..20]);
        if let Some(r) = self.rules.iter_mut().find(|r| r.id == id) {
            r.active = false;
        }
    }

    pub fn add(&mut self, rule: RuleSet) {
        self.add_rule(rule);
    }

    pub fn approve(&mut self, rule_id: impl AsRef<[u8]>, approver: NodeId) {
        self.approve_rule(rule_id, approver);
    }

    pub fn activate_rule(&mut self, rule_id: impl AsRef<[u8]>) {
        self.activate(rule_id);
    }

    pub fn deactivate_rule(&mut self, rule_id: impl AsRef<[u8]>) {
        self.deactivate(rule_id);
    }

    pub fn evaluate_triggers(&self, event_kind: &str) -> Vec<RuleSet> {
        self.rules
            .iter()
            .filter(|r| r.active && r.triggers.iter().any(|t| trigger_matches(t, event_kind)))
            .cloned()
            .collect()
    }

    pub fn evaluate(&self, event_kind: &str, ctx: &RuleContext) -> Option<RuleSet> {
        let mut best: Option<&RuleSet> = None;
        for r in &self.rules {
            if !r.active {
                continue;
            }
            if !r.triggers.iter().any(|t| trigger_matches(t, event_kind)) {
                continue;
            }
            if !r.conditions.iter().all(|c| c.holds(ctx)) {
                continue;
            }
            let replace = match best {
                None => true,
                Some(b) => {
                    if r.priority != b.priority {
                        r.priority > b.priority
                    } else if r.version != b.version {
                        r.version > b.version
                    } else {
                        r.id < b.id
                    }
                }
            };
            if replace {
                best = Some(r);
            }
        }
        best.cloned()
    }

    pub fn evaluate_event(&self, event: &Event, ctx: &RuleContext) -> Option<RuleSet> {
        self.evaluate(&event.kind, ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> RuleContext {
        RuleContext {
            queue_depth: 10,
            loss_rate: 0.5,
            reputation: 50,
            block_height_delta: 5,
            transfer_amount: 100,
        }
    }

    #[test]
    fn tie_breaking() {
        let mut engine = RuleEngine::new();
        let r1 = RuleSet::new("a", 1, 5, vec![Trigger::CongestionHigh], vec![Condition::Always], vec![Action::Alert { message: "a".into() }]);
        let r2 = RuleSet::new("b", 2, 5, vec![Trigger::CongestionHigh], vec![Condition::Always], vec![Action::Alert { message: "b".into() }]);
        let r3 = RuleSet::new("c", 1, 10, vec![Trigger::CongestionHigh], vec![Condition::Always], vec![Action::Alert { message: "c".into() }]);
        let id1 = r1.id;
        let id2 = r2.id;
        let id3 = r3.id;
        engine.add_rule(r1);
        engine.add_rule(r2);
        engine.add_rule(r3);
        engine.activate(id1);
        engine.activate(id2);
        engine.activate(id3);
        let chosen = engine.evaluate("CongestionHigh", &ctx()).unwrap();
        assert_eq!(chosen.priority, 10);
        // tie between r1/r2? r3 wins; test version tie
        let mut engine2 = RuleEngine::new();
        let a = RuleSet::new("x", 2, 5, vec![Trigger::CongestionHigh], vec![Condition::Always], vec![]);
        let b = RuleSet::new("y", 1, 5, vec![Trigger::CongestionHigh], vec![Condition::Always], vec![]);
        let aid = a.id;
        let bid = b.id;
        engine2.add_rule(a);
        engine2.add_rule(b);
        engine2.activate(aid);
        engine2.activate(bid);
        let chosen2 = engine2.evaluate("CongestionHigh", &ctx()).unwrap();
        assert_eq!(chosen2.version, 2);
        // id tie-break (unlikely but compare)
        let _ = id1;
        let _ = id2;
        let _ = id3;
    }

    #[test]
    fn activation() {
        let mut engine = RuleEngine::new();
        let rule = RuleSet::new("r", 1, 1, vec![Trigger::CongestionHigh], vec![Condition::Always], vec![]);
        let id = rule.id;
        engine.add_rule(rule);
        assert!(engine.evaluate("CongestionHigh", &ctx()).is_none());
        engine.activate(id);
        assert!(engine.evaluate("CongestionHigh", &ctx()).is_some());
        engine.deactivate(id);
        assert!(engine.evaluate("CongestionHigh", &ctx()).is_none());
    }
}
