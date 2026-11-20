use rules::{Action, RuleContext, RuleEngine};
use std::path::{Path, PathBuf};

pub trait AsRuleEngine {
    fn as_engine(&self) -> &RuleEngine;
}
impl AsRuleEngine for RuleEngine {
    fn as_engine(&self) -> &RuleEngine { self }
}
impl AsRuleEngine for &RuleEngine {
    fn as_engine(&self) -> &RuleEngine { *self }
}

pub trait AsRuleContext {
    fn as_ctx(&self) -> &RuleContext;
}
impl AsRuleContext for RuleContext {
    fn as_ctx(&self) -> &RuleContext { self }
}
impl AsRuleContext for &RuleContext {
    fn as_ctx(&self) -> &RuleContext { *self }
}


#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockchainEvent {
    NewBlock { height: u64 },
    LargeTransfer { amount: u64, from: String, to: String },
    Reorg { depth: u64 },
}

impl BlockchainEvent {
    pub fn kind(&self) -> &'static str {
        match self {
            BlockchainEvent::NewBlock { .. } => "NewBlock",
            BlockchainEvent::LargeTransfer { .. } => "LargeTransfer",
            BlockchainEvent::Reorg { .. } => "Reorg",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EventParser {
    pub patterns: Vec<(String, String)>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcessIntrospector {
    pub process_name: Option<String>,
    pub log_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Default)]
pub struct HookManager {
    pub rules_engine: Option<RuleEngine>,
    pub events: Vec<BlockchainEvent>,
}

impl HookManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn on_event(&mut self, event: BlockchainEvent) -> Vec<Action> {
        self.events.push(event);
        Vec::new()
    }

    pub fn handle_event<E, C>(
        &mut self,
        event: BlockchainEvent,
        engine: E,
        ctx: C,
    ) -> Vec<Action>
    where
        E: AsRuleEngine,
        C: AsRuleContext,
    {
        let engine = engine.as_engine();
        let ctx = ctx.as_ctx();
        self.events.push(event.clone());
        let kind = event.kind();
        let mut actions = Vec::new();
        for rule in engine.evaluate_triggers(kind) {
            if rule.conditions.iter().all(|c| c.holds(ctx)) {
                actions.extend(rule.actions.clone());
            }
        }
        if actions.is_empty() {
            if let Some(rule) = engine.evaluate(kind, ctx) {
                actions.extend(rule.actions);
            }
        }
        actions
    }
}

pub fn handle_event<E, C>(
    manager: &mut HookManager,
    event: BlockchainEvent,
    engine: E,
    ctx: C,
) -> Vec<Action>
where
    E: AsRuleEngine,
    C: AsRuleContext,
{
    manager.handle_event(event, engine, ctx)
}

pub fn tail_log(path: impl AsRef<Path>) -> Vec<String> {
    match std::fs::read_to_string(path.as_ref()) {
        Ok(s) => s.lines().map(|l| l.to_string()).collect(),
        Err(_) => Vec::new(),
    }
}

fn first_number(s: &str) -> Option<u64> {
    let mut start = None;
    for (i, c) in s.char_indices() {
        if c.is_ascii_digit() {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(st) = start {
            return s[st..i].parse().ok();
        }
    }
    if let Some(st) = start {
        return s[st..].parse().ok();
    }
    None
}

fn value_after_label<'a>(line: &'a str, label: &str) -> Option<&'a str> {
    let idx = line.find(label)?;
    let rest = &line[idx + label.len()..];
    let rest = rest.trim_start_matches(|c: char| {
        c == '=' || c == ':' || c == ' ' || c == '\t' || c == '"' || c == '\''
    });
    let end = rest
        .find(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '"' || c == '\'')
        .unwrap_or(rest.len());
    let val = &rest[..end];
    if val.is_empty() {
        None
    } else {
        Some(val)
    }
}

fn strip_delim(s: &str) -> String {
    s.trim_matches(|c: char| c == ',' || c == ';' || c == '"' || c == '\'')
        .to_string()
}

pub fn parse_line(line: &str) -> Option<BlockchainEvent> {
    if line.contains("NewBlock") {
        let height = first_number(line).unwrap_or(0);
        // Prefer explicit height label if present.
        let height = value_after_label(line, "height")
            .and_then(|v| first_number(v))
            .unwrap_or(height);
        return Some(BlockchainEvent::NewBlock { height });
    }
    if line.contains("LargeTransfer") {
        let amount = value_after_label(line, "amount")
            .and_then(first_number)
            .or_else(|| first_number(line))
            .unwrap_or(0);
        let from = value_after_label(line, "from")
            .map(strip_delim)
            .unwrap_or_else(|| {
                // fallback: token after amount
                line.split_whitespace().nth(2).unwrap_or("").to_string()
            });
        let to = value_after_label(line, "to")
            .map(strip_delim)
            .unwrap_or_else(|| {
                line.split_whitespace().nth(3).unwrap_or("").to_string()
            });
        return Some(BlockchainEvent::LargeTransfer { amount, from, to });
    }
    if line.contains("Reorg") {
        let depth = value_after_label(line, "depth")
            .and_then(first_number)
            .or_else(|| first_number(line))
            .unwrap_or(0);
        return Some(BlockchainEvent::Reorg { depth });
    }
    None
}

// Associated-style helpers on structs.
impl EventParser {
    pub fn tail_log(path: impl AsRef<Path>) -> Vec<String> {
        tail_log(path)
    }
    pub fn parse_line(line: &str) -> Option<BlockchainEvent> {
        parse_line(line)
    }
}

impl ProcessIntrospector {
    pub fn tail_log(path: impl AsRef<Path>) -> Vec<String> {
        tail_log(path)
    }
    pub fn parse_line(line: &str) -> Option<BlockchainEvent> {
        parse_line(line)
    }
}

// Trait hedges for method-call syntax when traits are in scope.
pub trait TailLogExt {
    fn tail_log(&self, path: impl AsRef<Path>) -> Vec<String> {
        tail_log(path)
    }
}
pub trait ParseLineExt {
    fn parse_line(&self, line: &str) -> Option<BlockchainEvent> {
        parse_line(line)
    }
}
impl TailLogExt for EventParser {}
impl TailLogExt for ProcessIntrospector {}
impl ParseLineExt for EventParser {}
impl ParseLineExt for ProcessIntrospector {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_new_block() {
        assert_eq!(
            parse_line("NewBlock height=42"),
            Some(BlockchainEvent::NewBlock { height: 42 })
        );
        assert_eq!(
            EventParser::parse_line("newblock? no uppercase? NewBlock 7"),
            Some(BlockchainEvent::NewBlock { height: 7 })
        );
    }

    #[test]
    fn parse_large_transfer() {
        assert_eq!(
            parse_line("LargeTransfer amount=100 from=alice to=bob"),
            Some(BlockchainEvent::LargeTransfer {
                amount: 100,
                from: "alice".into(),
                to: "bob".into()
            })
        );
        assert_eq!(
            parse_line("LargeTransfer amount: 5 from: x to: y"),
            Some(BlockchainEvent::LargeTransfer {
                amount: 5,
                from: "x".into(),
                to: "y".into()
            })
        );
    }

    #[test]
    fn parse_reorg() {
        assert_eq!(
            parse_line("Reorg depth=3"),
            Some(BlockchainEvent::Reorg { depth: 3 })
        );
        assert_eq!(
            parse_line("Chain Reorg 9"),
            Some(BlockchainEvent::Reorg { depth: 9 })
        );
    }

    #[test]
    fn parse_unknown() {
        assert_eq!(parse_line("hello world"), None);
    }

    #[test]
    fn tail_log_reads() {
        let dir = std::env::temp_dir().join("chainhooks_test.log");
        std::fs::write(&dir, "a\nb\nc\n").unwrap();
        assert_eq!(tail_log(&dir), vec!["a", "b", "c"]);
        std::fs::remove_file(&dir).ok();
    }
}
