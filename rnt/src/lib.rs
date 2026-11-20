use core;
use crypto;
use std::collections::HashMap;

pub fn validate_region_code(code: &str) -> bool {
    let segments: Vec<&str> = code.split('/').collect();
    if segments.is_empty() || segments.len() > 4 {
        return false;
    }
    for seg in segments {
        if seg.is_empty() {
            return false;
        }
        if seg.starts_with('-') || seg.ends_with('-') {
            return false;
        }
        for c in seg.chars() {
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
                return false;
            }
        }
    }
    true
}

pub fn region_bucket_key(code: &str) -> [u8; 20] {
    crypto::ripemd160(code.as_bytes())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegionNode {
    pub node_id: core::NodeId,
    pub addrs: Vec<String>,
}

impl RegionNode {
    pub fn new(node_id: core::NodeId, addrs: Vec<String>) -> Self {
        Self { node_id, addrs }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RntError {
    InvalidRegionCode(String),
    InvalidCode(String),
    InvalidRegion(String),
    RegionNotFound(String),
    RegionNotFoundCode(String),
    NodeNotFound,
    NotFound,
}

impl std::fmt::Display for RntError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RntError::InvalidRegionCode(c)
            | RntError::InvalidCode(c)
            | RntError::InvalidRegion(c) => write!(f, "invalid region code: {}", c),
            RntError::RegionNotFound(c) | RntError::RegionNotFoundCode(c) => {
                write!(f, "region not found: {}", c)
            }
            RntError::NodeNotFound | RntError::NotFound => write!(f, "node not found"),
        }
    }
}

impl std::error::Error for RntError {}


pub trait AsNodeId {
    fn as_node_id(&self) -> &core::NodeId;
}

impl AsNodeId for core::NodeId {
    fn as_node_id(&self) -> &core::NodeId {
        self
    }
}

impl AsNodeId for &core::NodeId {
    fn as_node_id(&self) -> &core::NodeId {
        *self
    }
}

pub struct RntTable {
    pub regions: HashMap<String, Vec<RegionNode>>,
}

impl RntTable {
    pub fn new() -> Self {
        let mut regions = HashMap::new();
        regions.insert("global".to_string(), Vec::new());
        Self { regions }
    }

    pub fn insert<C>(&mut self, code: C, node: RegionNode) -> Result<(), RntError>
    where
        C: AsRef<str>,
    {
        let code = code.as_ref();
        if !validate_region_code(code) {
            return Err(RntError::InvalidRegionCode(code.to_string()));
        }
        self.regions
            .entry(code.to_string())
            .or_default()
            .push(node);
        Ok(())
    }

    pub fn remove<C, N>(&mut self, code: C, node_id: N) -> bool
    where
        C: AsRef<str>,
        N: AsNodeId,
    {
        let code = code.as_ref();
        let node_id = node_id.as_node_id();
        if let Some(nodes) = self.regions.get_mut(code) {
            let before = nodes.len();
            nodes.retain(|n| &n.node_id != node_id);
            before != nodes.len()
        } else {
            false
        }
    }

    pub fn get(&self, code: impl AsRef<str>) -> Option<&[RegionNode]> {
        self.regions.get(code.as_ref()).map(|v| v.as_slice())
    }

    pub fn contains_region(&self, code: impl AsRef<str>) -> bool {
        self.regions.contains_key(code.as_ref())
    }

    pub fn list_regions(&self) -> Vec<String> {
        let mut v: Vec<String> = self.regions.keys().cloned().collect();
        v.sort();
        v
    }

    pub fn all_nodes(&self) -> Vec<RegionNode> {
        self.regions.values().flatten().cloned().collect()
    }

    pub fn contains(&self, code: impl AsRef<str>) -> bool {
        self.contains_region(code)
    }

    pub fn get_region(&self, code: impl AsRef<str>) -> Option<&[RegionNode]> {
        self.get(code)
    }
    pub fn clear(&mut self) {
        self.regions.clear();
        self.regions.insert("global".to_string(), Vec::new());
    }
}

impl Default for RntTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_region_code_works() {
        assert!(validate_region_code("global"));
        assert!(validate_region_code("us"));
        assert!(validate_region_code("us-east"));
        assert!(validate_region_code("a/b/c/d"));
        assert!(validate_region_code("a1/b2/c3/d4"));
        assert!(!validate_region_code(""));
        assert!(!validate_region_code("/"));
        assert!(!validate_region_code("a//b"));
        assert!(!validate_region_code("A"));
        assert!(!validate_region_code("-a"));
        assert!(!validate_region_code("a-"));
        assert!(!validate_region_code("a/b/c/d/e"));
        assert!(!validate_region_code("a b"));
    }

    #[test]
    fn insert_and_get() {
        let mut table = RntTable::new();
        assert!(table.contains_region("global"));
        let node = RegionNode::new(core::NodeId([0u8; 20]), vec!["addr".into()]);
        table.insert("us-east", node).unwrap();
        let got = table.get("us-east").unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].addrs, vec!["addr".to_string()]);
        assert!(table.insert("bad code", RegionNode::new(core::NodeId([1u8; 20]), vec![])).is_err());
    }

    #[test]
    fn remove_works() {
        let mut table = RntTable::new();
        let id = core::NodeId([2u8; 20]);
        table.insert("global", RegionNode::new(id.clone(), vec![])).unwrap();
        assert!(table.remove("global", &id));
        assert!(!table.remove("global", &id));
        let got = table.get("global").unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn region_bucket_key_len() {
        let k = region_bucket_key("global");
        assert_eq!(k.len(), 20);
    }
}
