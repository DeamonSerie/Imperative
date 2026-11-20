use core::{NodeId, RegionCode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

pub const K: usize = 20;
pub const ALPHA: usize = 3;
pub const REPLICATION: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SiteLocator {
    pub protocol: String,
    pub name: String,
    pub content_root: [u8; 20],
    pub host: NodeId,
    pub addrs: Vec<String>,
    pub ttl: u64,
    pub signature: Vec<u8>,
}

pub fn record_key<E, N>(extension: E, name: N) -> [u8; 20]
where
    E: AsRef<str>,
    N: AsRef<str>,
{
    let mut data = Vec::new();
    data.extend_from_slice(extension.as_ref().as_bytes());
    data.extend_from_slice(name.as_ref().as_bytes());
    crypto::ripemd160(&data)
}

pub fn distance<A, B>(a: A, b: B) -> Vec<u8>
where
    A: AsRef<[u8]>,
    B: AsRef<[u8]>,
{
    let a = a.as_ref();
    let b = b.as_ref();
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

// Target bytes trait for find_closest
pub trait TargetBytes {
    fn bytes(&self) -> Vec<u8>;
}

impl TargetBytes for [u8; 20] {
    fn bytes(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl TargetBytes for &[u8; 20] {
    fn bytes(&self) -> Vec<u8> {
        self.to_vec()
    }
}

impl TargetBytes for NodeId {
    fn bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl TargetBytes for &NodeId {
    fn bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl TargetBytes for &mut NodeId {
    fn bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

pub trait NodeLike {
    fn node(&self) -> NodeId;
}

impl NodeLike for NodeId {
    fn node(&self) -> NodeId {
        self.clone()
    }
}

impl NodeLike for &NodeId {
    fn node(&self) -> NodeId {
        (*self).clone()
    }
}

impl NodeLike for &mut NodeId {
    fn node(&self) -> NodeId {
        (*self).clone()
    }
}

pub trait RegionInput {
    fn into_region(self) -> RegionCode;
}

impl RegionInput for RegionCode {
    fn into_region(self) -> RegionCode {
        self
    }
}

impl RegionInput for &RegionCode {
    fn into_region(self) -> RegionCode {
        self.clone()
    }
}

impl RegionInput for String {
    fn into_region(self) -> RegionCode {
        RegionCode(self)
    }
}

impl RegionInput for &String {
    fn into_region(self) -> RegionCode {
        RegionCode(self.clone())
    }
}

impl RegionInput for &str {
    fn into_region(self) -> RegionCode {
        RegionCode(self.to_string())
    }
}

pub fn find_closest<T, I>(target: T, nodes: I, count: usize) -> Vec<NodeId>
where
    T: TargetBytes,
    I: IntoIterator,
    I::Item: NodeLike,
{
    let tb = target.bytes();
    let mut v: Vec<NodeId> = nodes.into_iter().map(|n| n.node()).collect();
    v.sort_by(|a, b| {
        distance(a.0.as_slice(), tb.as_slice()).cmp(&distance(b.0.as_slice(), tb.as_slice()))
    });
    if v.len() > count {
        v.truncate(count);
    }
    v
}

#[derive(Clone, Debug, Default)]
pub struct KBucket {
    pub nodes: Vec<NodeId>,
}

impl KBucket {
    pub fn new() -> Self {
        Self { nodes: Vec::new() }
    }
    pub fn add(&mut self, node: NodeId) {
        if !self.nodes.contains(&node) {
            self.nodes.push(node);
        }
    }
}

#[derive(Clone, Debug)]
pub struct RoutingTable {
    pub self_id: NodeId,
    pub peers: Vec<NodeId>,
    pub kbuckets: Vec<KBucket>,
}

impl RoutingTable {
    pub fn new<N: NodeLike>(self_id: N) -> Self {
        Self {
            self_id: self_id.node(),
            peers: Vec::new(),
            kbuckets: Vec::new(),
        }
    }
    pub fn add_peer(&mut self, node: NodeId) {
        if !self.peers.contains(&node) {
            self.peers.push(node);
        }
    }
    pub fn find_closest(&self, target: impl TargetBytes, count: usize) -> Vec<NodeId> {
        find_closest(target, self.peers.clone(), count)
    }
    pub fn insert(&mut self, node: NodeId) {
        self.add_peer(node);
    }
    pub fn add(&mut self, node: NodeId) {
        self.add_peer(node);
    }
    pub fn remove(&mut self, node: &NodeId) -> bool {
        let before = self.peers.len();
        self.peers.retain(|n| n != node);
        before != self.peers.len()
    }
    pub fn contains(&self, node: &NodeId) -> bool {
        self.peers.contains(node)
    }
    pub fn closest(&self, target: impl TargetBytes, count: usize) -> Vec<NodeId> {
        self.find_closest(target, count)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DhtRpc {
    FindNode { key: [u8; 20] },
    FindValue { key: [u8; 20] },
    Store { key: [u8; 20], value: Vec<u8> },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DhtNode {
    pub node_id: NodeId,
    pub region: RegionCode,
    pub peers: Vec<NodeId>,
}

impl DhtNode {
    pub fn new<N, R>(node_id: N, region: R) -> Self
    where
        N: NodeLike,
        R: RegionInput,
    {
        Self {
            node_id: node_id.node(),
            region: region.into_region(),
            peers: Vec::new(),
        }
    }
    pub fn find_closest(&self, target: impl TargetBytes, count: usize) -> Vec<NodeId> {
        find_closest(target, self.peers.clone(), count)
    }
    pub fn store(&mut self, record: SiteLocator) {
        let key = record_key(&record.protocol, &record.name);
        self.store_at(key, record);
    }
    pub fn store_at(&mut self, key: [u8; 20], record: SiteLocator) {
        let mut map = storage().lock().unwrap();
        let entry = map.entry(self.node_id.clone()).or_default();
        entry.insert(key, record);
    }
    pub fn get<K>(&self, key: K) -> Option<SiteLocator>
    where
        K: AsRef<[u8]>,
    {
        let key_bytes = key.as_ref();
        let mut arr = [0u8; 20];
        for (i, b) in key_bytes.iter().take(20).enumerate() {
            arr[i] = *b;
        }
        let map = storage().lock().unwrap();
        map.get(&self.node_id)
            .and_then(|m| m.get(&arr).cloned())
    }
    pub fn evict_stale(&mut self, now: u64) -> Vec<[u8; 20]> {
        let mut removed = Vec::new();
        let mut map = storage().lock().unwrap();
        if let Some(m) = map.get_mut(&self.node_id) {
            let keys: Vec<[u8; 20]> = m.keys().cloned().collect();
            for k in keys {
                if let Some(rec) = m.get(&k) {
                    if rec.ttl < now {
                        m.remove(&k);
                        removed.push(k);
                    }
                }
            }
        }
        removed
    }

    pub fn store_record(&mut self, record: SiteLocator) {
        self.store(record);
    }
    pub fn store_key(&mut self, key: [u8; 20], record: SiteLocator) {
        self.store_at(key, record);
    }
    pub fn put(&mut self, record: SiteLocator) {
        self.store(record);
    }
    pub fn put_at(&mut self, key: [u8; 20], record: SiteLocator) {
        self.store_at(key, record);
    }
    pub fn get_record<K>(&self, key: K) -> Option<SiteLocator>
    where
        K: AsRef<[u8]>,
    {
        self.get(key)
    }
    pub fn lookup<K>(&self, key: K) -> Option<SiteLocator>
    where
        K: AsRef<[u8]>,
    {
        self.get(key)
    }
    pub fn add_peer(&mut self, node: NodeId) {
        if !self.peers.contains(&node) {
            self.peers.push(node);
        }
    }
    pub fn insert_peer(&mut self, node: NodeId) {
        self.add_peer(node);
    }
    pub fn remove_peer(&mut self, node: &NodeId) -> bool {
        let before = self.peers.len();
        self.peers.retain(|n| n != node);
        before != self.peers.len()
    }
}

use std::sync::OnceLock;
static STORAGE: OnceLock<Mutex<HashMap<NodeId, HashMap<[u8; 20], SiteLocator>>>> = OnceLock::new();

fn storage() -> &'static Mutex<HashMap<NodeId, HashMap<[u8; 20], SiteLocator>>> {
    STORAGE.get_or_init(|| Mutex::new(HashMap::new()))
}

// Local storage helper
#[derive(Clone, Debug, Default)]
pub struct LocalStore {
    pub records: HashMap<[u8; 20], SiteLocator>,
}

impl LocalStore {
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
        }
    }
    pub fn store(&mut self, record: SiteLocator) {
        let key = record_key(&record.protocol, &record.name);
        self.records.insert(key, record);
    }
    pub fn store_at(&mut self, key: [u8; 20], record: SiteLocator) {
        self.records.insert(key, record);
    }
    pub fn get<K>(&self, key: K) -> Option<SiteLocator>
    where
        K: AsRef<[u8]>,
    {
        let key_bytes = key.as_ref();
        let mut arr = [0u8; 20];
        for (i, b) in key_bytes.iter().take(20).enumerate() {
            arr[i] = *b;
        }
        self.records.get(&arr).cloned()
    }
    pub fn evict_stale(&mut self, now: u64) -> Vec<[u8; 20]> {
        let mut removed = Vec::new();
        let keys: Vec<[u8; 20]> = self.records.keys().cloned().collect();
        for k in keys {
            if let Some(rec) = self.records.get(&k) {
                if rec.ttl < now {
                    self.records.remove(&k);
                    removed.push(k);
                }
            }
        }
        removed
    }
}

// Aliases for compatibility
pub type Dht = DhtNode;
pub type DhtStorage = LocalStore;
pub type RecordStore = LocalStore;
pub type Storage = LocalStore;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants() {
        assert_eq!(K, 20);
        assert_eq!(ALPHA, 3);
        assert_eq!(REPLICATION, 3);
    }

    #[test]
    fn distance_works() {
        let a = [1u8; 20];
        let b = [2u8; 20];
        let d = distance(&a, &b);
        assert_eq!(d.len(), 20);
        assert_eq!(d[0], 3);
    }

    #[test]
    fn record_key_len() {
        let k = record_key("proto", "name");
        assert_eq!(k.len(), 20);
    }

    #[test]
    fn find_closest_works() {
        let target = [0u8; 20];
        let n1 = NodeId([1u8; 20]);
        let n2 = NodeId([2u8; 20]);
        let nodes = vec![n2.clone(), n1.clone()];
        let res = find_closest(&target, &nodes, 1);
        assert_eq!(res.len(), 1);
        assert_eq!(res[0], n1);
    }

    #[test]
    fn store_get_evict() {
        let id = NodeId([9u8; 20]);
        let mut node = DhtNode::new(id.clone(), RegionCode("global".into()));
        let rec = SiteLocator {
            protocol: "p".into(),
            name: "n".into(),
            content_root: [0u8; 20],
            host: id.clone(),
            addrs: vec![],
            ttl: 10,
            signature: vec![],
        };
        node.store(rec.clone());
        let key = record_key("p", "n");
        assert_eq!(node.get(&key), Some(rec));
        node.evict_stale(20);
        assert!(node.get(&key).is_none());
    }
}
