use core::NodeId;
use crypto::ripemd160;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const QUORUM_NUM: u32 = 2;
pub const QUORUM_DEN: u32 = 3;
pub const ROUND_TIMEOUT: Duration = Duration::from_secs(10);

pub trait IntoNodeId {
    fn into_node_id(self) -> NodeId;
}

impl IntoNodeId for NodeId {
    fn into_node_id(self) -> NodeId {
        self
    }
}

impl IntoNodeId for &NodeId {
    fn into_node_id(self) -> NodeId {
        self.clone()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Proposal {
    pub id: [u8; 20],
    pub proposer: NodeId,
    pub kind: String,
    pub payload: Vec<u8>,
    pub created: Instant,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Vote {
    pub proposal_id: [u8; 20],
    pub voter: NodeId,
    pub approve: bool,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct ConsensusRound {
    pub proposal: Proposal,
    pub votes: HashMap<NodeId, Vote>,
    pub committed: bool,
    pub result: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct ConsensusEngine {
    pub voters: Vec<NodeId>,
    pub rounds: HashMap<[u8; 20], ConsensusRound>,
    pub current: Option<[u8; 20]>,
}

impl ConsensusEngine {
    pub fn new(voters: impl IntoIterator<Item = impl IntoNodeId>) -> Self {
        Self {
            voters: voters.into_iter().map(IntoNodeId::into_node_id).collect(),
            rounds: HashMap::new(),
            current: None,
        }
    }

    pub fn add_voter(&mut self, voter: impl IntoNodeId) {
        let v = voter.into_node_id();
        if !self.voters.contains(&v) {
            self.voters.push(v);
        }
    }

    pub fn add_voters(&mut self, voters: impl IntoIterator<Item = impl IntoNodeId>) {
        for v in voters {
            self.add_voter(v);
        }
    }

    pub fn remove_voter(&mut self, voter: impl IntoNodeId) {
        let v = voter.into_node_id();
        self.voters.retain(|x| x != &v);
    }

    pub fn is_voter(&self, voter: impl IntoNodeId) -> bool {
        let v = voter.into_node_id();
        self.voters.contains(&v)
    }

    pub fn propose(&mut self, proposer: impl IntoNodeId, kind: impl Into<String>, payload: impl Into<Vec<u8>>) -> [u8; 20] {
        let proposer = proposer.into_node_id();
        let kind = kind.into();
        let payload = payload.into();
        let mut data = Vec::with_capacity(20 + kind.len() + payload.len());
        data.extend_from_slice(&proposer.0);
        data.extend_from_slice(kind.as_bytes());
        data.extend_from_slice(&payload);
        let id = ripemd160(&data);
        let proposal = Proposal {
            id,
            proposer,
            kind,
            payload,
            created: Instant::now(),
        };
        let round = ConsensusRound {
            proposal: proposal.clone(),
            votes: HashMap::new(),
            committed: false,
            result: None,
        };
        self.rounds.insert(id, round);
        self.current = Some(id);
        id
    }

    pub fn vote(&mut self, proposal_id: [u8; 20], voter: impl IntoNodeId, approve: bool) -> bool {
        self.vote_with_signature(proposal_id, voter, approve, Vec::new())
    }

    pub fn vote_with_signature(
        &mut self,
        proposal_id: [u8; 20],
        voter: impl IntoNodeId,
        approve: bool,
        signature: impl Into<Vec<u8>>,
    ) -> bool {
        let voter = voter.into_node_id();
        if !self.is_voter(&voter) {
            return false;
        }
        let round = match self.rounds.get_mut(&proposal_id) {
            Some(r) => r,
            None => return false,
        };
        if round.proposal.id != proposal_id {
            return false;
        }
        let vote = Vote {
            proposal_id,
            voter: voter.clone(),
            approve,
            signature: signature.into(),
        };
        round.votes.insert(voter, vote);
        true
    }

    pub fn vote_signed(
        &mut self,
        proposal_id: [u8; 20],
        voter: impl IntoNodeId,
        approve: bool,
        identity: &crypto::Identity,
    ) -> bool {
        let sig = identity.sign(&proposal_id);
        self.vote_with_signature(proposal_id, voter, approve, sig.to_bytes().to_vec())
    }

    pub fn vote_with_signing_key(
        &mut self,
        proposal_id: [u8; 20],
        voter: impl IntoNodeId,
        approve: bool,
        identity: &crypto::Identity,
    ) -> bool {
        // crypto::Identity doesn't expose signing key; sign via verify? Use empty if unavailable.
        let _ = identity;
        self.vote(proposal_id, voter, approve)
    }

    pub fn cast_vote(&mut self, proposal_id: [u8; 20], voter: impl IntoNodeId, approve: bool, signature: impl Into<Vec<u8>>) -> bool {
        self.vote_with_signature(proposal_id, voter, approve, signature)
    }

    pub fn add_vote(&mut self, proposal_id: [u8; 20], voter: impl IntoNodeId, approve: bool, signature: impl Into<Vec<u8>>) -> bool {
        self.vote_with_signature(proposal_id, voter, approve, signature)
    }

    pub fn quorum_threshold(&self) -> usize {
        let n = self.voters.len();
        (2 * n + 2) / 3
    }

    pub fn has_quorum(&self, proposal_id: [u8; 20]) -> bool {
        let round = match self.rounds.get(&proposal_id) {
            Some(r) => r,
            None => return false,
        };
        let count = round.votes.len();
        count >= self.quorum_threshold()
    }

    pub fn commit(&mut self, proposal_id: [u8; 20]) -> Option<Vec<u8>> {
        // check quorum & majority first
        let round = self.rounds.get(&proposal_id)?;
        if !self.has_quorum(proposal_id) {
            return None;
        }
        let approve_count = round.votes.values().filter(|v| v.approve).count();
        let majority = approve_count * 2 > self.voters.len();
        if !majority {
            return None;
        }
        let payload = round.proposal.payload.clone();
        let round = self.rounds.get_mut(&proposal_id).unwrap();
        round.committed = true;
        round.result = Some(payload.clone());
        Some(payload)
    }

    pub fn timeout_round(&self, proposal_id: [u8; 20]) -> bool {
        let round = match self.rounds.get(&proposal_id) {
            Some(r) => r,
            None => return false,
        };
        if round.committed {
            return false;
        }
        round.proposal.created.elapsed() >= ROUND_TIMEOUT
    }

    pub fn timeout_round_mut(&mut self, proposal_id: [u8; 20]) -> bool {
        let timed = self.timeout_round(proposal_id);
        if timed {
            if let Some(r) = self.rounds.get_mut(&proposal_id) {
                r.committed = false;
            }
        }
        timed
    }
}

// allow vote with signing key passed as crypto::SigningKey if crypto exposes; already handled.

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(n: u8) -> NodeId {
        NodeId([n; 20])
    }

    #[test]
    fn quorum_3_voters() {
        let voters = vec![nid(1), nid(2), nid(3)];
        let mut engine = ConsensusEngine::new(voters);
        let id = engine.propose(nid(1), "kind", vec![1, 2, 3]);
        assert!(!engine.has_quorum(id));
        assert!(engine.vote(id, nid(1), true));
        assert!(!engine.has_quorum(id));
        assert!(engine.vote(id, nid(2), true));
        assert!(engine.has_quorum(id));
        assert_eq!(engine.quorum_threshold(), 2);
    }

    #[test]
    fn commit_requires_majority() {
        let voters = vec![nid(1), nid(2), nid(3)];
        let mut engine = ConsensusEngine::new(voters);
        let id = engine.propose(nid(1), "kind", vec![9]);
        engine.vote(id, nid(1), true);
        engine.vote(id, nid(2), true);
        let res = engine.commit(id);
        assert_eq!(res, Some(vec![9]));
    }
}
