use rand::RngCore;
use sha3::{Digest, Keccak256};

use crate::types::NodeInfo;

const K: usize = 16;
const NUM_BUCKETS: usize = 256;

struct Bucket {
    entries: Vec<NodeInfo>,
}

impl Bucket {
    fn new() -> Self {
        Bucket {
            entries: Vec::new(),
        }
    }
}

pub struct RoutingTable {
    self_id: [u8; 32],
    buckets: Vec<Bucket>,
}

fn node_id_hash(pubkey: &[u8; 64]) -> [u8; 32] {
    let hash = Keccak256::digest(pubkey);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

fn log_distance(a: &[u8; 32], b: &[u8; 32]) -> usize {
    let mut distance = 0;
    for i in 0..32 {
        let xor = a[i] ^ b[i];
        if xor == 0 {
            distance += 8;
        } else {
            distance += xor.leading_zeros() as usize;
            break;
        }
    }
    // distance is the number of leading zero bits in the XOR
    // bucket index = 255 - distance (higher = further away)
    NUM_BUCKETS.saturating_sub(1 + distance)
}

impl RoutingTable {
    pub fn new(self_pubkey: &[u8; 64]) -> Self {
        let self_id = node_id_hash(self_pubkey);
        let mut buckets = Vec::with_capacity(NUM_BUCKETS);
        for _ in 0..NUM_BUCKETS {
            buckets.push(Bucket::new());
        }
        RoutingTable { self_id, buckets }
    }

    pub fn insert(&mut self, node: NodeInfo) -> bool {
        let node_hash = node_id_hash(&node.pubkey);
        if node_hash == self.self_id {
            return false;
        }

        let bucket_idx = log_distance(&self.self_id, &node_hash);
        let bucket = &mut self.buckets[bucket_idx];

        // Check if already exists
        if let Some(pos) = bucket.entries.iter().position(|e| e.pubkey == node.pubkey) {
            // Move to end (most recently seen)
            let entry = bucket.entries.remove(pos);
            bucket.entries.push(entry);
            return true;
        }

        if bucket.entries.len() < K {
            bucket.entries.push(node);
            true
        } else {
            // Bucket full, drop new node (simplified eviction)
            false
        }
    }

    pub fn closest(&self, target: &[u8; 64], count: usize) -> Vec<NodeInfo> {
        let target_hash = node_id_hash(target);

        let mut all_nodes: Vec<(NodeInfo, [u8; 32])> = Vec::new();
        for bucket in &self.buckets {
            for entry in &bucket.entries {
                let entry_hash = node_id_hash(&entry.pubkey);
                let mut xor = [0u8; 32];
                for i in 0..32 {
                    xor[i] = target_hash[i] ^ entry_hash[i];
                }
                all_nodes.push((entry.clone(), xor));
            }
        }

        all_nodes.sort_by(|a, b| a.1.cmp(&b.1));
        all_nodes.truncate(count);
        all_nodes.into_iter().map(|(n, _)| n).collect()
    }

    pub fn random_target(&self) -> [u8; 64] {
        let mut target = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut target);
        target
    }

    #[cfg(test)]
    pub fn remove(&mut self, pubkey: &[u8; 64]) -> bool {
        let node_hash = node_id_hash(pubkey);
        let bucket_idx = log_distance(&self.self_id, &node_hash);
        let bucket = &mut self.buckets[bucket_idx];

        if let Some(pos) = bucket.entries.iter().position(|e| e.pubkey == *pubkey) {
            bucket.entries.remove(pos);
            true
        } else {
            false
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.entries.len()).sum()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn make_node(byte: u8) -> NodeInfo {
        let mut pubkey = [0u8; 64];
        pubkey[0] = byte;
        pubkey[1] = byte;
        NodeInfo {
            pubkey,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, byte)), 30303),
            tcp_port: 30303,
            udp_port: 30303,
        }
    }

    #[test]
    fn test_insert_and_len() {
        let self_key = [0xFFu8; 64];
        let mut table = RoutingTable::new(&self_key);

        assert!(table.insert(make_node(1)));
        assert!(table.insert(make_node(2)));
        assert!(table.insert(make_node(3)));
        assert_eq!(table.len(), 3);
    }

    #[test]
    fn test_insert_self_rejected() {
        let self_key = [0xFFu8; 64];
        let mut table = RoutingTable::new(&self_key);

        let mut self_node = make_node(0);
        self_node.pubkey = self_key;
        assert!(!table.insert(self_node));
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_insert_duplicate_updates() {
        let self_key = [0xFFu8; 64];
        let mut table = RoutingTable::new(&self_key);

        assert!(table.insert(make_node(1)));
        assert!(table.insert(make_node(1)));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_closest() {
        let self_key = [0xFFu8; 64];
        let mut table = RoutingTable::new(&self_key);

        for i in 1..=10 {
            table.insert(make_node(i));
        }

        let target = [0x01u8; 64];
        let closest = table.closest(&target, 3);
        assert_eq!(closest.len(), 3);
    }

    #[test]
    fn test_remove() {
        let self_key = [0xFFu8; 64];
        let mut table = RoutingTable::new(&self_key);

        let node = make_node(1);
        table.insert(node.clone());
        assert_eq!(table.len(), 1);

        assert!(table.remove(&node.pubkey));
        assert_eq!(table.len(), 0);
        assert!(!table.remove(&node.pubkey));
    }

    #[test]
    fn test_random_target() {
        let self_key = [0xFFu8; 64];
        let table = RoutingTable::new(&self_key);

        let t1 = table.random_target();
        let t2 = table.random_target();
        assert_ne!(t1, t2);
    }
}
