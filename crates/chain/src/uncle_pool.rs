use std::collections::HashMap;

use alloy_primitives::B256;

use crate::types::BlockHeader;

/// Maximum uncles per block (Ethereum yellow paper).
const MAX_UNCLES: usize = 2;
/// Maximum uncle depth (uncle must be within 7 generations of the including block).
const MAX_UNCLE_DEPTH: u64 = 7;

/// Pool of uncle candidates — blocks that were valid but lost the TD race.
///
/// The CL is stateless, so this pool lives in memory and is rebuilt after restart
/// (uncles from before restart are lost, which is acceptable).
pub struct UnclePool {
    /// Candidate blocks grouped by block number.
    candidates: HashMap<u64, Vec<(BlockHeader, B256)>>,
    /// Hashes of uncles already included in canonical blocks, with the block number
    /// of the including block (for age-based eviction).
    used: HashMap<B256, u64>,
}

impl UnclePool {
    pub fn new() -> Self {
        Self {
            candidates: HashMap::new(),
            used: HashMap::new(),
        }
    }

    /// Add a block that lost the TD race as an uncle candidate.
    pub fn add_candidate(&mut self, header: BlockHeader, hash: B256) {
        // Don't add if already used
        if self.used.contains_key(&hash) {
            return;
        }
        let entries = self.candidates.entry(header.number).or_default();
        // Don't add duplicates
        if entries.iter().any(|(_, h)| *h == hash) {
            return;
        }
        entries.push((header, hash));
    }

    /// Mark uncle hashes as already included in a canonical block at `block_number`.
    pub fn mark_used(&mut self, hashes: &[B256], block_number: u64) {
        for hash in hashes {
            self.used.insert(*hash, block_number);
        }
        // Remove from candidates too
        for entries in self.candidates.values_mut() {
            entries.retain(|(_, h)| !self.used.contains_key(h));
        }
        // Clean up empty entries
        self.candidates.retain(|_, v| !v.is_empty());
    }

    /// Get the best uncle candidates for a block at `head_number + 1`.
    ///
    /// Returns up to MAX_UNCLES (2) headers within MAX_UNCLE_DEPTH (7) of
    /// the including block, preferring higher-difficulty uncles.
    pub fn get_best_uncles(&self, head_number: u64) -> Vec<BlockHeader> {
        let including_number = head_number + 1;
        let min_number = including_number.saturating_sub(MAX_UNCLE_DEPTH);

        let mut candidates: Vec<&(BlockHeader, B256)> = self
            .candidates
            .iter()
            .filter(|(&num, _)| num >= min_number && num < including_number)
            .flat_map(|(_, entries)| entries.iter())
            .filter(|(_, hash)| !self.used.contains_key(hash))
            .collect();

        // Sort by difficulty descending (prefer higher-difficulty uncles for more reward)
        candidates.sort_by(|a, b| b.0.difficulty.cmp(&a.0.difficulty));

        candidates
            .into_iter()
            .take(MAX_UNCLES)
            .map(|(header, _)| header.clone())
            .collect()
    }

    /// Prune entries older than MAX_UNCLE_DEPTH from the current head.
    pub fn prune(&mut self, head_number: u64) {
        let min_keep = head_number.saturating_sub(MAX_UNCLE_DEPTH + 1);
        self.candidates.retain(|&num, _| num >= min_keep);
        // Prune used set: only keep entries from recent blocks
        self.used
            .retain(|_, &mut included_at| included_at >= min_keep);
    }
}

impl Default for UnclePool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::empty_uncle_hash;
    use alloy_primitives::{Address, U256};

    fn make_header(number: u64, difficulty: u64) -> BlockHeader {
        BlockHeader {
            parent_hash: B256::ZERO,
            uncle_hash: empty_uncle_hash(),
            coinbase: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: [0u8; 256],
            difficulty: U256::from(difficulty),
            number,
            gas_limit: 8_000_000,
            gas_used: 0,
            timestamp: 1_000_000 + number,
            extra_data: vec![],
            mix_hash: B256::ZERO,
            nonce: [0u8; 8],
            base_fee: None,
        }
    }

    fn make_hash(n: u8) -> B256 {
        let mut bytes = [0u8; 32];
        bytes[31] = n;
        B256::from(bytes)
    }

    #[test]
    fn add_and_get_uncles() {
        let mut pool = UnclePool::new();

        let h1 = make_header(100, 1000);
        let h2 = make_header(99, 2000);
        pool.add_candidate(h1, make_hash(1));
        pool.add_candidate(h2, make_hash(2));

        let uncles = pool.get_best_uncles(100);
        assert_eq!(uncles.len(), 2);
        // Higher difficulty first
        assert_eq!(uncles[0].difficulty, U256::from(2000));
        assert_eq!(uncles[1].difficulty, U256::from(1000));
    }

    #[test]
    fn mark_used_excludes_from_results() {
        let mut pool = UnclePool::new();

        pool.add_candidate(make_header(100, 1000), make_hash(1));
        pool.add_candidate(make_header(100, 2000), make_hash(2));

        pool.mark_used(&[make_hash(2)], 101);

        let uncles = pool.get_best_uncles(100);
        assert_eq!(uncles.len(), 1);
        assert_eq!(uncles[0].difficulty, U256::from(1000));
    }

    #[test]
    fn prune_removes_old_entries() {
        let mut pool = UnclePool::new();

        pool.add_candidate(make_header(90, 1000), make_hash(1));
        pool.add_candidate(make_header(100, 2000), make_hash(2));

        pool.prune(100);
        // Block 90 is older than 100 - 8 = 92, should be pruned
        let uncles = pool.get_best_uncles(100);
        assert_eq!(uncles.len(), 1);
        assert_eq!(uncles[0].number, 100);
    }

    #[test]
    fn depth_limit_respected() {
        let mut pool = UnclePool::new();

        // Block 92 is within depth 7 of including block 100 (min_number = 93)
        // Actually: including_number = 101, min_number = 101 - 7 = 94
        pool.add_candidate(make_header(93, 1000), make_hash(1));
        pool.add_candidate(make_header(94, 2000), make_hash(2));

        let uncles = pool.get_best_uncles(100);
        // Only block 94 is within depth (including=101, min=94)
        assert_eq!(uncles.len(), 1);
        assert_eq!(uncles[0].number, 94);
    }

    #[test]
    fn max_uncles_limit() {
        let mut pool = UnclePool::new();

        pool.add_candidate(make_header(100, 1000), make_hash(1));
        pool.add_candidate(make_header(100, 2000), make_hash(2));
        pool.add_candidate(make_header(100, 3000), make_hash(3));

        let uncles = pool.get_best_uncles(100);
        assert_eq!(uncles.len(), 2); // MAX_UNCLES = 2
    }

    #[test]
    fn no_duplicate_adds() {
        let mut pool = UnclePool::new();

        pool.add_candidate(make_header(100, 1000), make_hash(1));
        pool.add_candidate(make_header(100, 1000), make_hash(1));

        assert_eq!(pool.candidates.get(&100).unwrap().len(), 1);
    }

    #[test]
    fn used_not_re_added() {
        let mut pool = UnclePool::new();

        pool.mark_used(&[make_hash(1)], 101);
        pool.add_candidate(make_header(100, 1000), make_hash(1));

        assert!(!pool.candidates.contains_key(&100));
    }
}
