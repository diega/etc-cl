use alloy_primitives::{B256, U256};
use std::collections::VecDeque;
use tracing::info;

/// Safe block depth (head - N). Set to 24 because ETC mainnet has seen
/// reorgs of 11+ blocks; 24 gives comfortable margin.
const SAFE_DEPTH: u64 = 24;
/// Finalized block depth (head - N).
const FINALIZED_DEPTH: u64 = 400;
/// Maximum number of entries in the ring buffer. Must be ≥ FINALIZED_DEPTH.
const RING_BUFFER_CAP: usize = 512;

/// Fork choice state for Engine API communication.
#[derive(Debug, Clone)]
pub struct ForkChoiceState {
    pub head: B256,
    pub safe: B256,
    pub finalized: B256,
}

/// In-memory chain tracker. Replaces the persistent ChainManager.
///
/// Tracks head hash/number/TD and a ring buffer of recent canonical blocks
/// for computing safe/finalized in fork choice updates.
pub struct ChainTracker {
    head_hash: Option<B256>,
    head_td: U256,
    head_number: u64,
    /// Recent canonical entries: (number, hash). Newest at back.
    recent_canonical: VecDeque<(u64, B256)>,
}

impl Default for ChainTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ChainTracker {
    /// Create a new empty tracker.
    pub fn new() -> Self {
        Self {
            head_hash: None,
            head_td: U256::ZERO,
            head_number: 0,
            recent_canonical: VecDeque::with_capacity(RING_BUFFER_CAP),
        }
    }

    /// Seed initial state from EL (replaces insert_genesis + fast-forward).
    pub fn init_from_el(&mut self, hash: B256, number: u64, td: U256) {
        self.head_hash = Some(hash);
        self.head_number = number;
        self.head_td = td;
        self.recent_canonical.clear();
        self.push_canonical(number, hash);
        info!(number, hash = %hash, td = %td, "chain tracker initialized from EL");
    }

    /// Update head + push to ring buffer. `td=None` preserves previous TD.
    pub fn set_head(&mut self, hash: B256, number: u64, td: Option<U256>) {
        self.head_hash = Some(hash);
        self.head_number = number;
        if let Some(td) = td {
            self.head_td = td;
        }
        self.push_canonical(number, hash);
    }

    /// Advance head sequentially (used during pipeline drain).
    pub fn advance_head(&mut self, hash: B256, number: u64, td: U256) {
        self.head_hash = Some(hash);
        self.head_number = number;
        self.head_td = td;
        self.push_canonical(number, hash);
    }

    /// Get current head hash.
    pub fn head_hash(&self) -> Option<B256> {
        self.head_hash
    }

    /// Get current head TD.
    pub fn head_td(&self) -> U256 {
        self.head_td
    }

    /// Get current head number.
    pub fn head_number(&self) -> u64 {
        self.head_number
    }

    /// Compute fork choice state from ring buffer.
    ///
    /// Safe = head - SAFE_DEPTH, finalized = head - FINALIZED_DEPTH.
    /// If not enough history (e.g. first ~100 blocks post-restart), uses B256::ZERO.
    pub fn fork_choice_state(&self) -> ForkChoiceState {
        let head = self.head_hash.unwrap_or(B256::ZERO);

        let safe_number = self.head_number.checked_sub(SAFE_DEPTH);
        let finalized_number = self.head_number.checked_sub(FINALIZED_DEPTH);

        let safe = safe_number
            .and_then(|n| self.lookup_canonical(n))
            .unwrap_or(B256::ZERO);

        let finalized = finalized_number
            .and_then(|n| self.lookup_canonical(n))
            .unwrap_or(B256::ZERO);

        ForkChoiceState {
            head,
            safe,
            finalized,
        }
    }

    /// Insert an entry into the ring buffer, evicting oldest if full.
    pub fn push_canonical(&mut self, number: u64, hash: B256) {
        // Avoid duplicate consecutive entries for the same number.
        if let Some(&(last_num, _)) = self.recent_canonical.back() {
            if last_num == number {
                // Replace in-place (e.g. reorg at same height).
                *self.recent_canonical.back_mut().unwrap() = (number, hash);
                return;
            }
        }
        if self.recent_canonical.len() >= RING_BUFFER_CAP {
            self.recent_canonical.pop_front();
        }
        self.recent_canonical.push_back((number, hash));
    }

    /// Lookup a block hash by number in the ring buffer.
    fn lookup_canonical(&self, number: u64) -> Option<B256> {
        self.recent_canonical
            .iter()
            .rev()
            .find(|(n, _)| *n == number)
            .map(|(_, h)| *h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_tracker_is_empty() {
        let t = ChainTracker::new();
        assert_eq!(t.head_hash(), None);
        assert_eq!(t.head_td(), U256::ZERO);
        assert_eq!(t.head_number(), 0);
    }

    #[test]
    fn test_init_from_el() {
        let mut t = ChainTracker::new();
        let hash = B256::from([1u8; 32]);
        t.init_from_el(hash, 100, U256::from(5000));
        assert_eq!(t.head_hash(), Some(hash));
        assert_eq!(t.head_number(), 100);
        assert_eq!(t.head_td(), U256::from(5000));
    }

    #[test]
    fn test_advance_head() {
        let mut t = ChainTracker::new();
        let h0 = B256::from([0u8; 32]);
        t.init_from_el(h0, 0, U256::from(1000));

        let h1 = B256::from([1u8; 32]);
        t.advance_head(h1, 1, U256::from(2000));
        assert_eq!(t.head_hash(), Some(h1));
        assert_eq!(t.head_number(), 1);
        assert_eq!(t.head_td(), U256::from(2000));
    }

    #[test]
    fn test_set_head_preserves_td_when_none() {
        let mut t = ChainTracker::new();
        let h0 = B256::from([0u8; 32]);
        t.init_from_el(h0, 0, U256::from(1000));

        let h1 = B256::from([1u8; 32]);
        t.set_head(h1, 1, None);
        assert_eq!(t.head_td(), U256::from(1000)); // preserved
        assert_eq!(t.head_hash(), Some(h1));
    }

    #[test]
    fn test_fork_choice_state_with_enough_history() {
        let mut t = ChainTracker::new();
        // Build 500 blocks so we have safe and finalized
        for i in 0..=500u64 {
            let mut hash_bytes = [0u8; 32];
            hash_bytes[0..8].copy_from_slice(&i.to_le_bytes());
            let hash = B256::from(hash_bytes);
            if i == 0 {
                t.init_from_el(hash, i, U256::from(1000));
            } else {
                t.advance_head(hash, i, U256::from(1000 + i));
            }
        }

        let fcs = t.fork_choice_state();
        // head = block 500
        assert_ne!(fcs.head, B256::ZERO);
        // safe = block 476 (500 - 24)
        assert_ne!(fcs.safe, B256::ZERO);
        // finalized = block 100 (500 - 400)
        assert_ne!(fcs.finalized, B256::ZERO);

        // Verify correct safe block number
        let safe_expected = {
            let n = 476u64;
            let mut b = [0u8; 32];
            b[0..8].copy_from_slice(&n.to_le_bytes());
            B256::from(b)
        };
        assert_eq!(fcs.safe, safe_expected);
    }

    #[test]
    fn test_fork_choice_state_not_enough_history() {
        let mut t = ChainTracker::new();
        let h = B256::from([1u8; 32]);
        t.init_from_el(h, 3, U256::from(100));

        let fcs = t.fork_choice_state();
        assert_eq!(fcs.head, h);
        assert_eq!(fcs.safe, B256::ZERO); // 3 < SAFE_DEPTH(24)
        assert_eq!(fcs.finalized, B256::ZERO); // 3 < FINALIZED_DEPTH(400)
    }

    #[test]
    fn test_ring_buffer_wraps_around() {
        let mut t = ChainTracker::new();
        // Push more than RING_BUFFER_CAP (512) entries
        for i in 0..600u64 {
            let mut hash_bytes = [0u8; 32];
            hash_bytes[0..8].copy_from_slice(&i.to_le_bytes());
            let hash = B256::from(hash_bytes);
            if i == 0 {
                t.init_from_el(hash, i, U256::from(100));
            } else {
                t.advance_head(hash, i, U256::from(100 + i));
            }
        }

        // Ring buffer should have exactly RING_BUFFER_CAP entries
        assert_eq!(t.recent_canonical.len(), RING_BUFFER_CAP);

        // Head should be block 599
        assert_eq!(t.head_number(), 599);

        // Safe = 599 - 24 = 575, should still be in buffer
        let fcs = t.fork_choice_state();
        assert_ne!(fcs.safe, B256::ZERO);

        // Finalized = 599 - 400 = 199, should still be in buffer (600-512=88, so 199 > 88)
        assert_ne!(fcs.finalized, B256::ZERO);

        // Block 0 should have been evicted
        assert!(t.lookup_canonical(0).is_none());
    }
}
