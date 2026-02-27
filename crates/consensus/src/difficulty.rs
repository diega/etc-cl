use alloy_primitives::U256;
use chain::types::{empty_uncle_hash, BlockHeader};
use forks::params::{DIFFICULTY_BOUND_DIVISOR, MIN_DIFFICULTY};
use forks::schedule::{self, Fork};

/// ECIP-1010 constants
const ECIP1010_PAUSE_BLOCK: u64 = 3_000_000;
const ECIP1010_LENGTH: u64 = 2_000_000;
const ECIP1010_CONTINUE_BLOCK: u64 = ECIP1010_PAUSE_BLOCK + ECIP1010_LENGTH; // 5,000,000
/// ECIP-1041: difficulty bomb removal block
const ECIP1041_BLOCK: u64 = 5_900_000;
/// Exponential difficulty period (100,000 blocks per period)
const EXP_DIFF_PERIOD: u64 = 100_000;

/// Calculate the expected difficulty of a block given its parent.
///
/// ETC difficulty algorithm:
///
/// For Atlantis+ (EIP-100):
///   Y = 2 if parent has uncles, 1 otherwise
///   diff = parent.diff + parent.diff / 2048 * max(Y - (timestamp - parent.timestamp) / 9, -99)
///
/// For Homestead+:
///   diff = parent.diff + parent.diff / 2048 * max(1 - (timestamp - parent.timestamp) / 10, -99)
///
/// For Frontier:
///   diff = parent.diff + parent.diff / 2048 * (1 if timestamp - parent.timestamp < 13 else -1)
///
/// Bomb component (blocks < ECIP-1041 / 5,900,000):
///   diff += 2^(floor(period_ref / 100000) - 2)
///
/// ECIP-1010 (blocks >= 3,000,000):
///   If block < 5,000,000: period_ref = 3,000,000 (frozen)
///   If block >= 5,000,000: period_ref = block - 2,000,000 (delayed)
///
/// ECIP-1041 (blocks >= 5,900,000): no bomb
pub fn calculate_difficulty(parent: &BlockHeader, timestamp: u64) -> U256 {
    let min_diff = U256::from(MIN_DIFFICULTY);

    // Genesis block or block 0 has no parent.
    if parent.number == 0 && parent.difficulty.is_zero() {
        return min_diff;
    }

    let parent_diff = parent.difficulty;
    let bound_divisor = U256::from(DIFFICULTY_BOUND_DIVISOR);
    let adjustment = parent_diff / bound_divisor;

    let block_number = parent.number + 1;

    let sigma = if schedule::is_active(Fork::Atlantis, block_number) {
        // EIP-100: Atlantis (Byzantium) difficulty adjustment
        let time_diff = timestamp.saturating_sub(parent.timestamp);
        let x = (time_diff / 9) as i64;
        let y = if parent.uncle_hash == empty_uncle_hash() {
            1i64
        } else {
            2i64
        };
        (y - x).max(-99)
    } else if schedule::is_active(Fork::Homestead, block_number) {
        // Homestead algorithm
        let time_diff = timestamp.saturating_sub(parent.timestamp);
        let x = (time_diff / 10) as i64;
        let sigma = 1i64 - x;
        sigma.max(-99)
    } else {
        // Frontier algorithm
        let time_diff = timestamp.saturating_sub(parent.timestamp);
        if time_diff < 13 {
            1i64
        } else {
            -1i64
        }
    };

    let mut diff = if sigma >= 0 {
        parent_diff + adjustment * U256::from(sigma as u64)
    } else {
        let sub = adjustment * U256::from((-sigma) as u64);
        if parent_diff > sub + min_diff {
            parent_diff - sub
        } else {
            min_diff
        }
    };

    diff = diff.max(min_diff);

    // Difficulty bomb (removed at ECIP-1041, block 5,900,000)
    if block_number < ECIP1041_BLOCK {
        // Determine the period reference for the bomb
        let period_ref = if block_number >= ECIP1010_PAUSE_BLOCK {
            // ECIP-1010: pause/delay the bomb
            if block_number < ECIP1010_CONTINUE_BLOCK {
                // Frozen at pause block
                ECIP1010_PAUSE_BLOCK
            } else {
                // Resumed with delay
                block_number - ECIP1010_LENGTH
            }
        } else {
            // Pre-ECIP-1010: normal bomb
            block_number
        };

        let period_count = period_ref / EXP_DIFF_PERIOD;
        if period_count > 1 {
            let bomb = U256::from(1u64) << (period_count as usize - 2);
            diff += bomb;
        }
    }

    diff
}

/// Validate that a block's difficulty matches the expected value.
pub fn validate_difficulty(
    header: &BlockHeader,
    parent: &BlockHeader,
) -> Result<(), DifficultyError> {
    let expected = calculate_difficulty(parent, header.timestamp);
    if header.difficulty != expected {
        return Err(DifficultyError::Mismatch {
            expected,
            actual: header.difficulty,
            block_number: header.number,
        });
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum DifficultyError {
    #[error("difficulty mismatch at block {block_number}: expected {expected}, got {actual}")]
    Mismatch {
        expected: U256,
        actual: U256,
        block_number: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256};

    fn make_header(number: u64, timestamp: u64, difficulty: u64) -> BlockHeader {
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
            timestamp,
            extra_data: vec![],
            mix_hash: B256::ZERO,
            nonce: [0u8; 8],
            base_fee: None,
        }
    }

    #[test]
    fn difficulty_increases_when_block_is_fast() {
        // Parent at t=1000, child at t=1005 (5 sec, faster than target).
        // Block 1,200,001: period = 12, bomb = 2^(12-2) = 1024
        let parent = make_header(1_200_000, 1000, 1_000_000);
        let diff = calculate_difficulty(&parent, 1005);
        // sigma = 1 - (5/10) = 1
        // base = 1_000_000 + 488 = 1_000_488
        // bomb = 2^(12-2) = 1024
        assert_eq!(diff, U256::from(1_000_488u64 + 1024));
    }

    #[test]
    fn difficulty_decreases_when_block_is_slow() {
        // Parent at t=1000, child at t=1030 (30 sec, slower than target).
        let parent = make_header(1_200_000, 1000, 1_000_000);
        let diff = calculate_difficulty(&parent, 1030);
        // sigma = 1 - 3 = -2
        // base = 1_000_000 - 976 = 999_024
        // bomb = 2^(12-2) = 1024
        assert_eq!(diff, U256::from(999_024u64 + 1024));
    }

    #[test]
    fn difficulty_never_below_minimum() {
        let parent = make_header(1_200_000, 1000, MIN_DIFFICULTY);
        let diff = calculate_difficulty(&parent, 2000);
        // base = MIN_DIFFICULTY (clamped), bomb = 1024
        assert_eq!(diff, U256::from(MIN_DIFFICULTY + 1024));
    }

    #[test]
    fn frontier_difficulty_increase() {
        // Before Homestead (block < 1_150_000), use Frontier algo.
        // Block 101: period = 1, bomb = 0 (period < 2)
        let parent = make_header(100, 1000, 1_000_000);
        // Block time < 13 -> sigma = 1
        let diff = calculate_difficulty(&parent, 1010);
        assert_eq!(diff, U256::from(1_000_488u64));
    }

    #[test]
    fn frontier_difficulty_decrease() {
        let parent = make_header(100, 1000, 1_000_000);
        // Block time >= 13 -> sigma = -1, period 1 < 2 so no bomb
        let diff = calculate_difficulty(&parent, 1013);
        assert_eq!(diff, U256::from(999_512u64));
    }

    #[test]
    fn frontier_bomb_active() {
        // Block 200,001: period = 2, bomb = 2^(2-2) = 1
        let parent = make_header(200_000, 1000, 1_000_000);
        let diff = calculate_difficulty(&parent, 1010);
        // Frontier: time_diff=10 < 13 → sigma=1, base = 1_000_488, bomb = 1
        assert_eq!(diff, U256::from(1_000_489u64));
    }

    #[test]
    fn sigma_capped_at_minus_99() {
        // Very slow block (1000 seconds).
        let parent = make_header(1_200_000, 1000, 10_000_000);
        let diff = calculate_difficulty(&parent, 2000);
        // sigma = 1 - 100 = -99 (capped)
        // base = 10_000_000 - 10_000_000/2048 * 99 = 9_516_602
        // bomb = 2^(12-2) = 1024
        let base = U256::from(10_000_000u64)
            - U256::from(10_000_000u64) / U256::from(2048u64) * U256::from(99u64);
        assert_eq!(diff, base + U256::from(1024u64));
    }

    #[test]
    fn ecip1010_bomb_frozen() {
        // Block 3,500,001: ECIP-1010 active, bomb frozen at period_ref = 3M
        // period = 3_000_000 / 100_000 = 30, bomb = 2^(30-2) = 2^28
        let parent = make_header(3_500_000, 1000, 10_000_000_000);
        let diff = calculate_difficulty(&parent, 1015);
        // Homestead: sigma = 1 - 1 = 0, so base = parent_diff
        let bomb = U256::from(1u64) << 28;
        assert_eq!(diff, U256::from(10_000_000_000u64) + bomb);
    }

    #[test]
    fn ecip1041_no_bomb() {
        // Block >= 5,900,000: ECIP-1041, no bomb
        let parent = make_header(5_900_000, 1000, 10_000_000);
        let diff = calculate_difficulty(&parent, 1015);
        // Homestead: sigma = 1 - 1 = 0, base = parent_diff, NO bomb
        assert_eq!(diff, U256::from(10_000_000u64));
    }

    fn make_header_with_uncles(
        number: u64,
        timestamp: u64,
        difficulty: u64,
        has_uncles: bool,
    ) -> BlockHeader {
        let mut header = make_header(number, timestamp, difficulty);
        if has_uncles {
            // Set uncle_hash to something other than empty to indicate uncles present
            header.uncle_hash = B256::from([0xAA; 32]);
        }
        header
    }

    #[test]
    fn eip100_no_uncles_fast_block() {
        // Atlantis+ block, no uncles, fast block (5 sec)
        // Y=1, sigma = max(1 - 5/9, -99) = max(1 - 0, -99) = 1
        let parent = make_header(8_772_000, 1000, 10_000_000);
        let diff = calculate_difficulty(&parent, 1005);
        // adjustment = 10_000_000 / 2048 = 4882
        // diff = 10_000_000 + 4882 * 1 = 10_004_882
        assert_eq!(diff, U256::from(10_004_882u64));
    }

    #[test]
    fn eip100_no_uncles_slow_block() {
        // Atlantis+ block, no uncles, slow block (20 sec)
        // Y=1, sigma = max(1 - 20/9, -99) = max(1 - 2, -99) = -1
        let parent = make_header(8_772_000, 1000, 10_000_000);
        let diff = calculate_difficulty(&parent, 1020);
        // diff = 10_000_000 - 4882 * 1 = 9_995_118
        assert_eq!(diff, U256::from(9_995_118u64));
    }

    #[test]
    fn eip100_with_uncles_fast_block() {
        // Atlantis+ block, WITH uncles, fast block (5 sec)
        // Y=2, sigma = max(2 - 5/9, -99) = max(2 - 0, -99) = 2
        let parent = make_header_with_uncles(8_772_000, 1000, 10_000_000, true);
        let diff = calculate_difficulty(&parent, 1005);
        // diff = 10_000_000 + 4882 * 2 = 10_009_764
        assert_eq!(diff, U256::from(10_009_764u64));
    }

    #[test]
    fn eip100_with_uncles_medium_block() {
        // Atlantis+ block, WITH uncles, medium block (15 sec)
        // Y=2, sigma = max(2 - 15/9, -99) = max(2 - 1, -99) = 1
        let parent = make_header_with_uncles(8_772_000, 1000, 10_000_000, true);
        let diff = calculate_difficulty(&parent, 1015);
        // diff = 10_000_000 + 4882 * 1 = 10_004_882
        assert_eq!(diff, U256::from(10_004_882u64));
    }

    #[test]
    fn eip100_with_uncles_slow_block() {
        // Atlantis+ block, WITH uncles, slow block (30 sec)
        // Y=2, sigma = max(2 - 30/9, -99) = max(2 - 3, -99) = -1
        let parent = make_header_with_uncles(8_772_000, 1000, 10_000_000, true);
        let diff = calculate_difficulty(&parent, 1030);
        // diff = 10_000_000 - 4882 * 1 = 9_995_118
        assert_eq!(diff, U256::from(9_995_118u64));
    }

    #[test]
    fn eip100_sigma_capped_at_minus_99() {
        // Very slow block (1000 sec), Atlantis+
        // Y=1, sigma = max(1 - 1000/9, -99) = -99
        let parent = make_header(8_772_000, 1000, 10_000_000);
        let diff = calculate_difficulty(&parent, 2000);
        let base = U256::from(10_000_000u64)
            - U256::from(10_000_000u64) / U256::from(2048u64) * U256::from(99u64);
        assert_eq!(diff, base);
    }
}
