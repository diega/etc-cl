use alloy_primitives::B256;
use chain::types::{compute_uncle_hash, BlockHeader};
use forks::params::{MAX_UNCLES, MAX_UNCLE_DEPTH};
use std::collections::HashSet;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum UncleError {
    #[error("too many uncles: {count} > {max}", max = MAX_UNCLES)]
    TooMany { count: usize },

    #[error("uncle too old: uncle block {uncle_number}, including block {block_number}, depth {depth} > {max}", max = MAX_UNCLE_DEPTH)]
    TooOld {
        uncle_number: u64,
        block_number: u64,
        depth: u64,
    },

    #[error(
        "uncle is from the future: uncle block {uncle_number} >= including block {block_number}"
    )]
    FromFuture {
        uncle_number: u64,
        block_number: u64,
    },

    #[error("duplicate uncle: {hash:?}")]
    Duplicate { hash: B256 },

    #[error("uncle hash mismatch: expected {expected:?}, got {actual:?}")]
    HashMismatch { expected: B256, actual: B256 },
}

/// Validate uncle rules that can be checked without historical state.
///
/// Checks: max count, uncle hash match, depth, future check, intra-block duplicates.
/// Does NOT check against known uncles from previous blocks (requires chain state).
pub fn validate_uncles_basic(
    header: &BlockHeader,
    uncles: &[BlockHeader],
) -> Result<(), UncleError> {
    validate_uncles(header, uncles, &HashSet::new())
}

/// Validate uncles for a block.
///
/// Rules:
/// 1. At most MAX_UNCLES (2) uncles per block.
/// 2. Uncle block number must be < including block number.
/// 3. Uncle depth: block_number - uncle_number <= MAX_UNCLE_DEPTH (7).
/// 4. No duplicate uncles.
/// 5. Uncle hash in header must match computed uncle hash.
pub fn validate_uncles(
    header: &BlockHeader,
    uncles: &[BlockHeader],
    known_uncles: &HashSet<B256>,
) -> Result<(), UncleError> {
    // Rule 1: Max uncles.
    if uncles.len() > MAX_UNCLES {
        return Err(UncleError::TooMany {
            count: uncles.len(),
        });
    }

    // Rule 5: Uncle hash must match.
    let computed_hash = compute_uncle_hash(uncles);
    if computed_hash != header.uncle_hash {
        return Err(UncleError::HashMismatch {
            expected: computed_hash,
            actual: header.uncle_hash,
        });
    }

    let mut seen = HashSet::new();

    for uncle in uncles {
        let uncle_hash = uncle.hash();

        // Rule 2: Uncle must be older than the including block.
        if uncle.number >= header.number {
            return Err(UncleError::FromFuture {
                uncle_number: uncle.number,
                block_number: header.number,
            });
        }

        // Rule 3: Uncle depth.
        let depth = header.number - uncle.number;
        if depth > MAX_UNCLE_DEPTH {
            return Err(UncleError::TooOld {
                uncle_number: uncle.number,
                block_number: header.number,
                depth,
            });
        }

        // Rule 4: No duplicates.
        if !seen.insert(uncle_hash) {
            return Err(UncleError::Duplicate { hash: uncle_hash });
        }

        // Check against already known uncles (from previous blocks).
        if known_uncles.contains(&uncle_hash) {
            return Err(UncleError::Duplicate { hash: uncle_hash });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, U256};
    use chain::types::empty_uncle_hash;

    fn make_header(number: u64, extra: u8) -> BlockHeader {
        BlockHeader {
            parent_hash: B256::ZERO,
            uncle_hash: empty_uncle_hash(),
            coinbase: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: [0u8; 256],
            difficulty: U256::from(1000),
            number,
            gas_limit: 8_000_000,
            gas_used: 0,
            timestamp: 1_000_000 + number * 13,
            extra_data: vec![extra],
            mix_hash: B256::ZERO,
            nonce: [0u8; 8],
            base_fee: None,
        }
    }

    #[test]
    fn valid_no_uncles() {
        let header = make_header(100, 0);
        let result = validate_uncles(&header, &[], &HashSet::new());
        assert!(result.is_ok());
    }

    #[test]
    fn valid_one_uncle() {
        let uncle = make_header(99, 1);
        let uncle_hash = compute_uncle_hash(std::slice::from_ref(&uncle));

        let mut header = make_header(100, 0);
        header.uncle_hash = uncle_hash;

        let result = validate_uncles(&header, &[uncle], &HashSet::new());
        assert!(result.is_ok());
    }

    #[test]
    fn too_many_uncles() {
        let u1 = make_header(99, 1);
        let u2 = make_header(98, 2);
        let u3 = make_header(97, 3);
        let uncle_hash = compute_uncle_hash(&[u1.clone(), u2.clone(), u3.clone()]);

        let mut header = make_header(100, 0);
        header.uncle_hash = uncle_hash;

        let result = validate_uncles(&header, &[u1, u2, u3], &HashSet::new());
        assert!(matches!(result, Err(UncleError::TooMany { .. })));
    }

    #[test]
    fn uncle_too_old() {
        let uncle = make_header(92, 1); // depth = 100 - 92 = 8 > 7
        let uncle_hash = compute_uncle_hash(std::slice::from_ref(&uncle));

        let mut header = make_header(100, 0);
        header.uncle_hash = uncle_hash;

        let result = validate_uncles(&header, &[uncle], &HashSet::new());
        assert!(matches!(result, Err(UncleError::TooOld { .. })));
    }

    #[test]
    fn uncle_from_future() {
        let uncle = make_header(101, 1);
        let uncle_hash = compute_uncle_hash(std::slice::from_ref(&uncle));

        let mut header = make_header(100, 0);
        header.uncle_hash = uncle_hash;

        let result = validate_uncles(&header, &[uncle], &HashSet::new());
        assert!(matches!(result, Err(UncleError::FromFuture { .. })));
    }

    #[test]
    fn duplicate_uncle() {
        let uncle = make_header(99, 1);
        let uncle_hash = compute_uncle_hash(&[uncle.clone(), uncle.clone()]);

        let mut header = make_header(100, 0);
        header.uncle_hash = uncle_hash;

        let result = validate_uncles(&header, &[uncle.clone(), uncle], &HashSet::new());
        assert!(matches!(result, Err(UncleError::Duplicate { .. })));
    }

    #[test]
    fn uncle_hash_mismatch() {
        let uncle = make_header(99, 1);
        // Header has empty uncle hash but we pass an uncle.
        let header = make_header(100, 0);

        let result = validate_uncles(&header, &[uncle], &HashSet::new());
        assert!(matches!(result, Err(UncleError::HashMismatch { .. })));
    }
}
