use alloy_primitives::U256;
use chain::trie::ordered_trie_root;
use chain::types::{BlockHeader, BlockNonce, Bloom};
use tracing::warn;

use crate::types::{ExecutionPayload, UncleHeader};

/// Convert a PoW Block (header + uncles) to an ExecutionPayload for the Engine API.
///
/// Mining rewards are NOT included — the EL computes them via ethash's
/// accumulateRewards during block processing (Finalize).
pub fn block_to_payload(
    header: &BlockHeader,
    uncles: &[BlockHeader],
    transactions: Vec<Vec<u8>>,
) -> ExecutionPayload {
    let uncle_headers: Option<Vec<UncleHeader>> = if uncles.is_empty() {
        None
    } else {
        Some(uncles.iter().map(block_header_to_uncle_header).collect())
    };

    ExecutionPayload {
        parent_hash: header.parent_hash,
        fee_recipient: header.coinbase,
        state_root: header.state_root,
        receipts_root: header.receipts_root,
        logs_bloom: header.logs_bloom.to_vec(),
        prev_randao: header.mix_hash, // mixHash maps to prevRandao
        block_number: header.number,
        gas_limit: header.gas_limit,
        gas_used: header.gas_used,
        timestamp: header.timestamp,
        extra_data: header.extra_data.clone(),
        base_fee_per_gas: header.base_fee.unwrap_or(U256::ZERO),
        block_hash: header.hash(),
        transactions,
        withdrawals: None,
        difficulty: Some(header.difficulty),
        nonce: Some(header.nonce),
        uncles: uncle_headers,
    }
}

/// Convert an ExecutionPayload back to a BlockHeader.
///
/// Used when receiving payloads from the EL (e.g., after getPayload for mining).
///
/// If the payload carries uncle headers, their hash is computed correctly.
/// Otherwise, the empty-uncles hash is used.
pub fn payload_to_header(payload: &ExecutionPayload) -> BlockHeader {
    let mut logs_bloom: Bloom = [0u8; 256];
    if payload.logs_bloom.len() == 256 {
        logs_bloom.copy_from_slice(&payload.logs_bloom);
    } else if !payload.logs_bloom.is_empty() {
        warn!(
            len = payload.logs_bloom.len(),
            "payload logs_bloom is not 256 bytes, using zeroed bloom"
        );
    }

    let nonce: BlockNonce = payload.nonce.unwrap_or([0u8; 8]);

    // Compute uncle_hash from payload's uncle headers (if present)
    let uncle_hash = match &payload.uncles {
        Some(uncle_headers) if !uncle_headers.is_empty() => {
            let block_headers: Vec<BlockHeader> = uncle_headers
                .iter()
                .map(uncle_header_to_block_header)
                .collect();
            chain::types::compute_uncle_hash(&block_headers)
        }
        _ => chain::types::empty_uncle_hash(),
    };

    BlockHeader {
        parent_hash: payload.parent_hash,
        uncle_hash,
        coinbase: payload.fee_recipient,
        state_root: payload.state_root,
        transactions_root: ordered_trie_root(&payload.transactions),
        receipts_root: payload.receipts_root,
        logs_bloom,
        difficulty: payload.difficulty.unwrap_or(U256::ZERO),
        number: payload.block_number,
        gas_limit: payload.gas_limit,
        gas_used: payload.gas_used,
        timestamp: payload.timestamp,
        extra_data: payload.extra_data.clone(),
        mix_hash: payload.prev_randao, // prevRandao maps to mixHash
        nonce,
        base_fee: if payload.base_fee_per_gas.is_zero() {
            None
        } else {
            Some(payload.base_fee_per_gas)
        },
    }
}

/// Convert a BlockHeader to an UncleHeader for Engine API transport.
pub fn block_header_to_uncle_header(header: &BlockHeader) -> UncleHeader {
    UncleHeader {
        parent_hash: header.parent_hash,
        uncle_hash: header.uncle_hash,
        coinbase: header.coinbase,
        state_root: header.state_root,
        transactions_root: header.transactions_root,
        receipts_root: header.receipts_root,
        logs_bloom: header.logs_bloom.to_vec(),
        difficulty: header.difficulty,
        number: header.number,
        gas_limit: header.gas_limit,
        gas_used: header.gas_used,
        timestamp: header.timestamp,
        extra_data: header.extra_data.clone(),
        mix_digest: header.mix_hash,
        nonce: header.nonce.to_vec(),
        base_fee: header.base_fee,
    }
}

/// Convert an UncleHeader (Engine API transport) back to a BlockHeader.
pub fn uncle_header_to_block_header(uncle: &UncleHeader) -> BlockHeader {
    let mut logs_bloom: [u8; 256] = [0u8; 256];
    if uncle.logs_bloom.len() == 256 {
        logs_bloom.copy_from_slice(&uncle.logs_bloom);
    } else if !uncle.logs_bloom.is_empty() {
        warn!(
            len = uncle.logs_bloom.len(),
            "uncle logs_bloom is not 256 bytes, using zeroed bloom"
        );
    }
    let mut nonce: BlockNonce = [0u8; 8];
    if uncle.nonce.len() == 8 {
        nonce.copy_from_slice(&uncle.nonce);
    } else if !uncle.nonce.is_empty() {
        warn!(
            len = uncle.nonce.len(),
            "uncle nonce is not 8 bytes, using zeroed nonce"
        );
    }
    BlockHeader {
        parent_hash: uncle.parent_hash,
        uncle_hash: uncle.uncle_hash,
        coinbase: uncle.coinbase,
        state_root: uncle.state_root,
        transactions_root: uncle.transactions_root,
        receipts_root: uncle.receipts_root,
        logs_bloom,
        difficulty: uncle.difficulty,
        number: uncle.number,
        gas_limit: uncle.gas_limit,
        gas_used: uncle.gas_used,
        timestamp: uncle.timestamp,
        extra_data: uncle.extra_data.clone(),
        mix_hash: uncle.mix_digest,
        nonce,
        base_fee: uncle.base_fee,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256};
    use chain::types::empty_uncle_hash;

    fn make_header(number: u64, coinbase: Address) -> BlockHeader {
        BlockHeader {
            parent_hash: B256::ZERO,
            uncle_hash: empty_uncle_hash(),
            coinbase,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: [0u8; 256],
            difficulty: U256::from(131072),
            number,
            gas_limit: 8_000_000,
            gas_used: 21_000,
            timestamp: 1_000_000,
            extra_data: vec![],
            mix_hash: B256::ZERO,
            nonce: [0, 0, 0, 0, 0, 0, 0, 42],
            base_fee: Some(U256::from(1000)),
        }
    }

    #[test]
    fn block_to_payload_includes_pow_fields() {
        let miner = {
            let mut bytes = [0u8; 20];
            bytes[19] = 1;
            Address::from_slice(&bytes)
        };
        let header = make_header(100, miner);

        let payload = block_to_payload(&header, &[], vec![]);

        assert_eq!(payload.difficulty, Some(U256::from(131072)));
        assert_eq!(payload.nonce, Some([0, 0, 0, 0, 0, 0, 0, 42]));
        assert_eq!(payload.prev_randao, B256::ZERO); // mixHash
        assert!(payload.withdrawals.is_none());
    }

    #[test]
    fn roundtrip_header_through_payload() {
        let miner = {
            let mut bytes = [0u8; 20];
            bytes[18] = 0xde;
            bytes[19] = 0xad;
            Address::from_slice(&bytes)
        };
        let header = make_header(42, miner);

        let payload = block_to_payload(&header, &[], vec![]);
        let recovered = payload_to_header(&payload);

        assert_eq!(recovered.coinbase, header.coinbase);
        assert_eq!(recovered.number, header.number);
        assert_eq!(recovered.difficulty, header.difficulty);
        assert_eq!(recovered.nonce, header.nonce);
        assert_eq!(recovered.mix_hash, header.mix_hash);
        assert_eq!(recovered.gas_limit, header.gas_limit);
        assert_eq!(recovered.timestamp, header.timestamp);
    }
}
