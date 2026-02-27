use alloy_primitives::{Address, B256, U256};
use sha3::{Digest, Keccak256};

use chain::types::{BlockHeader, BlockNonce, Bloom};
use devp2p::rlp::{self, RlpItem};

#[derive(Debug)]
pub enum DecodeError {
    Rlp(String),
    FieldCount {
        expected_min: usize,
        got: usize,
    },
    InvalidLength {
        field: &'static str,
        expected: usize,
        got: usize,
    },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Rlp(s) => write!(f, "RLP decode error: {}", s),
            DecodeError::FieldCount { expected_min, got } => {
                write!(f, "expected at least {} fields, got {}", expected_min, got)
            }
            DecodeError::InvalidLength {
                field,
                expected,
                got,
            } => {
                write!(f, "{}: expected {} bytes, got {}", field, expected, got)
            }
        }
    }
}

impl std::error::Error for DecodeError {}

impl From<devp2p::error::Error> for DecodeError {
    fn from(e: devp2p::error::Error) -> Self {
        DecodeError::Rlp(e.to_string())
    }
}

/// Consume the next item from an RLP iterator, returning a DecodeError if exhausted.
fn next_field(iter: &mut impl Iterator<Item = RlpItem>) -> Result<RlpItem, DecodeError> {
    iter.next()
        .ok_or(DecodeError::Rlp("unexpected end of RLP fields".to_string()))
}

fn to_bytes(item: RlpItem) -> Result<Vec<u8>, DecodeError> {
    item.into_bytes()
        .map_err(|e| DecodeError::Rlp(e.to_string()))
}

fn to_b256(item: RlpItem, field: &'static str) -> Result<B256, DecodeError> {
    let bytes = to_bytes(item)?;
    if bytes.len() != 32 {
        return Err(DecodeError::InvalidLength {
            field,
            expected: 32,
            got: bytes.len(),
        });
    }
    Ok(B256::from_slice(&bytes))
}

fn to_address(item: RlpItem) -> Result<Address, DecodeError> {
    let bytes = to_bytes(item)?;
    if bytes.len() != 20 {
        return Err(DecodeError::InvalidLength {
            field: "address",
            expected: 20,
            got: bytes.len(),
        });
    }
    Ok(Address::from_slice(&bytes))
}

fn to_bloom(item: RlpItem) -> Result<Bloom, DecodeError> {
    let bytes = to_bytes(item)?;
    if bytes.len() != 256 {
        return Err(DecodeError::InvalidLength {
            field: "bloom",
            expected: 256,
            got: bytes.len(),
        });
    }
    let mut bloom = [0u8; 256];
    bloom.copy_from_slice(&bytes);
    Ok(bloom)
}

fn to_u256(item: RlpItem) -> Result<U256, DecodeError> {
    let bytes = to_bytes(item)?;
    if bytes.is_empty() {
        return Ok(U256::ZERO);
    }
    if bytes.len() > 32 {
        return Err(DecodeError::InvalidLength {
            field: "u256",
            expected: 32,
            got: bytes.len(),
        });
    }
    // big-endian bytes, pad to 32
    let mut buf = [0u8; 32];
    let offset = 32 - bytes.len();
    buf[offset..].copy_from_slice(&bytes);
    Ok(U256::from_be_bytes(buf))
}

fn to_u64(item: RlpItem) -> Result<u64, DecodeError> {
    let bytes = to_bytes(item)?;
    Ok(devp2p::bytes::decode_u64(&bytes))
}

fn to_nonce(item: RlpItem) -> Result<BlockNonce, DecodeError> {
    let bytes = to_bytes(item)?;
    if bytes.len() != 8 {
        return Err(DecodeError::InvalidLength {
            field: "nonce",
            expected: 8,
            got: bytes.len(),
        });
    }
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&bytes);
    Ok(nonce)
}

/// Decode a block header from raw RLP bytes.
pub fn decode_block_header(data: &[u8]) -> Result<BlockHeader, DecodeError> {
    let item = rlp::decode(data)?;
    let fields = item
        .into_list()
        .map_err(|e| DecodeError::Rlp(e.to_string()))?;

    // Pre-London: 15 fields, Post-London: 16 fields (with base_fee)
    if fields.len() < 15 {
        return Err(DecodeError::FieldCount {
            expected_min: 15,
            got: fields.len(),
        });
    }

    let mut iter = fields.into_iter();

    let parent_hash = to_b256(next_field(&mut iter)?, "parent_hash")?;
    let uncle_hash = to_b256(next_field(&mut iter)?, "uncle_hash")?;
    let coinbase = to_address(next_field(&mut iter)?)?;
    let state_root = to_b256(next_field(&mut iter)?, "state_root")?;
    let transactions_root = to_b256(next_field(&mut iter)?, "transactions_root")?;
    let receipts_root = to_b256(next_field(&mut iter)?, "receipts_root")?;
    let logs_bloom = to_bloom(next_field(&mut iter)?)?;
    let difficulty = to_u256(next_field(&mut iter)?)?;
    let number = to_u64(next_field(&mut iter)?)?;
    let gas_limit = to_u64(next_field(&mut iter)?)?;
    let gas_used = to_u64(next_field(&mut iter)?)?;
    let timestamp = to_u64(next_field(&mut iter)?)?;
    let extra_data = to_bytes(next_field(&mut iter)?)?;
    let mix_hash = to_b256(next_field(&mut iter)?, "mix_hash")?;
    let nonce = to_nonce(next_field(&mut iter)?)?;

    let base_fee = if let Some(item) = iter.next() {
        Some(to_u256(item)?)
    } else {
        None
    };

    Ok(BlockHeader {
        parent_hash,
        uncle_hash,
        coinbase,
        state_root,
        transactions_root,
        receipts_root,
        logs_bloom,
        difficulty,
        number,
        gas_limit,
        gas_used,
        timestamp,
        extra_data,
        mix_hash,
        nonce,
        base_fee,
    })
}

/// Decoded block body: transactions (raw RLP) and uncle headers.
pub struct DecodedBody {
    pub transactions: Vec<Vec<u8>>,
    pub uncles: Vec<BlockHeader>,
}

/// Decode a block body from raw RLP bytes.
/// Body = [transactions_list, uncles_list]
pub fn decode_block_body(data: &[u8]) -> Result<DecodedBody, DecodeError> {
    let item = rlp::decode(data)?;
    let fields = item
        .into_list()
        .map_err(|e| DecodeError::Rlp(e.to_string()))?;

    if fields.len() < 2 {
        return Err(DecodeError::FieldCount {
            expected_min: 2,
            got: fields.len(),
        });
    }

    let mut iter = fields.into_iter();

    // Transactions: keep as raw RLP bytes for each tx
    let txs_list = next_field(&mut iter)?
        .into_list()
        .map_err(|e| DecodeError::Rlp(e.to_string()))?;
    let transactions: Vec<Vec<u8>> = txs_list.into_iter().map(|item| item.encode()).collect();

    // Uncles: decode each as BlockHeader
    let uncles_list = next_field(&mut iter)?
        .into_list()
        .map_err(|e| DecodeError::Rlp(e.to_string()))?;
    let mut uncles = Vec::with_capacity(uncles_list.len());
    for uncle_item in uncles_list {
        let uncle_rlp = uncle_item.encode();
        uncles.push(decode_block_header(&uncle_rlp)?);
    }

    Ok(DecodedBody {
        transactions,
        uncles,
    })
}

/// Decoded NewBlock message contents.
pub struct DecodedNewBlock {
    pub header: BlockHeader,
    pub header_rlp: Vec<u8>,
    pub transactions: Vec<Vec<u8>>,
    pub uncles: Vec<BlockHeader>,
    pub td: U256,
}

/// Decode a NewBlock broadcast message from snappy-compressed payload.
/// Wire format: snappy([[header, [tx1, tx2, ...], [uncle1, ...]], td])
pub fn decode_new_block(compressed: &[u8]) -> Result<DecodedNewBlock, DecodeError> {
    let decompressed = snap::raw::Decoder::new()
        .decompress_vec(compressed)
        .map_err(|e| DecodeError::Rlp(format!("snappy decompress: {}", e)))?;

    let item = rlp::decode(&decompressed)?;
    let outer = item
        .into_list()
        .map_err(|e| DecodeError::Rlp(e.to_string()))?;
    if outer.len() < 2 {
        return Err(DecodeError::FieldCount {
            expected_min: 2,
            got: outer.len(),
        });
    }

    let mut outer_iter = outer.into_iter();

    // First element: block = [header, txs, uncles]
    let block_item = next_field(&mut outer_iter)?;
    let block_fields = block_item
        .into_list()
        .map_err(|e| DecodeError::Rlp(e.to_string()))?;
    if block_fields.len() < 3 {
        return Err(DecodeError::FieldCount {
            expected_min: 3,
            got: block_fields.len(),
        });
    }

    let mut block_iter = block_fields.into_iter();

    // Header: encode back to RLP for hashing, then decode
    let header_item = next_field(&mut block_iter)?;
    let header_rlp = header_item.encode();
    let header = decode_block_header(&header_rlp)?;

    // Transactions: keep as raw RLP
    let txs_list = next_field(&mut block_iter)?
        .into_list()
        .map_err(|e| DecodeError::Rlp(e.to_string()))?;
    let transactions: Vec<Vec<u8>> = txs_list.into_iter().map(|item| item.encode()).collect();

    // Uncles
    let uncles_list = next_field(&mut block_iter)?
        .into_list()
        .map_err(|e| DecodeError::Rlp(e.to_string()))?;
    let mut uncles = Vec::with_capacity(uncles_list.len());
    for uncle_item in uncles_list {
        let uncle_rlp = uncle_item.encode();
        uncles.push(decode_block_header(&uncle_rlp)?);
    }

    // Second element: TD
    let td = to_u256(next_field(&mut outer_iter)?)?;

    Ok(DecodedNewBlock {
        header,
        header_rlp,
        transactions,
        uncles,
        td,
    })
}

/// Decode a NewBlockHashes broadcast message from snappy-compressed payload.
/// Wire format: snappy([[hash1, number1], [hash2, number2], ...])
pub fn decode_new_block_hashes(compressed: &[u8]) -> Result<Vec<(B256, u64)>, DecodeError> {
    let decompressed = snap::raw::Decoder::new()
        .decompress_vec(compressed)
        .map_err(|e| DecodeError::Rlp(format!("snappy decompress: {}", e)))?;

    let item = rlp::decode(&decompressed)?;
    let entries = item
        .into_list()
        .map_err(|e| DecodeError::Rlp(e.to_string()))?;

    let mut result = Vec::with_capacity(entries.len());
    for entry in entries {
        let fields = entry
            .into_list()
            .map_err(|e| DecodeError::Rlp(e.to_string()))?;
        if fields.len() < 2 {
            return Err(DecodeError::FieldCount {
                expected_min: 2,
                got: fields.len(),
            });
        }
        let mut iter = fields.into_iter();
        let hash = to_b256(next_field(&mut iter)?, "block_hash")?;
        let number = to_u64(next_field(&mut iter)?)?;
        result.push((hash, number));
    }

    Ok(result)
}

/// Compute keccak256 hash of raw RLP header bytes.
pub fn hash_raw_header(raw_rlp: &[u8]) -> B256 {
    B256::from_slice(&Keccak256::digest(raw_rlp))
}

/// Convert decoded header + body into an ExecutionPayload for the Engine API.
///
/// Mining rewards are NOT included — the EL computes them internally via
/// ethash's accumulateRewards during block processing.
pub fn block_to_payload_with_hash(
    header: &BlockHeader,
    block_hash: B256,
    uncles: &[BlockHeader],
    transactions: &[Vec<u8>],
) -> engine_api::types::ExecutionPayload {
    let mut payload = engine_api::bridge::block_to_payload(header, uncles, transactions.to_vec());
    payload.block_hash = block_hash;
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain::types::{compute_uncle_hash, empty_uncle_hash};

    #[test]
    fn decode_header_roundtrip() {
        // Create a header, RLP-encode it, then decode and verify
        let header = BlockHeader {
            parent_hash: B256::ZERO,
            uncle_hash: empty_uncle_hash(),
            coinbase: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: [0u8; 256],
            difficulty: U256::from(131072u64),
            number: 1,
            gas_limit: 8_000_000,
            gas_used: 21000,
            timestamp: 1_438_270_000,
            extra_data: b"test".to_vec(),
            mix_hash: B256::ZERO,
            nonce: [0, 0, 0, 0, 0, 0, 0, 42],
            base_fee: None,
        };

        let rlp = header.rlp_encode();
        let decoded = decode_block_header(&rlp).unwrap();

        assert_eq!(decoded.parent_hash, header.parent_hash);
        assert_eq!(decoded.uncle_hash, header.uncle_hash);
        assert_eq!(decoded.coinbase, header.coinbase);
        assert_eq!(decoded.difficulty, header.difficulty);
        assert_eq!(decoded.number, header.number);
        assert_eq!(decoded.gas_limit, header.gas_limit);
        assert_eq!(decoded.gas_used, header.gas_used);
        assert_eq!(decoded.timestamp, header.timestamp);
        assert_eq!(decoded.extra_data, header.extra_data);
        assert_eq!(decoded.nonce, header.nonce);
        assert_eq!(decoded.base_fee, None);
    }

    #[test]
    fn decode_header_with_base_fee() {
        let header = BlockHeader {
            parent_hash: B256::ZERO,
            uncle_hash: empty_uncle_hash(),
            coinbase: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: [0u8; 256],
            difficulty: U256::from(1000u64),
            number: 100,
            gas_limit: 8_000_000,
            gas_used: 0,
            timestamp: 1_000_000,
            extra_data: vec![],
            mix_hash: B256::ZERO,
            nonce: [0u8; 8],
            base_fee: Some(U256::from(7u64)),
        };

        let rlp = header.rlp_encode();
        let decoded = decode_block_header(&rlp).unwrap();
        assert_eq!(decoded.base_fee, Some(U256::from(7u64)));
    }

    #[test]
    fn hash_raw_header_matches() {
        let header = BlockHeader {
            parent_hash: B256::ZERO,
            uncle_hash: empty_uncle_hash(),
            coinbase: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: [0u8; 256],
            difficulty: U256::from(1u64),
            number: 0,
            gas_limit: 5000,
            gas_used: 0,
            timestamp: 0,
            extra_data: vec![],
            mix_hash: B256::ZERO,
            nonce: [0u8; 8],
            base_fee: None,
        };

        let rlp = header.rlp_encode();
        assert_eq!(hash_raw_header(&rlp), header.hash());
    }

    #[test]
    fn decode_empty_body() {
        // Body = [[txs], [uncles]] — both empty lists
        let body = RlpItem::List(vec![RlpItem::List(vec![]), RlpItem::List(vec![])]);
        let encoded = body.encode();
        let decoded = decode_block_body(&encoded).unwrap();
        assert!(decoded.transactions.is_empty());
        assert!(decoded.uncles.is_empty());
    }

    #[test]
    fn uncle_hash_validation() {
        let uncle = BlockHeader {
            parent_hash: B256::ZERO,
            uncle_hash: empty_uncle_hash(),
            coinbase: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: [0u8; 256],
            difficulty: U256::from(1000u64),
            number: 5,
            gas_limit: 8_000_000,
            gas_used: 0,
            timestamp: 1_000_000,
            extra_data: vec![],
            mix_hash: B256::ZERO,
            nonce: [0u8; 8],
            base_fee: None,
        };

        let computed = compute_uncle_hash(&[uncle]);
        assert_ne!(computed, empty_uncle_hash());
    }
}
