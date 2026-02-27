use alloy_primitives::{Address, B256, U256};
use sha3::{Digest, Keccak256};

/// 8-byte nonce used in PoW.
pub type BlockNonce = [u8; 8];

/// 256-byte bloom filter.
pub type Bloom = [u8; 256];

/// Block header with all PoW fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub parent_hash: B256,
    pub uncle_hash: B256,
    pub coinbase: Address,
    pub state_root: B256,
    pub transactions_root: B256,
    pub receipts_root: B256,
    pub logs_bloom: Bloom,
    pub difficulty: U256,
    pub number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub mix_hash: B256,
    pub nonce: BlockNonce,
    pub base_fee: Option<U256>,
}

/// Compute the empty uncle hash (keccak256 of RLP-encoded empty list).
pub fn empty_uncle_hash() -> B256 {
    // RLP of empty list = [0xc0]
    B256::from_slice(&Keccak256::digest([0xc0]))
}

impl BlockHeader {
    /// Compute the hash of this header (keccak256 of RLP encoding).
    pub fn hash(&self) -> B256 {
        let rlp = self.rlp_encode();
        B256::from_slice(&Keccak256::digest(&rlp))
    }

    /// RLP-encode the header for hash computation.
    /// Follows the Ethereum header RLP structure exactly.
    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut fields: Vec<Vec<u8>> = Vec::with_capacity(16);

        fields.push(rlp_encode_b256(&self.parent_hash));
        fields.push(rlp_encode_b256(&self.uncle_hash));
        fields.push(rlp_encode_address(&self.coinbase));
        fields.push(rlp_encode_b256(&self.state_root));
        fields.push(rlp_encode_b256(&self.transactions_root));
        fields.push(rlp_encode_b256(&self.receipts_root));
        fields.push(rlp_encode_bytes(&self.logs_bloom));
        fields.push(rlp_encode_u256(&self.difficulty));
        fields.push(rlp_encode_u64(self.number));
        fields.push(rlp_encode_u64(self.gas_limit));
        fields.push(rlp_encode_u64(self.gas_used));
        fields.push(rlp_encode_u64(self.timestamp));
        fields.push(rlp_encode_bytes(&self.extra_data));
        fields.push(rlp_encode_b256(&self.mix_hash));
        fields.push(rlp_encode_bytes(&self.nonce));

        if let Some(ref base_fee) = self.base_fee {
            fields.push(rlp_encode_u256(base_fee));
        }

        rlp_encode_list_from_encoded(&fields)
    }

    /// Compute the seal hash (header hash without mix_hash and nonce) for ethash verification.
    pub fn seal_hash(&self) -> B256 {
        let mut fields: Vec<Vec<u8>> = Vec::with_capacity(14);

        fields.push(rlp_encode_b256(&self.parent_hash));
        fields.push(rlp_encode_b256(&self.uncle_hash));
        fields.push(rlp_encode_address(&self.coinbase));
        fields.push(rlp_encode_b256(&self.state_root));
        fields.push(rlp_encode_b256(&self.transactions_root));
        fields.push(rlp_encode_b256(&self.receipts_root));
        fields.push(rlp_encode_bytes(&self.logs_bloom));
        fields.push(rlp_encode_u256(&self.difficulty));
        fields.push(rlp_encode_u64(self.number));
        fields.push(rlp_encode_u64(self.gas_limit));
        fields.push(rlp_encode_u64(self.gas_used));
        fields.push(rlp_encode_u64(self.timestamp));
        fields.push(rlp_encode_bytes(&self.extra_data));

        if let Some(ref base_fee) = self.base_fee {
            fields.push(rlp_encode_u256(base_fee));
        }

        let rlp = rlp_encode_list_from_encoded(&fields);
        B256::from_slice(&Keccak256::digest(&rlp))
    }
}

// ============================================================================
// RLP encoding helpers (minimal, no external dep)
// ============================================================================

/// RLP-encode a single byte string (already raw bytes).
pub fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        return data.to_vec();
    }
    let mut out = rlp_length_prefix(data.len(), 0x80);
    out.extend_from_slice(data);
    out
}

/// RLP-encode a 32-byte hash.
fn rlp_encode_b256(h: &B256) -> Vec<u8> {
    rlp_encode_bytes(h.as_slice())
}

/// RLP-encode a 20-byte address.
fn rlp_encode_address(h: &Address) -> Vec<u8> {
    rlp_encode_bytes(h.as_slice())
}

/// RLP-encode a U256 as big-endian bytes with no leading zeros.
pub fn rlp_encode_u256(v: &U256) -> Vec<u8> {
    if v.is_zero() {
        return rlp_encode_bytes(&[]);
    }
    let buf = v.to_be_bytes::<32>();
    let start = buf.iter().position(|&b| b != 0).unwrap_or(32);
    rlp_encode_bytes(&buf[start..])
}

/// RLP-encode a u64 as big-endian bytes with no leading zeros.
pub fn rlp_encode_u64(v: u64) -> Vec<u8> {
    if v == 0 {
        return rlp_encode_bytes(&[]);
    }
    let bytes = v.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(8);
    rlp_encode_bytes(&bytes[start..])
}

/// Build an RLP list from already-encoded items.
pub fn rlp_encode_list_from_encoded(items: &[Vec<u8>]) -> Vec<u8> {
    let total_len: usize = items.iter().map(|i| i.len()).sum();
    let mut out = rlp_length_prefix(total_len, 0xc0);
    for item in items {
        out.extend_from_slice(item);
    }
    out
}

/// Compute RLP length prefix for a payload of given length.
fn rlp_length_prefix(len: usize, offset: u8) -> Vec<u8> {
    if len < 56 {
        vec![offset + len as u8]
    } else {
        let len_bytes = to_minimal_be_bytes(len as u64);
        let mut out = vec![offset + 55 + len_bytes.len() as u8];
        out.extend_from_slice(&len_bytes);
        out
    }
}

fn to_minimal_be_bytes(v: u64) -> Vec<u8> {
    let bytes = v.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    bytes[start..].to_vec()
}

/// Compute the uncle hash for a list of uncle headers.
pub fn compute_uncle_hash(uncles: &[BlockHeader]) -> B256 {
    if uncles.is_empty() {
        return empty_uncle_hash();
    }
    let encoded_uncles: Vec<Vec<u8>> = uncles.iter().map(|u| u.rlp_encode()).collect();
    let list = rlp_encode_list_from_encoded(&encoded_uncles);
    B256::from_slice(&Keccak256::digest(&list))
}

/// Convert a U256 total difficulty to big-endian bytes for RLP encoding / eth/68.
/// Returns `vec![1]` for zero TD (minimum TD per eth/68 — peers reject TD=0).
pub fn td_to_rlp_bytes(td: &U256) -> Vec<u8> {
    if td.is_zero() {
        return vec![1];
    }
    let buf = td.to_be_bytes::<32>();
    let start = buf.iter().position(|&b| b != 0).unwrap_or(32);
    buf[start..].to_vec()
}

/// Convert big-endian bytes to U256.
pub fn bytes_to_u256(bytes: &[u8]) -> U256 {
    if bytes.is_empty() {
        return U256::ZERO;
    }
    let mut buf = [0u8; 32];
    let offset = 32usize.saturating_sub(bytes.len());
    let len = bytes.len().min(32);
    buf[offset..offset + len].copy_from_slice(&bytes[bytes.len() - len..]);
    U256::from_be_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rlp_encode_empty_bytes() {
        assert_eq!(rlp_encode_bytes(&[]), vec![0x80]);
    }

    #[test]
    fn rlp_encode_single_byte() {
        assert_eq!(rlp_encode_bytes(&[0x42]), vec![0x42]);
    }

    #[test]
    fn rlp_encode_short_string() {
        let data = b"hello";
        let encoded = rlp_encode_bytes(data);
        assert_eq!(encoded[0], 0x80 + 5);
        assert_eq!(&encoded[1..], b"hello");
    }

    #[test]
    fn rlp_encode_zero_u64() {
        assert_eq!(rlp_encode_u64(0), vec![0x80]);
    }

    #[test]
    fn rlp_encode_small_u64() {
        assert_eq!(rlp_encode_u64(1), vec![0x01]);
    }

    #[test]
    fn rlp_encode_medium_u64() {
        // 1024 = 0x0400
        let encoded = rlp_encode_u64(1024);
        assert_eq!(encoded, vec![0x82, 0x04, 0x00]);
    }

    #[test]
    fn rlp_encode_zero_u256() {
        assert_eq!(rlp_encode_u256(&U256::ZERO), vec![0x80]);
    }

    #[test]
    fn empty_uncle_hash_is_correct() {
        assert_eq!(empty_uncle_hash(), compute_uncle_hash(&[]));
    }

    #[test]
    fn header_hash_deterministic() {
        let header = BlockHeader {
            parent_hash: B256::ZERO,
            uncle_hash: empty_uncle_hash(),
            coinbase: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: [0u8; 256],
            difficulty: U256::from(1),
            number: 0,
            gas_limit: 5000,
            gas_used: 0,
            timestamp: 0,
            extra_data: vec![],
            mix_hash: B256::ZERO,
            nonce: [0u8; 8],
            base_fee: None,
        };

        let h1 = header.hash();
        let h2 = header.hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, B256::ZERO);
    }
}
