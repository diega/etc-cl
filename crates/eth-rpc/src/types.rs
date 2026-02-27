use alloy_primitives::{Address, B256, U256};
use serde::Deserialize;
use serde_hex::{
    hex_bloom, hex_bytes, hex_h160, hex_h160_opt, hex_h256, hex_h256_opt, hex_nonce, hex_u256,
    hex_u256_opt, hex_u64, hex_u64_opt,
};

use chain::types::{
    rlp_encode_bytes, rlp_encode_list_from_encoded, rlp_encode_u256, rlp_encode_u64, BlockHeader,
    Bloom,
};

// ============================================================================
// EthBlock — deserialized from geth eth_getBlockByNumber response
// ============================================================================

/// Block as returned by geth `eth_getBlockByNumber`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthBlock {
    #[serde(deserialize_with = "hex_h256::deserialize")]
    pub parent_hash: B256,

    #[serde(rename = "sha3Uncles", deserialize_with = "hex_h256::deserialize")]
    pub uncle_hash: B256,

    #[serde(rename = "miner", deserialize_with = "hex_h160::deserialize")]
    pub coinbase: Address,

    #[serde(deserialize_with = "hex_h256::deserialize")]
    pub state_root: B256,

    #[serde(deserialize_with = "hex_h256::deserialize")]
    pub transactions_root: B256,

    #[serde(deserialize_with = "hex_h256::deserialize")]
    pub receipts_root: B256,

    #[serde(deserialize_with = "hex_bloom::deserialize")]
    pub logs_bloom: [u8; 256],

    #[serde(deserialize_with = "hex_u256::deserialize")]
    pub difficulty: U256,

    #[serde(deserialize_with = "hex_u64::deserialize")]
    pub number: u64,

    #[serde(deserialize_with = "hex_u64::deserialize")]
    pub gas_limit: u64,

    #[serde(deserialize_with = "hex_u64::deserialize")]
    pub gas_used: u64,

    #[serde(deserialize_with = "hex_u64::deserialize")]
    pub timestamp: u64,

    #[serde(deserialize_with = "hex_bytes::deserialize")]
    pub extra_data: Vec<u8>,

    #[serde(deserialize_with = "hex_h256::deserialize")]
    pub mix_hash: B256,

    #[serde(deserialize_with = "hex_nonce::deserialize")]
    pub nonce: [u8; 8],

    #[serde(deserialize_with = "hex_h256::deserialize")]
    pub hash: B256,

    #[serde(
        default,
        deserialize_with = "hex_u256_opt::deserialize",
        rename = "baseFeePerGas"
    )]
    pub base_fee: Option<U256>,

    #[serde(
        default,
        deserialize_with = "hex_u256_opt::deserialize",
        rename = "totalDifficulty"
    )]
    pub total_difficulty: Option<U256>,
}

impl EthBlock {
    /// Convert to a `chain::types::BlockHeader`.
    pub fn to_block_header(&self) -> BlockHeader {
        BlockHeader {
            parent_hash: self.parent_hash,
            uncle_hash: self.uncle_hash,
            coinbase: self.coinbase,
            state_root: self.state_root,
            transactions_root: self.transactions_root,
            receipts_root: self.receipts_root,
            logs_bloom: self.logs_bloom,
            difficulty: self.difficulty,
            number: self.number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data: self.extra_data.clone(),
            mix_hash: self.mix_hash,
            nonce: self.nonce,
            base_fee: self.base_fee,
        }
    }
}

// ============================================================================
// EthTransaction — deserialized from geth eth_getBlockByNumber(n, true)
// ============================================================================

/// Transaction as returned by geth with full=true.
/// Supports legacy (type 0) and EIP-2930 access list (type 1) transactions.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthTransaction {
    /// Transaction type: 0 = legacy, 1 = EIP-2930 access list.
    #[serde(default, rename = "type", deserialize_with = "hex_u64::deserialize")]
    pub tx_type: u64,

    #[serde(default, deserialize_with = "hex_u64_opt::deserialize")]
    pub chain_id: Option<u64>,

    #[serde(deserialize_with = "hex_u64::deserialize")]
    pub nonce: u64,

    #[serde(deserialize_with = "hex_u256::deserialize")]
    pub gas_price: U256,

    #[serde(deserialize_with = "hex_u64::deserialize")]
    pub gas: u64,

    #[serde(default, deserialize_with = "hex_h160_opt::deserialize")]
    pub to: Option<Address>,

    #[serde(deserialize_with = "hex_u256::deserialize")]
    pub value: U256,

    #[serde(deserialize_with = "hex_bytes::deserialize")]
    pub input: Vec<u8>,

    /// EIP-2930 access list (type 1 txs only).
    #[serde(default)]
    pub access_list: Vec<AccessListEntry>,

    #[serde(deserialize_with = "hex_u256::deserialize")]
    pub v: U256,

    #[serde(deserialize_with = "hex_u256::deserialize")]
    pub r: U256,

    #[serde(deserialize_with = "hex_u256::deserialize")]
    pub s: U256,
}

/// A single entry in an EIP-2930 access list.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessListEntry {
    pub address: Address,
    pub storage_keys: Vec<B256>,
}

impl EthTransaction {
    /// RLP-encode the transaction.
    /// - Type 0 (legacy): `RLP([nonce, gasPrice, gas, to, value, input, v, r, s])`
    /// - Type 1 (EIP-2930): `0x01 || RLP([chainId, nonce, gasPrice, gas, to, value, input, accessList, yParity, r, s])`
    pub fn rlp_encode(&self) -> Vec<u8> {
        match self.tx_type {
            0 => self.rlp_encode_legacy(),
            1 => self.rlp_encode_eip2930(),
            other => {
                // ETC only has type 0 (legacy) and type 1 (EIP-2930). If a future fork
                // introduces new tx types, this fallback will produce an invalid body
                // (wrong transactions_root) — the warning makes it visible so support
                // can be added. The EL will reject the block via newPayload regardless.
                tracing::warn!(
                    tx_type = other,
                    "unknown transaction type, encoding as legacy"
                );
                self.rlp_encode_legacy()
            }
        }
    }

    fn rlp_encode_legacy(&self) -> Vec<u8> {
        let mut fields: Vec<Vec<u8>> = Vec::with_capacity(9);

        fields.push(rlp_encode_u64(self.nonce));
        fields.push(rlp_encode_u256(&self.gas_price));
        fields.push(rlp_encode_u64(self.gas));

        match self.to {
            Some(addr) => fields.push(rlp_encode_bytes(addr.as_slice())),
            None => fields.push(rlp_encode_bytes(&[])),
        }

        fields.push(rlp_encode_u256(&self.value));
        fields.push(rlp_encode_bytes(&self.input));
        fields.push(rlp_encode_u256(&self.v));
        fields.push(rlp_encode_u256(&self.r));
        fields.push(rlp_encode_u256(&self.s));

        rlp_encode_list_from_encoded(&fields)
    }

    fn rlp_encode_eip2930(&self) -> Vec<u8> {
        let mut fields: Vec<Vec<u8>> = Vec::with_capacity(11);

        fields.push(rlp_encode_u64(self.chain_id.unwrap_or(0)));
        fields.push(rlp_encode_u64(self.nonce));
        fields.push(rlp_encode_u256(&self.gas_price));
        fields.push(rlp_encode_u64(self.gas));

        match self.to {
            Some(addr) => fields.push(rlp_encode_bytes(addr.as_slice())),
            None => fields.push(rlp_encode_bytes(&[])),
        }

        fields.push(rlp_encode_u256(&self.value));
        fields.push(rlp_encode_bytes(&self.input));

        // Access list: [[address, [storageKey1, storageKey2, ...]], ...]
        let access_list_encoded: Vec<Vec<u8>> = self
            .access_list
            .iter()
            .map(|entry| {
                let keys_encoded: Vec<Vec<u8>> = entry
                    .storage_keys
                    .iter()
                    .map(|k| rlp_encode_bytes(k.as_slice()))
                    .collect();
                let keys_list = rlp_encode_list_from_encoded(&keys_encoded);
                rlp_encode_list_from_encoded(&[
                    rlp_encode_bytes(entry.address.as_slice()),
                    keys_list,
                ])
            })
            .collect();
        fields.push(rlp_encode_list_from_encoded(&access_list_encoded));

        // yParity (v is 0 or 1 for typed txs)
        fields.push(rlp_encode_u256(&self.v));
        fields.push(rlp_encode_u256(&self.r));
        fields.push(rlp_encode_u256(&self.s));

        let rlp_body = rlp_encode_list_from_encoded(&fields);

        // Typed tx envelope: type_byte || rlp_body
        let mut result = Vec::with_capacity(1 + rlp_body.len());
        result.push(0x01);
        result.extend_from_slice(&rlp_body);
        result
    }
}

// ============================================================================
// EthBlockFull — block with full transaction objects
// ============================================================================

/// Block with full transaction objects, as returned by `eth_getBlockByNumber(n, true)`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthBlockFull {
    #[serde(deserialize_with = "hex_h256::deserialize")]
    pub parent_hash: B256,

    #[serde(rename = "sha3Uncles", deserialize_with = "hex_h256::deserialize")]
    pub uncle_hash: B256,

    #[serde(rename = "miner", deserialize_with = "hex_h160::deserialize")]
    pub coinbase: Address,

    #[serde(deserialize_with = "hex_h256::deserialize")]
    pub state_root: B256,

    #[serde(deserialize_with = "hex_h256::deserialize")]
    pub transactions_root: B256,

    #[serde(deserialize_with = "hex_h256::deserialize")]
    pub receipts_root: B256,

    #[serde(deserialize_with = "hex_bloom::deserialize")]
    pub logs_bloom: [u8; 256],

    #[serde(deserialize_with = "hex_u256::deserialize")]
    pub difficulty: U256,

    #[serde(deserialize_with = "hex_u64::deserialize")]
    pub number: u64,

    #[serde(deserialize_with = "hex_u64::deserialize")]
    pub gas_limit: u64,

    #[serde(deserialize_with = "hex_u64::deserialize")]
    pub gas_used: u64,

    #[serde(deserialize_with = "hex_u64::deserialize")]
    pub timestamp: u64,

    #[serde(deserialize_with = "hex_bytes::deserialize")]
    pub extra_data: Vec<u8>,

    #[serde(deserialize_with = "hex_h256::deserialize")]
    pub mix_hash: B256,

    #[serde(deserialize_with = "hex_nonce::deserialize")]
    pub nonce: [u8; 8],

    #[serde(deserialize_with = "hex_h256::deserialize")]
    pub hash: B256,

    #[serde(
        default,
        deserialize_with = "hex_u256_opt::deserialize",
        rename = "baseFeePerGas"
    )]
    pub base_fee: Option<U256>,

    pub transactions: Vec<EthTransaction>,

    #[serde(rename = "uncles")]
    pub uncle_hashes: Vec<B256>,
}

impl EthBlockFull {
    /// Convert to a `chain::types::BlockHeader`.
    pub fn to_block_header(&self) -> BlockHeader {
        BlockHeader {
            parent_hash: self.parent_hash,
            uncle_hash: self.uncle_hash,
            coinbase: self.coinbase,
            state_root: self.state_root,
            transactions_root: self.transactions_root,
            receipts_root: self.receipts_root,
            logs_bloom: self.logs_bloom,
            difficulty: self.difficulty,
            number: self.number,
            gas_limit: self.gas_limit,
            gas_used: self.gas_used,
            timestamp: self.timestamp,
            extra_data: self.extra_data.clone(),
            mix_hash: self.mix_hash,
            nonce: self.nonce,
            base_fee: self.base_fee,
        }
    }
}

// ============================================================================
// EthReceipt — deserialized from geth eth_getBlockReceipts response
// ============================================================================

/// A single log entry in a receipt.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthLog {
    #[serde(deserialize_with = "hex_h160::deserialize")]
    pub address: Address,

    pub topics: Vec<B256>,

    #[serde(deserialize_with = "hex_bytes::deserialize")]
    pub data: Vec<u8>,
}

impl EthLog {
    /// RLP-encode: [address, [topic1, ...], data]
    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut fields: Vec<Vec<u8>> = Vec::with_capacity(3);
        fields.push(rlp_encode_bytes(self.address.as_slice()));

        let topics_encoded: Vec<Vec<u8>> = self
            .topics
            .iter()
            .map(|t| rlp_encode_bytes(t.as_slice()))
            .collect();
        fields.push(rlp_encode_list_from_encoded(&topics_encoded));

        fields.push(rlp_encode_bytes(&self.data));
        rlp_encode_list_from_encoded(&fields)
    }
}

/// Transaction receipt as returned by geth `eth_getBlockReceipts`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthReceipt {
    #[serde(deserialize_with = "hex_u64::deserialize")]
    pub status: u64,

    #[serde(deserialize_with = "hex_u64::deserialize")]
    pub cumulative_gas_used: u64,

    #[serde(deserialize_with = "hex_bloom::deserialize")]
    pub logs_bloom: Bloom,

    pub logs: Vec<EthLog>,

    /// Pre-Atlantis stateRoot (post-Atlantis receipts have status instead).
    #[serde(default, deserialize_with = "hex_h256_opt::deserialize")]
    pub root: Option<B256>,
}

/// ETC Atlantis fork block (post-Byzantium, status receipts).
fn atlantis_block() -> u64 {
    forks::schedule::Fork::Atlantis.activation_block()
}

impl EthReceipt {
    /// RLP-encode for eth/68 wire format.
    /// Pre-Atlantis: [stateRoot, cumulativeGasUsed, bloom, [logs]]
    /// Post-Atlantis: [status, cumulativeGasUsed, bloom, [logs]]
    pub fn rlp_encode(&self, block_number: u64) -> Vec<u8> {
        let mut fields: Vec<Vec<u8>> = Vec::with_capacity(4);

        if block_number < atlantis_block() {
            // Pre-Atlantis: postStateOrStatus = stateRoot (32 bytes)
            match &self.root {
                Some(root) => fields.push(rlp_encode_bytes(root.as_slice())),
                None => fields.push(rlp_encode_bytes(&[0u8; 32])),
            }
        } else {
            // Post-Atlantis: postStateOrStatus = status byte
            if self.status == 1 {
                fields.push(rlp_encode_bytes(&[1u8]));
            } else {
                fields.push(rlp_encode_bytes(&[]));
            }
        }

        fields.push(rlp_encode_u64(self.cumulative_gas_used));
        fields.push(rlp_encode_bytes(&self.logs_bloom));

        let logs_encoded: Vec<Vec<u8>> = self.logs.iter().map(|l| l.rlp_encode()).collect();
        fields.push(rlp_encode_list_from_encoded(&logs_encoded));

        rlp_encode_list_from_encoded(&fields)
    }
}
