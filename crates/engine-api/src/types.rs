use alloy_primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};
use serde_hex::{
    hex_bytes, hex_bytes_vec, hex_h160, hex_h256, hex_nonce_opt, hex_u256, hex_u256_opt, hex_u64,
};

// ============================================================================
// Engine API types (matching go-ethereum-etc-el JSON format exactly)
// ============================================================================

/// ExecutionPayload (V2+) — the core data structure sent to/from the EL.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionPayload {
    #[serde(with = "hex_h256")]
    pub parent_hash: B256,

    #[serde(with = "hex_h160")]
    pub fee_recipient: Address,

    #[serde(with = "hex_h256")]
    pub state_root: B256,

    #[serde(with = "hex_h256")]
    pub receipts_root: B256,

    #[serde(with = "hex_bytes")]
    pub logs_bloom: Vec<u8>,

    /// Maps to MixDigest in the EL header. For PoW, this is the ethash mixHash.
    #[serde(with = "hex_h256")]
    pub prev_randao: B256,

    #[serde(with = "hex_u64")]
    pub block_number: u64,

    #[serde(with = "hex_u64")]
    pub gas_limit: u64,

    #[serde(with = "hex_u64")]
    pub gas_used: u64,

    #[serde(with = "hex_u64")]
    pub timestamp: u64,

    #[serde(with = "hex_bytes")]
    pub extra_data: Vec<u8>,

    #[serde(with = "hex_u256")]
    pub base_fee_per_gas: U256,

    #[serde(with = "hex_h256")]
    pub block_hash: B256,

    #[serde(with = "hex_bytes_vec")]
    pub transactions: Vec<Vec<u8>>,

    /// Withdrawals (V2+). Not used for PoW chains (ETC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawals: Option<Vec<Withdrawal>>,

    // PoW consensus fields (optional, used by PoW CLs).
    #[serde(skip_serializing_if = "Option::is_none", with = "hex_u256_opt")]
    pub difficulty: Option<U256>,

    #[serde(skip_serializing_if = "Option::is_none", with = "hex_nonce_opt")]
    pub nonce: Option<[u8; 8]>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub uncles: Option<Vec<UncleHeader>>,
}

/// Uncle header for Engine API transport.
/// Field names must match go-ethereum's `types.Header` JSON tags exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UncleHeader {
    #[serde(rename = "parentHash", with = "hex_h256")]
    pub parent_hash: B256,
    #[serde(rename = "sha3Uncles", with = "hex_h256")]
    pub uncle_hash: B256,
    #[serde(rename = "miner", with = "hex_h160")]
    pub coinbase: Address,
    #[serde(rename = "stateRoot", with = "hex_h256")]
    pub state_root: B256,
    #[serde(rename = "transactionsRoot", with = "hex_h256")]
    pub transactions_root: B256,
    #[serde(rename = "receiptsRoot", with = "hex_h256")]
    pub receipts_root: B256,
    #[serde(rename = "logsBloom", with = "hex_bytes")]
    pub logs_bloom: Vec<u8>,
    #[serde(with = "hex_u256")]
    pub difficulty: U256,
    #[serde(with = "hex_u64")]
    pub number: u64,
    #[serde(rename = "gasLimit", with = "hex_u64")]
    pub gas_limit: u64,
    #[serde(rename = "gasUsed", with = "hex_u64")]
    pub gas_used: u64,
    #[serde(with = "hex_u64")]
    pub timestamp: u64,
    #[serde(rename = "extraData", with = "hex_bytes")]
    pub extra_data: Vec<u8>,
    #[serde(rename = "mixHash", with = "hex_h256")]
    pub mix_digest: B256,
    #[serde(with = "hex_bytes")]
    pub nonce: Vec<u8>,
    #[serde(
        rename = "baseFeePerGas",
        skip_serializing_if = "Option::is_none",
        with = "hex_u256_opt"
    )]
    pub base_fee: Option<U256>,
}

/// Withdrawal entry for Engine API.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Withdrawal {
    #[serde(with = "hex_u64")]
    pub index: u64,
    #[serde(with = "hex_u64")]
    pub validator_index: u64,
    #[serde(with = "hex_h160")]
    pub address: Address,
    #[serde(with = "hex_u64")]
    pub amount: u64,
}

/// PayloadAttributes for engine_forkchoiceUpdated (V2).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadAttributes {
    #[serde(with = "hex_u64")]
    pub timestamp: u64,
    #[serde(with = "hex_h256")]
    pub prev_randao: B256,
    #[serde(with = "hex_h160")]
    pub suggested_fee_recipient: Address,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawals: Option<Vec<Withdrawal>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uncles: Option<Vec<UncleHeader>>,
}

/// ForkchoiceState for engine_forkchoiceUpdated.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkchoiceState {
    #[serde(with = "hex_h256")]
    pub head_block_hash: B256,
    #[serde(with = "hex_h256")]
    pub safe_block_hash: B256,
    #[serde(with = "hex_h256")]
    pub finalized_block_hash: B256,
}

/// PayloadStatus returned by engine_newPayload and engine_forkchoiceUpdated.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadStatus {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_valid_hash: Option<B256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_error: Option<String>,
}

/// ForkChoiceResponse from engine_forkchoiceUpdated.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForkChoiceResponse {
    pub payload_status: PayloadStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_id: Option<String>,
}

/// ExecutionPayloadEnvelope from engine_getPayload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionPayloadEnvelope {
    pub execution_payload: ExecutionPayload,
    #[serde(with = "hex_u256")]
    pub block_value: U256,
}

/// Payload status values.
pub const STATUS_VALID: &str = "VALID";
pub const STATUS_INVALID: &str = "INVALID";
pub const STATUS_SYNCING: &str = "SYNCING";
pub const STATUS_ACCEPTED: &str = "ACCEPTED";

/// StatusInfoResponse from engine_getStatusInfoV1.
/// Contains the EL network identity and current fork ID (EIP-2124).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusInfoResponse {
    pub network_id: u64,
    #[serde(with = "hex_h256")]
    pub genesis_hash: B256,
    #[serde(with = "hex_bytes")]
    pub hash: Vec<u8>,
    pub next: u64,
    #[serde(default)]
    pub fork_blocks: Vec<u64>,
}

/// PayloadID is an 8-byte identifier.
pub type PayloadId = String;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_withdrawal() {
        let w = Withdrawal {
            index: 0,
            validator_index: 0,
            address: {
                let mut bytes = [0u8; 20];
                bytes[18] = 0x12;
                bytes[19] = 0x34;
                Address::from_slice(&bytes)
            },
            amount: 5_000_000_000,
        };

        let json = serde_json::to_string(&w).unwrap();
        assert!(json.contains("\"index\":\"0x0\""));
        assert!(json.contains("\"amount\":\"0x12a05f200\""));

        let decoded: Withdrawal = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, w);
    }

    #[test]
    fn serialize_forkchoice_state() {
        let fcs = ForkchoiceState {
            head_block_hash: B256::ZERO,
            safe_block_hash: B256::ZERO,
            finalized_block_hash: B256::ZERO,
        };

        let json = serde_json::to_string(&fcs).unwrap();
        assert!(json.contains("headBlockHash"));
        assert!(json.contains("safeBlockHash"));
        assert!(json.contains("finalizedBlockHash"));
    }

    #[test]
    fn deserialize_payload_status() {
        let json = r#"{"status":"VALID","latestValidHash":"0x0000000000000000000000000000000000000000000000000000000000000000","validationError":null}"#;
        let ps: PayloadStatus = serde_json::from_str(json).unwrap();
        assert_eq!(ps.status, "VALID");
    }

    #[test]
    fn execution_payload_with_pow_fields() {
        let payload = ExecutionPayload {
            parent_hash: B256::ZERO,
            fee_recipient: Address::ZERO,
            state_root: B256::ZERO,
            receipts_root: B256::ZERO,
            logs_bloom: vec![0u8; 256],
            prev_randao: B256::ZERO,
            block_number: 1,
            gas_limit: 8_000_000,
            gas_used: 0,
            timestamp: 1_000_000,
            extra_data: vec![],
            base_fee_per_gas: U256::from(1000),
            block_hash: B256::ZERO,
            transactions: vec![],
            withdrawals: Some(vec![]),
            difficulty: Some(U256::from(131072)),
            nonce: Some([0, 0, 0, 0, 0, 0, 0, 42]),
            uncles: None,
        };

        let json = serde_json::to_string(&payload).unwrap();
        assert!(json.contains("\"difficulty\""));
        assert!(json.contains("\"nonce\""));

        let decoded: ExecutionPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.difficulty, Some(U256::from(131072)));
        assert_eq!(decoded.nonce, Some([0, 0, 0, 0, 0, 0, 0, 42]));
    }

    #[test]
    fn execution_payload_without_pow_fields() {
        let json = r#"{
            "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "feeRecipient": "0x0000000000000000000000000000000000000000",
            "stateRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "receiptsRoot": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "prevRandao": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "blockNumber": "0x1",
            "gasLimit": "0x7a1200",
            "gasUsed": "0x0",
            "timestamp": "0xf4240",
            "extraData": "0x",
            "baseFeePerGas": "0x3e8",
            "blockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "transactions": [],
            "difficulty": null,
            "nonce": null
        }"#;

        let payload: ExecutionPayload = serde_json::from_str(json).unwrap();
        assert_eq!(payload.block_number, 1);
        assert_eq!(payload.difficulty, None);
        assert_eq!(payload.nonce, None);
        assert_eq!(payload.uncles, None);
    }
}
