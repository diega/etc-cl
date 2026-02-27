pub mod rpc;

use std::collections::HashMap;
use std::sync::Arc;

use alloy_primitives::{Address, B256, U256};
use chain::types::BlockHeader;
use consensus::ethash;
use engine_api::bridge::block_header_to_uncle_header;
use engine_api::bridge::payload_to_header;
use engine_api::client::EngineClient;
use engine_api::types::{
    ExecutionPayload, ForkchoiceState, PayloadAttributes, UncleHeader, STATUS_VALID,
};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};

/// A work package ready for miners.
pub struct WorkPackage {
    /// seal_hash of the header (keccak256 without nonce/mixHash).
    pub pow_hash: B256,
    /// Seed hash for the DAG epoch.
    pub seed_hash: B256,
    /// Target boundary: 2^256 / difficulty.
    pub target: U256,
    /// Block number being mined.
    pub block_number: u64,
    /// Difficulty of the block.
    pub difficulty: U256,
    /// The execution payload template from the EL.
    pub payload: ExecutionPayload,
    /// The block header reconstructed from the payload.
    pub header: BlockHeader,
}

/// Result of a successfully mined block.
pub struct MinedBlock {
    pub hash: B256,
    pub number: u64,
    /// RLP-encoded sealed header (for block broadcast).
    pub header_rlp: Vec<u8>,
    /// Raw RLP-encoded transactions (for block broadcast).
    pub transactions: Vec<Vec<u8>>,
    /// Uncle headers included in this block.
    pub uncles: Vec<BlockHeader>,
}

/// Mining coordinator: manages work generation and submission.
pub struct MiningCoordinator {
    coinbase: Address,
    current_work: RwLock<Option<WorkPackage>>,
    ethash_caches: Mutex<HashMap<u64, Arc<Vec<u8>>>>,
    submitted_hashrates: Mutex<HashMap<String, u64>>,
}

impl MiningCoordinator {
    pub fn new(coinbase: Address) -> Self {
        Self {
            coinbase,
            current_work: RwLock::new(None),
            ethash_caches: Mutex::new(HashMap::new()),
            submitted_hashrates: Mutex::new(HashMap::new()),
        }
    }

    /// Called when a new head is accepted. Triggers block building on the EL
    /// and prepares a new work package for miners.
    pub async fn on_new_head(
        &self,
        engine: &EngineClient,
        head_hash: B256,
        head_timestamp: u64,
        uncle_candidates: Vec<BlockHeader>,
    ) -> Result<(), MiningError> {
        let timestamp = {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            std::cmp::max(head_timestamp + 1, now)
        };

        // Send FCU with PayloadAttributes to trigger block building.
        // Use B256::ZERO for finalized — PoW has no finality, and marking
        // head as finalized could trigger aggressive state pruning in the EL.
        let state = ForkchoiceState {
            head_block_hash: head_hash,
            safe_block_hash: head_hash,
            finalized_block_hash: B256::ZERO,
        };
        let uncle_headers: Option<Vec<UncleHeader>> = if uncle_candidates.is_empty() {
            None
        } else {
            Some(
                uncle_candidates
                    .iter()
                    .map(block_header_to_uncle_header)
                    .collect(),
            )
        };
        let attrs = PayloadAttributes {
            timestamp,
            prev_randao: B256::ZERO,
            suggested_fee_recipient: self.coinbase,
            withdrawals: None,
            uncles: uncle_headers,
        };

        let fcu_resp = engine
            .forkchoice_updated_v2(&state, Some(&attrs))
            .await
            .map_err(|e| MiningError::Engine(e.to_string()))?;

        if fcu_resp.payload_status.status != STATUS_VALID {
            return Err(MiningError::Engine(format!(
                "FCU returned {}: {}",
                fcu_resp.payload_status.status,
                fcu_resp.payload_status.validation_error.unwrap_or_default()
            )));
        }

        let payload_id = match fcu_resp.payload_id {
            Some(id) => id,
            None => {
                return Err(MiningError::Engine(
                    "FCU returned no payload_id".to_string(),
                ));
            }
        };

        // Wait briefly for the EL to assemble the block.
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Fetch the built payload.
        let envelope = engine
            .get_payload_v2(&payload_id)
            .await
            .map_err(|e| MiningError::Engine(e.to_string()))?;

        let payload = envelope.execution_payload;
        let header = payload_to_header(&payload);

        let difficulty = header.difficulty;
        if difficulty.is_zero() {
            return Err(MiningError::Engine(
                "EL returned difficulty=0 — beacon.Prepare() not patched?".to_string(),
            ));
        }

        let block_number = header.number;
        let ep = ethash::epoch(block_number);
        let ep_len = ethash::epoch_length(block_number);
        let pow_hash = header.seal_hash();
        let seed = ethash::seed_hash(ep, ep_len);
        let target = ethash::difficulty_to_target(&difficulty);

        // Ensure ethash cache is ready for this epoch (cap at 3).
        {
            let mut caches = self.ethash_caches.lock().await;
            caches.entry(ep).or_insert_with(|| {
                info!(
                    epoch = ep,
                    "generating ethash cache for mining verification"
                );
                let cache = ethash::make_cache(ep, ep_len);
                Arc::new(cache)
            });
            // Evict oldest caches if we have too many
            while caches.len() > 3 {
                if let Some(&oldest) = caches.keys().min() {
                    caches.remove(&oldest);
                }
            }
        }

        let work = WorkPackage {
            pow_hash,
            seed_hash: seed,
            target,
            block_number,
            difficulty,
            payload,
            header,
        };

        info!(
            block = block_number,
            difficulty = %difficulty,
            pow_hash = %pow_hash,
            "new mining work available"
        );

        *self.current_work.write().await = Some(work);
        Ok(())
    }

    /// Returns current work for miners: [powHash, seedHash, target, blockNumber].
    pub async fn get_work(&self) -> Option<[String; 4]> {
        let work = self.current_work.read().await;
        work.as_ref().map(|w| {
            [
                format!("0x{}", hex::encode(w.pow_hash.as_slice())),
                format!("0x{}", hex::encode(w.seed_hash.as_slice())),
                format!("0x{:064x}", w.target),
                format!("0x{:x}", w.block_number),
            ]
        })
    }

    /// Submit a mined solution. Verifies PoW, sends to EL, returns mined block info.
    ///
    /// The caller (node.rs) is responsible for updating the chain DB.
    pub async fn submit_work(
        &self,
        engine: &EngineClient,
        nonce_hex: &str,
        pow_hash_hex: &str,
        mix_digest_hex: &str,
    ) -> Result<Option<MinedBlock>, MiningError> {
        // Parse inputs.
        let nonce_bytes = hex::decode(strip_0x(nonce_hex))
            .map_err(|_| MiningError::InvalidInput("bad nonce hex".into()))?;
        if nonce_bytes.len() != 8 {
            return Err(MiningError::InvalidInput("nonce must be 8 bytes".into()));
        }
        let mut nonce = [0u8; 8];
        nonce.copy_from_slice(&nonce_bytes);

        let pow_hash = parse_b256(pow_hash_hex)?;
        let mix_digest = parse_b256(mix_digest_hex)?;

        // Check that the pow_hash matches current work.
        let work_guard = self.current_work.read().await;
        let work = match work_guard.as_ref() {
            Some(w) if w.pow_hash == pow_hash => w,
            _ => {
                warn!(submitted = %pow_hash, "submitted work does not match current pow_hash");
                return Ok(None);
            }
        };

        // Verify PoW locally.
        let nonce_u64 = u64::from_be_bytes(nonce);
        let ep = ethash::epoch(work.block_number);
        let cache = {
            let caches = self.ethash_caches.lock().await;
            caches.get(&ep).cloned()
        };
        let cache = match cache {
            Some(c) => c,
            None => return Err(MiningError::Engine("no ethash cache for epoch".into())),
        };

        let full_size = ethash::dataset_size(ep);
        let (computed_mix, result) = {
            let pow_hash_clone = pow_hash;
            let cache_clone = Arc::clone(&cache);
            tokio::task::spawn_blocking(move || {
                ethash::hashimoto_light(&pow_hash_clone, nonce_u64, full_size, &cache_clone)
            })
            .await
            .map_err(|e| MiningError::Engine(format!("spawn_blocking failed: {}", e)))?
        };

        if computed_mix != mix_digest {
            warn!(
                expected = %computed_mix,
                got = %mix_digest,
                "mix digest mismatch"
            );
            return Ok(None);
        }

        let result_u256 = U256::from_be_slice(result.as_ref());
        if result_u256 > work.target {
            warn!("PoW result does not meet difficulty target");
            return Ok(None);
        }

        info!(
            block = work.block_number,
            nonce = %hex::encode(nonce),
            "valid PoW solution, submitting to EL"
        );

        // Build the final payload with nonce and mixDigest.
        let mut final_payload = work.payload.clone();
        final_payload.nonce = Some(nonce);
        final_payload.prev_randao = mix_digest; // prevRandao maps to mixHash

        // Recompute block_hash with the sealed header.
        let mut sealed_header = work.header.clone();
        sealed_header.nonce = nonce;
        sealed_header.mix_hash = mix_digest;
        let block_hash = sealed_header.hash();
        final_payload.block_hash = block_hash;

        // Extract uncles from payload (if any) for broadcast.
        let block_uncles: Vec<BlockHeader> = match &work.payload.uncles {
            Some(uncle_headers) => uncle_headers
                .iter()
                .map(engine_api::bridge::uncle_header_to_block_header)
                .collect(),
            None => vec![],
        };

        // Save info before dropping read lock.
        let block_number = work.block_number;
        let sealed_header_rlp = sealed_header.rlp_encode();
        let transactions = work.payload.transactions.clone();
        drop(work_guard);

        // Send newPayloadV2 to EL.
        let status = engine
            .new_payload_v2(&final_payload)
            .await
            .map_err(|e| MiningError::Engine(e.to_string()))?;

        // Mined blocks must be immediately VALID (not just ACCEPTED) because the EL
        // built them locally — there's no missing parent or pending validation.
        if status.status != STATUS_VALID {
            error!(
                status = %status.status,
                err = ?status.validation_error,
                "EL rejected mined block"
            );
            return Ok(None);
        }

        // Send FCU to make this the new head.
        // Use B256::ZERO for finalized — PoW has no finality.
        let fcu_state = ForkchoiceState {
            head_block_hash: block_hash,
            safe_block_hash: block_hash,
            finalized_block_hash: B256::ZERO,
        };
        let fcu_resp = engine
            .forkchoice_updated_v2(&fcu_state, None)
            .await
            .map_err(|e| MiningError::Engine(e.to_string()))?;

        if fcu_resp.payload_status.status != STATUS_VALID {
            error!(
                status = %fcu_resp.payload_status.status,
                "FCU failed after mining"
            );
            return Ok(None);
        }

        info!(
            block = block_number,
            hash = %block_hash,
            "mined block accepted!"
        );

        // Clear current work — new head will trigger new work via on_new_head.
        *self.current_work.write().await = None;

        Ok(Some(MinedBlock {
            hash: block_hash,
            number: block_number,
            header_rlp: sealed_header_rlp,
            transactions,
            uncles: block_uncles,
        }))
    }

    /// Submit hashrate from a miner.
    pub async fn submit_hashrate(&self, rate: u64, id: String) {
        debug!(rate, id = %id, "hashrate submitted");
        let mut rates = self.submitted_hashrates.lock().await;
        if rates.len() >= 64 {
            rates.clear();
        }
        rates.insert(id, rate);
    }

    /// Get total submitted hashrate.
    pub async fn hashrate(&self) -> u64 {
        self.submitted_hashrates.lock().await.values().sum()
    }
}

fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

fn parse_b256(hex_str: &str) -> Result<B256, MiningError> {
    let s = strip_0x(hex_str);
    let bytes = hex::decode(s).map_err(|_| MiningError::InvalidInput("bad hex for B256".into()))?;
    if bytes.len() != 32 {
        return Err(MiningError::InvalidInput(format!(
            "expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(B256::from_slice(&bytes))
}

#[derive(Debug, thiserror::Error)]
pub enum MiningError {
    #[error("engine API error: {0}")]
    Engine(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
}
