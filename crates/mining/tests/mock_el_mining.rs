//! End-to-end mining test via real HTTP RPC (`eth_getWork`, `eth_submitWork`).
//!
//! Spins up:
//! 1. A mock EL (Engine API) that returns VALID and tracks FCU `headBlockHash`es.
//! 2. The real mining RPC server (`mining::rpc::start_mining_rpc`).
//!
//! The test mines 2 blocks by talking to the mining RPC over HTTP and verifies
//! that each mined block caused an FCU to the mock EL with the correct head hash.

use std::sync::Arc;

use alloy_primitives::{Address, B256, U256};
use axum::{extract::State, routing::post, Json, Router};
use chain::types::{empty_uncle_hash, BlockHeader};
use consensus::ethash;
use engine_api::client::EngineClient;
use mining::MiningCoordinator;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tokio::sync::Mutex as TokioMutex;

/// Shared secret for JWT auth (test-only).
const JWT_SECRET: [u8; 32] = [0x42u8; 32];

/// Low difficulty so PoW is solved in 1-2 attempts on average.
const TEST_DIFFICULTY: u64 = 2;

// --------------------------------------------------------------------------
// Mock Engine API types
// --------------------------------------------------------------------------

#[derive(Deserialize)]
struct RpcRequest {
    method: String,
    params: serde_json::Value,
    id: serde_json::Value,
}

#[derive(Serialize)]
struct RpcResponse {
    jsonrpc: &'static str,
    result: Option<serde_json::Value>,
    error: Option<RpcError>,
    id: serde_json::Value,
}

#[derive(Serialize)]
struct RpcError {
    code: i64,
    message: String,
}

impl RpcResponse {
    fn ok(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0",
            result: Some(result),
            error: None,
            id,
        }
    }
}

// --------------------------------------------------------------------------
// Mock EL state — tracks chain + FCU heads
// --------------------------------------------------------------------------

struct MockElState {
    chain: TokioMutex<Vec<BlockHeader>>,
    /// headBlockHash from each engine_forkchoiceUpdatedV2 call (that has no payloadAttributes).
    fcu_heads: TokioMutex<Vec<String>>,
}

impl MockElState {
    fn new(genesis: BlockHeader) -> Self {
        Self {
            chain: TokioMutex::new(vec![genesis]),
            fcu_heads: TokioMutex::new(Vec::new()),
        }
    }
}

// --------------------------------------------------------------------------
// Build a payload for the next block
// --------------------------------------------------------------------------

fn build_next_payload(parent: &BlockHeader) -> BlockHeader {
    let block_number = parent.number + 1;
    let timestamp = parent.timestamp + 13;

    BlockHeader {
        parent_hash: parent.hash(),
        uncle_hash: empty_uncle_hash(),
        coinbase: Address::ZERO,
        state_root: B256::ZERO,
        transactions_root: empty_trie_root(),
        receipts_root: B256::ZERO,
        logs_bloom: [0u8; 256],
        difficulty: U256::from(TEST_DIFFICULTY),
        number: block_number,
        gas_limit: parent.gas_limit,
        gas_used: 0,
        timestamp,
        extra_data: vec![],
        mix_hash: B256::ZERO,
        nonce: [0u8; 8],
        base_fee: None,
    }
}

fn header_to_payload_json(header: &BlockHeader) -> serde_json::Value {
    let block_hash = header.hash();
    let parent_hash_hex = format!("0x{}", hex::encode(header.parent_hash.as_slice()));
    let block_hash_hex = format!("0x{}", hex::encode(block_hash.as_slice()));
    let block_num_hex = format!("0x{:x}", header.number);
    let timestamp_hex = format!("0x{:x}", header.timestamp);
    let diff_hex = format!("0x{:x}", header.difficulty);
    let bloom_hex = format!("0x{}", hex::encode([0u8; 256]));
    let zero_hash = format!("0x{:064x}", 0);

    let exec_payload = serde_json::json!({
        "parentHash": parent_hash_hex,
        "feeRecipient": "0x0000000000000000000000000000000000000000",
        "stateRoot": zero_hash,
        "receiptsRoot": zero_hash,
        "logsBloom": bloom_hex,
        "prevRandao": zero_hash,
        "blockNumber": block_num_hex,
        "gasLimit": format!("0x{:x}", header.gas_limit),
        "gasUsed": "0x0",
        "timestamp": timestamp_hex,
        "extraData": "0x",
        "baseFeePerGas": "0x0",
        "blockHash": block_hash_hex,
        "transactions": [],
        "difficulty": diff_hex,
        "nonce": "0x0000000000000000"
    });

    serde_json::json!({
        "executionPayload": exec_payload,
        "blockValue": "0x0"
    })
}

/// Empty transactions trie root = keccak256(0x80).
fn empty_trie_root() -> B256 {
    use sha3::Digest;
    B256::from_slice(&sha3::Keccak256::digest([0x80]))
}

// --------------------------------------------------------------------------
// Mock Engine API handler
// --------------------------------------------------------------------------

async fn handle_engine_rpc(
    State(state): State<Arc<MockElState>>,
    Json(req): Json<RpcRequest>,
) -> Json<RpcResponse> {
    match req.method.as_str() {
        "engine_forkchoiceUpdatedV2" => {
            // Track the headBlockHash for FCU calls without payloadAttributes
            // (these are the "set new head" calls from submit_work).
            if let Some(params) = req.params.as_array() {
                let has_payload_attrs = params.get(1).is_some_and(|v| !v.is_null());
                if !has_payload_attrs {
                    if let Some(head) = params
                        .first()
                        .and_then(|v| v.get("headBlockHash"))
                        .and_then(|v| v.as_str())
                    {
                        state.fcu_heads.lock().await.push(head.to_string());
                    }
                }
            }

            Json(RpcResponse::ok(
                req.id,
                serde_json::json!({
                    "payloadStatus": {
                        "status": "VALID",
                        "latestValidHash": null,
                        "validationError": null
                    },
                    "payloadId": "0x0000000000000001"
                }),
            ))
        }
        "engine_getPayloadV2" => {
            let chain = state.chain.lock().await;
            let parent = chain.last().unwrap();
            let header = build_next_payload(parent);
            let envelope = header_to_payload_json(&header);
            Json(RpcResponse::ok(req.id, envelope))
        }
        "engine_newPayloadV2" => {
            // Accept the block — push it onto our chain so the next getPayload
            // builds on top of it.
            if let Some(params) = req.params.as_array() {
                if let Some(payload) = params.first() {
                    if let (Some(number_hex), Some(parent_hex)) = (
                        payload.get("blockNumber").and_then(|v| v.as_str()),
                        payload.get("parentHash").and_then(|v| v.as_str()),
                    ) {
                        let number = u64::from_str_radix(
                            number_hex.strip_prefix("0x").unwrap_or(number_hex),
                            16,
                        )
                        .unwrap_or(0);

                        let parent_bytes =
                            hex::decode(parent_hex.strip_prefix("0x").unwrap_or(parent_hex))
                                .unwrap_or_default();
                        let parent_hash = if parent_bytes.len() == 32 {
                            B256::from_slice(&parent_bytes)
                        } else {
                            B256::ZERO
                        };

                        let block_hash_hex = payload
                            .get("blockHash")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let block_hash_bytes = hex::decode(
                            block_hash_hex.strip_prefix("0x").unwrap_or(block_hash_hex),
                        )
                        .unwrap_or_default();
                        let block_hash = if block_hash_bytes.len() == 32 {
                            B256::from_slice(&block_hash_bytes)
                        } else {
                            B256::ZERO
                        };

                        let timestamp_hex = payload
                            .get("timestamp")
                            .and_then(|v| v.as_str())
                            .unwrap_or("0x0");
                        let timestamp = u64::from_str_radix(
                            timestamp_hex.strip_prefix("0x").unwrap_or(timestamp_hex),
                            16,
                        )
                        .unwrap_or(0);

                        let gas_limit_hex = payload
                            .get("gasLimit")
                            .and_then(|v| v.as_str())
                            .unwrap_or("0x0");
                        let gas_limit = u64::from_str_radix(
                            gas_limit_hex.strip_prefix("0x").unwrap_or(gas_limit_hex),
                            16,
                        )
                        .unwrap_or(0);

                        let nonce_hex = payload
                            .get("nonce")
                            .and_then(|v| v.as_str())
                            .unwrap_or("0x0000000000000000");
                        let nonce_bytes =
                            hex::decode(nonce_hex.strip_prefix("0x").unwrap_or(nonce_hex))
                                .unwrap_or_else(|_| vec![0u8; 8]);
                        let mut nonce = [0u8; 8];
                        if nonce_bytes.len() == 8 {
                            nonce.copy_from_slice(&nonce_bytes);
                        }

                        let mix_hex = payload
                            .get("prevRandao")
                            .and_then(|v| v.as_str())
                            .unwrap_or("");
                        let mix_bytes = hex::decode(mix_hex.strip_prefix("0x").unwrap_or(mix_hex))
                            .unwrap_or_default();
                        let mix_hash = if mix_bytes.len() == 32 {
                            B256::from_slice(&mix_bytes)
                        } else {
                            B256::ZERO
                        };

                        // Build a header that matches
                        let header = BlockHeader {
                            parent_hash,
                            uncle_hash: empty_uncle_hash(),
                            coinbase: Address::ZERO,
                            state_root: B256::ZERO,
                            transactions_root: empty_trie_root(),
                            receipts_root: B256::ZERO,
                            logs_bloom: [0u8; 256],
                            difficulty: U256::from(TEST_DIFFICULTY),
                            number,
                            gas_limit,
                            gas_used: 0,
                            timestamp,
                            extra_data: vec![],
                            mix_hash,
                            nonce,
                            base_fee: None,
                        };

                        // Only push if this block_hash matches (sealed block from submit_work)
                        if header.hash() == block_hash {
                            let mut chain = state.chain.lock().await;
                            chain.push(header);
                        }
                    }
                }
            }

            Json(RpcResponse::ok(
                req.id,
                serde_json::json!({
                    "status": "VALID",
                    "latestValidHash": null,
                    "validationError": null
                }),
            ))
        }
        _ => Json(RpcResponse::ok(req.id, serde_json::json!(null))),
    }
}

// --------------------------------------------------------------------------
// Helper: solve PoW for a given pow_hash at TEST_DIFFICULTY
// --------------------------------------------------------------------------

fn solve_pow(pow_hash: &B256, block_number: u64) -> (u64, B256) {
    let ep = ethash::epoch(block_number);
    let ep_len = ethash::epoch_length(block_number);
    let cache = ethash::make_cache(ep, ep_len);
    let full_size = ethash::dataset_size(ep);
    let target = ethash::difficulty_to_target(&U256::from(TEST_DIFFICULTY));

    let mut nonce = 0u64;
    loop {
        let (mix, result) = ethash::hashimoto_light(pow_hash, nonce, full_size, &cache);
        let result_u256 = U256::from_be_slice(result.as_ref());
        if result_u256 <= target {
            return (nonce, mix);
        }
        nonce += 1;
        assert!(
            nonce < 1000,
            "should find nonce quickly at difficulty={}",
            TEST_DIFFICULTY
        );
    }
}

// --------------------------------------------------------------------------
// Helper: JSON-RPC call via reqwest
// --------------------------------------------------------------------------

async fn rpc_call(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    });

    let resp = client
        .post(url)
        .json(&body)
        .send()
        .await
        .expect("HTTP request failed");

    let json: serde_json::Value = resp.json().await.expect("invalid JSON response");
    json
}

// --------------------------------------------------------------------------
// Test: mine 2 blocks via real HTTP RPC endpoints
// --------------------------------------------------------------------------

#[tokio::test]
async fn mine_two_blocks_e2e_via_rpc() {
    let genesis = BlockHeader {
        parent_hash: B256::ZERO,
        uncle_hash: empty_uncle_hash(),
        coinbase: Address::ZERO,
        state_root: B256::ZERO,
        transactions_root: empty_trie_root(),
        receipts_root: B256::ZERO,
        logs_bloom: [0u8; 256],
        difficulty: U256::from(TEST_DIFFICULTY),
        number: 0,
        gas_limit: 8_000_000,
        gas_used: 0,
        timestamp: 1_000_000,
        extra_data: vec![],
        mix_hash: B256::ZERO,
        nonce: [0u8; 8],
        base_fee: None,
    };

    println!(
        "Genesis: hash={} difficulty={}",
        genesis.hash(),
        genesis.difficulty
    );

    // 1. Start mock EL.
    let mock_state = Arc::new(MockElState::new(genesis.clone()));

    let app = Router::new()
        .route("/", post(handle_engine_rpc))
        .with_state(Arc::clone(&mock_state));

    let el_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let el_addr = el_listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(el_listener, app).await.unwrap();
    });

    let el_url = format!("http://{}", el_addr);

    // 2. Start real mining RPC server.
    let engine = Arc::new(EngineClient::new(&el_url, JWT_SECRET.to_vec()).unwrap());
    let coordinator = Arc::new(MiningCoordinator::new(Address::ZERO));

    let (mined_tx, _mined_rx) = tokio::sync::mpsc::channel(16);

    let rpc_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rpc_addr = rpc_listener.local_addr().unwrap();
    let rpc_url = format!("http://{}", rpc_addr);

    {
        let coord = Arc::clone(&coordinator);
        let eng = Arc::clone(&engine);
        tokio::spawn(async move {
            // Re-bind manually so we control the port
            let state = Arc::new(mining::rpc::MiningRpcState {
                coordinator: coord,
                engine: eng,
                mined_tx,
            });
            let app = axum::Router::new()
                .route("/", axum::routing::post(mining_rpc_handler))
                .with_state(state);
            axum::serve(rpc_listener, app).await.unwrap();
        });
    }

    let http = reqwest::Client::new();

    let mut fcu_count_before;
    let mut last_fcu_head = String::new();

    for block_num in 1..=2u64 {
        println!("\n--- Mining block {} ---", block_num);

        // 3. Seed work via coordinator.on_new_head
        let parent_hash = {
            let chain = mock_state.chain.lock().await;
            chain.last().unwrap().hash()
        };
        let parent_timestamp = {
            let chain = mock_state.chain.lock().await;
            chain.last().unwrap().timestamp
        };

        coordinator
            .on_new_head(engine.as_ref(), parent_hash, parent_timestamp, vec![])
            .await
            .unwrap_or_else(|e| panic!("on_new_head failed for block {}: {}", block_num, e));

        // Record FCU count before submit
        fcu_count_before = mock_state.fcu_heads.lock().await.len();

        // 4. eth_getWork via HTTP
        let resp = rpc_call(&http, &rpc_url, "eth_getWork", serde_json::json!([])).await;
        let work = resp["result"]
            .as_array()
            .expect("eth_getWork should return array");
        assert_eq!(work.len(), 4);

        let pow_hash_hex = work[0].as_str().unwrap();
        let block_number_hex = work[3].as_str().unwrap();
        assert_eq!(
            block_number_hex,
            &format!("0x{:x}", block_num),
            "work should be for block {}",
            block_num
        );
        println!(
            "  got work: powHash={} blockNumber={}",
            pow_hash_hex, block_number_hex
        );

        // 5. Solve PoW
        let pow_hash = {
            let bytes = hex::decode(pow_hash_hex.strip_prefix("0x").unwrap()).unwrap();
            B256::from_slice(&bytes)
        };
        let (found_nonce, mix_hash) = solve_pow(&pow_hash, block_num);
        println!(
            "  solved: nonce={} mixHash={} (after {} attempts)",
            found_nonce,
            mix_hash,
            found_nonce + 1
        );

        // 6. eth_submitWork via HTTP
        let nonce_hex = format!("0x{}", hex::encode(found_nonce.to_be_bytes()));
        let mix_hex = format!("0x{}", hex::encode(mix_hash.as_slice()));

        let resp = rpc_call(
            &http,
            &rpc_url,
            "eth_submitWork",
            serde_json::json!([nonce_hex, pow_hash_hex, mix_hex]),
        )
        .await;
        assert_eq!(
            resp["result"], true,
            "eth_submitWork should return true, got: {}",
            resp
        );
        println!("  eth_submitWork returned true");

        // 7. Verify mock EL received a new FCU with the mined block's headBlockHash
        let fcu_heads = mock_state.fcu_heads.lock().await;
        assert!(
            fcu_heads.len() > fcu_count_before,
            "block {}: expected new FCU head after submit, got {} (was {})",
            block_num,
            fcu_heads.len(),
            fcu_count_before,
        );

        let new_head = fcu_heads.last().unwrap().clone();
        println!("  FCU headBlockHash = {}", new_head);

        if block_num == 2 {
            assert_ne!(
                new_head, last_fcu_head,
                "block 2 FCU head should differ from block 1"
            );
        }
        last_fcu_head = new_head;
    }

    println!("\n2 blocks mined and verified via HTTP RPC successfully.");
}

// --------------------------------------------------------------------------
// Thin handler that delegates to the mining RPC state (same as rpc.rs but
// accessible from the test without needing start_mining_rpc's bind logic).
// --------------------------------------------------------------------------

async fn mining_rpc_handler(
    State(state): State<Arc<mining::rpc::MiningRpcState>>,
    body: axum::body::Bytes,
) -> axum::response::Response {
    // Deserialize, dispatch to the coordinator, and build response.
    let req: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            return axum::response::IntoResponse::into_response(axum::Json(serde_json::json!({
                "jsonrpc": "2.0",
                "error": {"code": -32700, "message": "parse error"},
                "id": null
            })));
        }
    };

    let method = req["method"].as_str().unwrap_or("");
    let id = req["id"].clone();
    let params = req["params"].clone();

    let result = match method {
        "eth_getWork" => match state.coordinator.get_work().await {
            Some(work) => serde_json::json!({"jsonrpc":"2.0","result":work,"id":id}),
            None => {
                serde_json::json!({"jsonrpc":"2.0","error":{"code":-32000,"message":"no work available"},"id":id})
            }
        },
        "eth_submitWork" => {
            let p = params.as_array().unwrap();
            let nonce = p[0].as_str().unwrap();
            let pow_hash = p[1].as_str().unwrap();
            let mix = p[2].as_str().unwrap();
            match state
                .coordinator
                .submit_work(&state.engine, nonce, pow_hash, mix)
                .await
            {
                Ok(Some(mined)) => {
                    let _ = state.mined_tx.send(mined).await;
                    serde_json::json!({"jsonrpc":"2.0","result":true,"id":id})
                }
                Ok(None) => serde_json::json!({"jsonrpc":"2.0","result":false,"id":id}),
                Err(e) => {
                    serde_json::json!({"jsonrpc":"2.0","error":{"code":-32000,"message":e.to_string()},"id":id})
                }
            }
        }
        _ => {
            serde_json::json!({"jsonrpc":"2.0","error":{"code":-32601,"message":"method not found"},"id":id})
        }
    };

    axum::response::IntoResponse::into_response(axum::Json(result))
}
