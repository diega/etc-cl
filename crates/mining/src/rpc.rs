use std::sync::Arc;

use axum::{extract::State, routing::post, Json, Router};
use engine_api::client::EngineClient;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use crate::{MinedBlock, MiningCoordinator};

/// Shared state for the mining RPC server.
pub struct MiningRpcState {
    pub coordinator: Arc<MiningCoordinator>,
    pub engine: Arc<EngineClient>,
    pub mined_tx: mpsc::Sender<MinedBlock>,
}

#[derive(Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
    id: serde_json::Value,
}

#[derive(Serialize)]
struct JsonRpcResponse {
    jsonrpc: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
    id: serde_json::Value,
}

#[derive(Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

impl JsonRpcResponse {
    fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0",
            result: Some(result),
            error: None,
            id,
        }
    }

    fn error(id: serde_json::Value, code: i64, message: String) -> Self {
        Self {
            jsonrpc: "2.0",
            result: None,
            error: Some(JsonRpcError { code, message }),
            id,
        }
    }
}

async fn handle_rpc(
    State(state): State<Arc<MiningRpcState>>,
    Json(req): Json<JsonRpcRequest>,
) -> Json<JsonRpcResponse> {
    if req.jsonrpc != "2.0" {
        return Json(JsonRpcResponse::error(
            req.id,
            -32600,
            "invalid JSON-RPC version".into(),
        ));
    }

    debug!(method = %req.method, "mining RPC request");

    match req.method.as_str() {
        "eth_getWork" => handle_get_work(&state, req.id).await,
        "eth_submitWork" => handle_submit_work(&state, req.id, req.params).await,
        "eth_submitHashrate" => handle_submit_hashrate(&state, req.id, req.params).await,
        "eth_hashrate" => handle_hashrate(&state, req.id).await,
        _ => {
            warn!(method = %req.method, "unknown mining RPC method");
            Json(JsonRpcResponse::error(
                req.id,
                -32601,
                format!("method not found: {}", req.method),
            ))
        }
    }
}

async fn handle_get_work(state: &MiningRpcState, id: serde_json::Value) -> Json<JsonRpcResponse> {
    match state.coordinator.get_work().await {
        Some(work) => Json(JsonRpcResponse::success(id, serde_json::json!(work))),
        None => Json(JsonRpcResponse::error(
            id,
            -32000,
            "no work available".into(),
        )),
    }
}

async fn handle_submit_work(
    state: &MiningRpcState,
    id: serde_json::Value,
    params: serde_json::Value,
) -> Json<JsonRpcResponse> {
    let params = match params.as_array() {
        Some(p) if p.len() >= 3 => p,
        _ => {
            return Json(JsonRpcResponse::error(
                id,
                -32602,
                "expected 3 params: [nonce, powHash, mixDigest]".into(),
            ));
        }
    };

    let nonce = match params[0].as_str() {
        Some(s) => s,
        None => {
            return Json(JsonRpcResponse::error(
                id,
                -32602,
                "nonce must be a string".into(),
            ));
        }
    };
    let pow_hash = match params[1].as_str() {
        Some(s) => s,
        None => {
            return Json(JsonRpcResponse::error(
                id,
                -32602,
                "powHash must be a string".into(),
            ));
        }
    };
    let mix_digest = match params[2].as_str() {
        Some(s) => s,
        None => {
            return Json(JsonRpcResponse::error(
                id,
                -32602,
                "mixDigest must be a string".into(),
            ));
        }
    };

    match state
        .coordinator
        .submit_work(&state.engine, nonce, pow_hash, mix_digest)
        .await
    {
        Ok(Some(mined_block)) => {
            // Notify the node about the mined block.
            if let Err(e) = state.mined_tx.send(mined_block).await {
                error!(err = %e, "failed to send mined block notification");
            }
            Json(JsonRpcResponse::success(id, serde_json::json!(true)))
        }
        Ok(None) => Json(JsonRpcResponse::success(id, serde_json::json!(false))),
        Err(e) => {
            error!(err = %e, "submit_work failed");
            Json(JsonRpcResponse::error(id, -32000, e.to_string()))
        }
    }
}

async fn handle_submit_hashrate(
    state: &MiningRpcState,
    id: serde_json::Value,
    params: serde_json::Value,
) -> Json<JsonRpcResponse> {
    let params = match params.as_array() {
        Some(p) if p.len() >= 2 => p,
        _ => {
            return Json(JsonRpcResponse::error(
                id,
                -32602,
                "expected 2 params: [rate, id]".into(),
            ));
        }
    };

    let rate_str = match params[0].as_str() {
        Some(s) => s,
        None => {
            return Json(JsonRpcResponse::error(
                id,
                -32602,
                "rate must be a hex string".into(),
            ));
        }
    };
    let miner_id = match params[1].as_str() {
        Some(s) => s.to_string(),
        None => {
            return Json(JsonRpcResponse::error(
                id,
                -32602,
                "id must be a string".into(),
            ));
        }
    };

    let rate_str = rate_str.strip_prefix("0x").unwrap_or(rate_str);
    let rate = match u64::from_str_radix(rate_str, 16) {
        Ok(r) => r,
        Err(_) => {
            return Json(JsonRpcResponse::error(
                id,
                -32602,
                format!("invalid hashrate hex: {}", rate_str),
            ));
        }
    };

    state.coordinator.submit_hashrate(rate, miner_id).await;

    Json(JsonRpcResponse::success(id, serde_json::json!(true)))
}

async fn handle_hashrate(state: &MiningRpcState, id: serde_json::Value) -> Json<JsonRpcResponse> {
    let rate = state.coordinator.hashrate().await;
    Json(JsonRpcResponse::success(
        id,
        serde_json::json!(format!("0x{:x}", rate)),
    ))
}

/// Start the mining JSON-RPC server.
pub async fn start_mining_rpc(
    coordinator: Arc<MiningCoordinator>,
    engine: Arc<EngineClient>,
    mined_tx: mpsc::Sender<MinedBlock>,
    bind_addr: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let state = Arc::new(MiningRpcState {
        coordinator,
        engine,
        mined_tx,
    });

    let app = Router::new().route("/", post(handle_rpc)).with_state(state);

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    tracing::info!(addr = %bind_addr, "mining RPC server started");

    axum::serve(listener, app).await?;
    Ok(())
}
