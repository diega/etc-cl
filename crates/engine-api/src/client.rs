use crate::auth;
use crate::types::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("auth error: {0}")]
    Auth(#[from] auth::AuthError),
    #[error("JSON-RPC error {code}: {message}")]
    Rpc { code: i64, message: String },
    #[error("unexpected response: {0}")]
    Unexpected(String),
}

/// JSON-RPC 2.0 request.
#[derive(Debug, Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'a str,
    method: &'a str,
    params: serde_json::Value,
    id: u64,
}

/// JSON-RPC 2.0 response (unknown fields ignored via default serde behavior).
#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    result: Option<serde_json::Value>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

/// HTTP timeout for Engine API requests (seconds).
const ENGINE_HTTP_TIMEOUT_SECS: u64 = 8;

/// Engine API client for communicating with the Execution Layer.
pub struct EngineClient {
    endpoint: String,
    secret: Vec<u8>,
    http: reqwest::Client,
    next_id: std::sync::atomic::AtomicU64,
}

impl EngineClient {
    /// Create a new Engine API client.
    pub fn new(endpoint: &str, secret: Vec<u8>) -> Result<Self, ClientError> {
        Ok(Self {
            endpoint: endpoint.to_string(),
            secret,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(ENGINE_HTTP_TIMEOUT_SECS))
                .build()?,
            next_id: std::sync::atomic::AtomicU64::new(1),
        })
    }

    /// Get the next request ID.
    fn next_id(&self) -> u64 {
        self.next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Make a JSON-RPC call to the Engine API.
    async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, ClientError> {
        let token = auth::create_token(&self.secret)?;
        let id = self.next_id();

        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            method,
            params,
            id,
        };

        debug!(method, id, "engine API call");

        let response = self
            .http
            .post(&self.endpoint)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await?;

        let rpc_response: JsonRpcResponse = response.json().await?;

        if let Some(err) = rpc_response.error {
            warn!(method, code = err.code, msg = %err.message, "engine API error");
            return Err(ClientError::Rpc {
                code: err.code,
                message: err.message,
            });
        }

        rpc_response
            .result
            .ok_or_else(|| ClientError::Unexpected("no result in response".to_string()))
    }

    /// Exchange capabilities with the EL.
    /// Returns the capabilities supported by the EL.
    pub async fn exchange_capabilities(
        &self,
        cl_capabilities: &[&str],
    ) -> Result<Vec<String>, ClientError> {
        let params = serde_json::json!([cl_capabilities]);
        let result = self.call("engine_exchangeCapabilities", params).await?;
        let caps: Vec<String> =
            serde_json::from_value(result).map_err(|e| ClientError::Unexpected(e.to_string()))?;
        info!(count = caps.len(), "exchanged capabilities with EL");

        // Verify the EL supports required methods
        let required = [
            "engine_newPayloadV2",
            "engine_forkchoiceUpdatedV2",
            "engine_getPayloadV2",
        ];
        for method in &required {
            if !caps.iter().any(|c| c == method) {
                warn!(method, "EL does not advertise required capability");
            }
        }

        Ok(caps)
    }

    /// Submit a new payload to the EL for execution (V2).
    pub async fn new_payload_v2(
        &self,
        payload: &ExecutionPayload,
    ) -> Result<PayloadStatus, ClientError> {
        let params = serde_json::json!([payload]);
        let result = self.call("engine_newPayloadV2", params).await?;
        let status: PayloadStatus =
            serde_json::from_value(result).map_err(|e| ClientError::Unexpected(e.to_string()))?;
        debug!(status = %status.status, "newPayloadV2 response");
        Ok(status)
    }

    /// Update fork choice and optionally start building a new payload (V2).
    pub async fn forkchoice_updated_v2(
        &self,
        state: &ForkchoiceState,
        payload_attributes: Option<&PayloadAttributes>,
    ) -> Result<ForkChoiceResponse, ClientError> {
        let params = serde_json::json!([state, payload_attributes]);
        let result = self.call("engine_forkchoiceUpdatedV2", params).await?;
        let response: ForkChoiceResponse =
            serde_json::from_value(result).map_err(|e| ClientError::Unexpected(e.to_string()))?;
        debug!(status = %response.payload_status.status, "forkchoiceUpdatedV2 response");
        Ok(response)
    }

    /// Get the EL network identity and current fork ID (EIP-2124).
    pub async fn get_status_info(&self) -> Result<StatusInfoResponse, ClientError> {
        let params = serde_json::json!([]);
        let result = self.call("engine_getStatusInfoV1", params).await?;
        let info: StatusInfoResponse =
            serde_json::from_value(result).map_err(|e| ClientError::Unexpected(e.to_string()))?;
        info!(
            network_id = info.network_id,
            genesis_hash = %hex::encode(info.genesis_hash.as_slice()),
            fork_hash = %hex::encode(&info.hash),
            fork_next = info.next,
            fork_blocks = ?info.fork_blocks,
            "getStatusInfoV1 response"
        );
        Ok(info)
    }

    /// Send a batch of JSON-RPC requests in a single HTTP call.
    /// Returns results in the same order as requests.
    async fn batch_call(
        &self,
        requests: Vec<serde_json::Value>,
    ) -> Result<Vec<serde_json::Value>, ClientError> {
        if requests.is_empty() {
            return Ok(vec![]);
        }

        let token = auth::create_token(&self.secret)?;

        let response = self
            .http
            .post(&self.endpoint)
            .header("Authorization", format!("Bearer {}", token))
            .header("Content-Type", "application/json")
            .json(&requests)
            .send()
            .await?;

        let resp: Vec<serde_json::Value> = response.json().await?;

        // Sort by id to match request order.
        let mut by_id: std::collections::HashMap<u64, serde_json::Value> =
            std::collections::HashMap::new();
        for item in resp {
            if let Some(id) = item.get("id").and_then(|v| v.as_u64()) {
                by_id.insert(id, item);
            } else {
                warn!("batch response item has no 'id' field, skipping");
            }
        }

        let mut results = Vec::with_capacity(requests.len());
        for req in &requests {
            let id = match req.get("id").and_then(|v| v.as_u64()) {
                Some(id) => id,
                None => {
                    warn!("batch request missing 'id' field");
                    results.push(
                        serde_json::json!({"error": {"code": -1, "message": "missing request id"}}),
                    );
                    continue;
                }
            };
            if let Some(item) = by_id.remove(&id) {
                results.push(item);
            } else {
                results.push(
                    serde_json::json!({"error": {"code": -1, "message": "missing response"}}),
                );
            }
        }

        Ok(results)
    }

    /// Submit multiple payloads to the EL in a single HTTP batch request.
    /// Returns a PayloadStatus for each payload, in order.
    pub async fn new_payload_v2_batch(
        &self,
        payloads: &[&ExecutionPayload],
    ) -> Result<Vec<PayloadStatus>, ClientError> {
        let requests: Vec<serde_json::Value> = payloads
            .iter()
            .map(|payload| {
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "engine_newPayloadV2",
                    "params": [payload],
                    "id": self.next_id()
                })
            })
            .collect();

        debug!(count = requests.len(), "engine API batch newPayloadV2");

        let responses = self.batch_call(requests).await?;
        let mut statuses = Vec::with_capacity(responses.len());

        for mut resp in responses {
            if let Some(err) = resp.get("error") {
                let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
                let message = err
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown error")
                    .to_string();
                return Err(ClientError::Rpc { code, message });
            }

            let result = resp
                .get_mut("result")
                .map(serde_json::Value::take)
                .ok_or_else(|| {
                    ClientError::Unexpected("no result in batch response".to_string())
                })?;
            let status: PayloadStatus = serde_json::from_value(result)
                .map_err(|e| ClientError::Unexpected(e.to_string()))?;
            statuses.push(status);
        }

        Ok(statuses)
    }

    /// Get a previously requested payload from the EL (V2).
    pub async fn get_payload_v2(
        &self,
        payload_id: &str,
    ) -> Result<ExecutionPayloadEnvelope, ClientError> {
        let params = serde_json::json!([payload_id]);
        let result = self.call("engine_getPayloadV2", params).await?;
        let envelope: ExecutionPayloadEnvelope =
            serde_json::from_value(result).map_err(|e| ClientError::Unexpected(e.to_string()))?;
        debug!(
            block_number = envelope.execution_payload.block_number,
            "getPayloadV2 response"
        );
        Ok(envelope)
    }
}
