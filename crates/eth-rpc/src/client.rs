use alloy_primitives::B256;
use serde_json::json;
use thiserror::Error;
use tracing::debug;

use crate::types::{EthBlock, EthBlockFull, EthReceipt};

#[derive(Error, Debug)]
pub enum EthRpcError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON-RPC error {code}: {message}")]
    Rpc { code: i64, message: String },
    #[error("null result from RPC call")]
    NullResult,
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Client for the standard Ethereum JSON-RPC (eth namespace).
pub struct EthClient {
    url: String,
    http: reqwest::Client,
}

impl EthClient {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// Get the latest block number via `eth_blockNumber`.
    pub async fn get_block_number(&self) -> Result<u64, EthRpcError> {
        let body = json!({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 1
        });

        let resp: serde_json::Value = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        if let Some(err) = resp.get("error") {
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            let message = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error")
                .to_string();
            return Err(EthRpcError::Rpc { code, message });
        }

        let result = resp.get("result").ok_or(EthRpcError::NullResult)?;
        let hex_str = result.as_str().ok_or(EthRpcError::NullResult)?;
        let num = u64::from_str_radix(hex_str.trim_start_matches("0x"), 16).map_err(|e| {
            EthRpcError::Rpc {
                code: -1,
                message: format!("bad hex: {}", e),
            }
        })?;
        Ok(num)
    }

    /// Fetch a block by number via `eth_getBlockByNumber`.
    /// Returns full block header fields (transactions=false).
    pub async fn get_block_by_number(&self, number: u64) -> Result<EthBlock, EthRpcError> {
        let block_num = format!("0x{:x}", number);
        let body = json!({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByNumber",
            "params": [block_num, false],
            "id": 1
        });

        debug!(
            method = "eth_getBlockByNumber",
            number, "sending eth RPC request"
        );

        let resp: serde_json::Value = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        if let Some(err) = resp.get("error") {
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            let message = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error")
                .to_string();
            return Err(EthRpcError::Rpc { code, message });
        }

        let result = resp.get("result").ok_or(EthRpcError::NullResult)?;
        if result.is_null() {
            return Err(EthRpcError::NullResult);
        }

        let block: EthBlock = serde_json::from_value(result.clone())?;
        Ok(block)
    }

    /// Fetch a block by hash via `eth_getBlockByHash`.
    /// Returns full block header fields (transactions=false).
    pub async fn get_block_by_hash(&self, hash: B256) -> Result<EthBlock, EthRpcError> {
        let hash_hex = format!("0x{:x}", hash);
        let body = json!({
            "jsonrpc": "2.0",
            "method": "eth_getBlockByHash",
            "params": [hash_hex, false],
            "id": 1
        });

        debug!(method = "eth_getBlockByHash", hash = %hash_hex, "sending eth RPC request");

        let resp: serde_json::Value = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await?
            .json()
            .await?;

        if let Some(err) = resp.get("error") {
            let code = err.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            let message = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown error")
                .to_string();
            return Err(EthRpcError::Rpc { code, message });
        }

        let result = resp.get("result").ok_or(EthRpcError::NullResult)?;
        if result.is_null() {
            return Err(EthRpcError::NullResult);
        }

        let block: EthBlock = serde_json::from_value(result.clone())?;
        Ok(block)
    }

    /// Send a batch of JSON-RPC requests in a single HTTP call.
    /// Returns results in the same order as requests.
    async fn batch_call(
        &self,
        requests: Vec<serde_json::Value>,
    ) -> Result<Vec<serde_json::Value>, EthRpcError> {
        if requests.is_empty() {
            return Ok(vec![]);
        }

        let resp: Vec<serde_json::Value> = self
            .http
            .post(&self.url)
            .json(&requests)
            .send()
            .await?
            .json()
            .await?;

        // go-ethereum returns results in the same order as requests,
        // but let's sort by id to be safe.
        let mut by_id: std::collections::HashMap<u64, serde_json::Value> =
            std::collections::HashMap::new();
        for item in resp {
            if let Some(id) = item.get("id").and_then(|v| v.as_u64()) {
                by_id.insert(id, item);
            }
        }

        let mut results = Vec::with_capacity(requests.len());
        for req in &requests {
            let id = req.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
            if let Some(item) = by_id.remove(&id) {
                results.push(item);
            } else {
                results.push(json!({"error": {"code": -1, "message": "missing response"}}));
            }
        }

        Ok(results)
    }

    /// Fetch multiple blocks by number (batch, transactions=false).
    pub async fn get_blocks_by_numbers(
        &self,
        numbers: &[u64],
    ) -> Result<Vec<Option<EthBlock>>, EthRpcError> {
        let requests: Vec<serde_json::Value> = numbers
            .iter()
            .enumerate()
            .map(|(i, num)| {
                json!({
                    "jsonrpc": "2.0",
                    "method": "eth_getBlockByNumber",
                    "params": [format!("0x{:x}", num), false],
                    "id": i + 1
                })
            })
            .collect();

        let responses = self.batch_call(requests).await?;
        let mut blocks = Vec::with_capacity(numbers.len());

        for resp in responses {
            if resp.get("error").is_some() {
                blocks.push(None);
                continue;
            }
            let result = resp.get("result");
            match result {
                Some(v) if !v.is_null() => {
                    let block: EthBlock = serde_json::from_value(v.clone())?;
                    blocks.push(Some(block));
                }
                _ => blocks.push(None),
            }
        }

        Ok(blocks)
    }

    /// Fetch multiple blocks by hash (batch, transactions=false).
    pub async fn get_blocks_by_hashes(
        &self,
        hashes: &[B256],
    ) -> Result<Vec<Option<EthBlock>>, EthRpcError> {
        let requests: Vec<serde_json::Value> = hashes
            .iter()
            .enumerate()
            .map(|(i, hash)| {
                json!({
                    "jsonrpc": "2.0",
                    "method": "eth_getBlockByHash",
                    "params": [format!("0x{:x}", hash), false],
                    "id": i + 1
                })
            })
            .collect();

        let responses = self.batch_call(requests).await?;
        let mut blocks = Vec::with_capacity(hashes.len());

        for resp in responses {
            if resp.get("error").is_some() {
                blocks.push(None);
                continue;
            }
            let result = resp.get("result");
            match result {
                Some(v) if !v.is_null() => {
                    let block: EthBlock = serde_json::from_value(v.clone())?;
                    blocks.push(Some(block));
                }
                _ => blocks.push(None),
            }
        }

        Ok(blocks)
    }

    /// Fetch multiple blocks by hash with full tx data (batch).
    pub async fn get_full_blocks_by_hashes(
        &self,
        hashes: &[B256],
    ) -> Result<Vec<Option<EthBlockFull>>, EthRpcError> {
        let requests: Vec<serde_json::Value> = hashes
            .iter()
            .enumerate()
            .map(|(i, hash)| {
                json!({
                    "jsonrpc": "2.0",
                    "method": "eth_getBlockByHash",
                    "params": [format!("0x{:x}", hash), true],
                    "id": i + 1
                })
            })
            .collect();

        let responses = self.batch_call(requests).await?;
        let mut blocks = Vec::with_capacity(hashes.len());

        for resp in responses {
            if resp.get("error").is_some() {
                blocks.push(None);
                continue;
            }
            let result = resp.get("result");
            match result {
                Some(v) if !v.is_null() => {
                    let block: EthBlockFull = serde_json::from_value(v.clone())?;
                    blocks.push(Some(block));
                }
                _ => blocks.push(None),
            }
        }

        Ok(blocks)
    }

    /// Fetch uncles for a block identified by hash.
    pub async fn get_uncles_for_block_hash(
        &self,
        block_hash: alloy_primitives::B256,
        uncle_count: usize,
    ) -> Result<Vec<Option<EthBlock>>, EthRpcError> {
        if uncle_count == 0 {
            return Ok(vec![]);
        }

        let hash_hex = format!("0x{}", hex::encode(block_hash.as_slice()));
        let requests: Vec<serde_json::Value> = (0..uncle_count)
            .enumerate()
            .map(|(i, idx)| {
                json!({
                    "jsonrpc": "2.0",
                    "method": "eth_getUncleByBlockHashAndIndex",
                    "params": [&hash_hex, format!("0x{:x}", idx)],
                    "id": i + 1
                })
            })
            .collect();

        let responses = self.batch_call(requests).await?;
        let mut uncles = Vec::with_capacity(uncle_count);

        for resp in responses {
            if resp.get("error").is_some() {
                uncles.push(None);
                continue;
            }
            let result = resp.get("result");
            match result {
                Some(v) if !v.is_null() => {
                    let uncle: EthBlock = serde_json::from_value(v.clone())?;
                    uncles.push(Some(uncle));
                }
                _ => uncles.push(None),
            }
        }

        Ok(uncles)
    }

    /// Batch-fetch receipts for multiple blocks identified by hash.
    pub async fn get_block_receipts_batch_by_hashes(
        &self,
        hashes: &[alloy_primitives::B256],
    ) -> Result<Vec<Option<Vec<EthReceipt>>>, EthRpcError> {
        let requests: Vec<serde_json::Value> = hashes
            .iter()
            .enumerate()
            .map(|(i, hash)| {
                json!({
                    "jsonrpc": "2.0",
                    "method": "eth_getBlockReceipts",
                    "params": [format!("0x{}", hex::encode(hash.as_slice()))],
                    "id": i + 1
                })
            })
            .collect();

        let responses = self.batch_call(requests).await?;
        let mut results = Vec::with_capacity(hashes.len());

        for resp in responses {
            if resp.get("error").is_some() {
                results.push(None);
                continue;
            }
            let result = resp.get("result");
            match result {
                Some(v) if !v.is_null() => {
                    let receipts: Vec<EthReceipt> = serde_json::from_value(v.clone())?;
                    results.push(Some(receipts));
                }
                _ => results.push(None),
            }
        }

        Ok(results)
    }
}
