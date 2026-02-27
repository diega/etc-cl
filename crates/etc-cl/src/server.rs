use std::sync::Arc;

use alloy_primitives::B256;
use devp2p::eth::{self, BlockBodiesRequest, BlockHeadersRequest, HeaderStart, ReceiptsRequest};
use devp2p::peer_manager::{PeerCommand, PeerManager};
use eth_rpc::EthClient;
use tokio::time::{timeout, Duration};
use tracing::{debug, warn};

use chain::types::rlp_encode_list_from_encoded;

/// Maximum number of headers we serve per request.
const MAX_HEADERS_SERVE: u64 = 1024;
/// Maximum number of bodies we serve per request.
const MAX_BODIES_SERVE: usize = 1024;
/// Maximum number of receipt sets we serve per request.
const MAX_RECEIPTS_SERVE: usize = 256;
/// Timeout for EL RPC calls when serving peers.
const EL_RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// Serve a GetBlockHeaders request by fetching data from the EL.
pub async fn serve_block_headers(
    pm: Arc<PeerManager>,
    eth: Arc<EthClient>,
    node_id: [u8; 64],
    request: BlockHeadersRequest,
) {
    let request_id = request.request_id;
    let msg_id = eth::ETH_MSG_OFFSET + eth::BLOCK_HEADERS_MSG_ID;

    // Cap limit
    let limit = request.limit.min(MAX_HEADERS_SERVE);

    if limit == 0 {
        let payload = eth::encode_block_headers_response(request_id, &[]);
        pm.send_command(
            &node_id,
            PeerCommand::SendRaw {
                msg_id,
                payload: Arc::new(payload),
            },
        )
        .await;
        return;
    }

    // Resolve start: for ByHash, fetch the exact block first to get its number
    // and use its header as the first result (not the canonical at that height).
    let (start_number, first_header_rlp) = match request.start {
        HeaderStart::ByNumber(n) => (n, None),
        HeaderStart::ByHash(hash) => {
            let h = B256::from_slice(&hash);
            match timeout(EL_RPC_TIMEOUT, eth.get_block_by_hash(h)).await {
                Ok(Ok(block)) => {
                    let header_rlp = block.to_block_header().rlp_encode();
                    (block.number, Some(header_rlp))
                }
                Ok(Err(e)) => {
                    debug!(err = %e, "failed to resolve block hash for GetBlockHeaders");
                    let payload = eth::encode_block_headers_response(request_id, &[]);
                    pm.send_command(
                        &node_id,
                        PeerCommand::SendRaw {
                            msg_id,
                            payload: Arc::new(payload),
                        },
                    )
                    .await;
                    return;
                }
                Err(_) => {
                    warn!("EL RPC timeout resolving block hash for GetBlockHeaders");
                    let payload = eth::encode_block_headers_response(request_id, &[]);
                    pm.send_command(
                        &node_id,
                        PeerCommand::SendRaw {
                            msg_id,
                            payload: Arc::new(payload),
                        },
                    )
                    .await;
                    return;
                }
            }
        }
    };

    // Calculate block numbers to fetch (skip the first if we already have it from ByHash)
    let step = request.skip.saturating_add(1);
    let remaining_start = if first_header_rlp.is_some() { 1 } else { 0 };
    let numbers: Vec<u64> = (remaining_start..limit)
        .filter_map(|i| {
            i.checked_mul(step).and_then(|offset| {
                if request.reverse {
                    start_number.checked_sub(offset)
                } else {
                    start_number.checked_add(offset)
                }
            })
        })
        .collect();

    // Start with the ByHash header if we have one
    let mut headers_rlp: Vec<Vec<u8>> = Vec::with_capacity(limit as usize);
    if let Some(first) = first_header_rlp {
        headers_rlp.push(first);
    }

    if !numbers.is_empty() {
        // Batch fetch remaining from EL
        let blocks = match timeout(EL_RPC_TIMEOUT, eth.get_blocks_by_numbers(&numbers)).await {
            Ok(Ok(b)) => b,
            Ok(Err(e)) => {
                warn!(err = %e, "batch get_blocks_by_numbers failed for GetBlockHeaders");
                if headers_rlp.is_empty() {
                    let payload = eth::encode_block_headers_response(request_id, &[]);
                    pm.send_command(
                        &node_id,
                        PeerCommand::SendRaw {
                            msg_id,
                            payload: Arc::new(payload),
                        },
                    )
                    .await;
                    return;
                }
                // Return what we have (the ByHash header)
                vec![]
            }
            Err(_) => {
                warn!("EL RPC timeout for GetBlockHeaders batch fetch");
                if headers_rlp.is_empty() {
                    let payload = eth::encode_block_headers_response(request_id, &[]);
                    pm.send_command(
                        &node_id,
                        PeerCommand::SendRaw {
                            msg_id,
                            payload: Arc::new(payload),
                        },
                    )
                    .await;
                    return;
                }
                vec![]
            }
        };

        // Encode headers to RLP — stop at first missing block
        for block in &blocks {
            match block {
                Some(b) => headers_rlp.push(b.to_block_header().rlp_encode()),
                None => break,
            }
        }
    }

    debug!(
        count = headers_rlp.len(),
        node_id = %hex::encode(&node_id[..8]),
        "serving block headers to peer"
    );

    let payload = eth::encode_block_headers_response(request_id, &headers_rlp);
    pm.send_command(
        &node_id,
        PeerCommand::SendRaw {
            msg_id,
            payload: Arc::new(payload),
        },
    )
    .await;
}

/// Serve a GetBlockBodies request by fetching data from the EL.
pub async fn serve_block_bodies(
    pm: Arc<PeerManager>,
    eth: Arc<EthClient>,
    node_id: [u8; 64],
    request: BlockBodiesRequest,
) {
    let request_id = request.request_id;
    let msg_id = eth::ETH_MSG_OFFSET + eth::BLOCK_BODIES_MSG_ID;

    // Cap the number of hashes
    let hashes: Vec<[u8; 32]> = if request.hashes.len() > MAX_BODIES_SERVE {
        request.hashes[..MAX_BODIES_SERVE].to_vec()
    } else {
        request.hashes
    };

    if hashes.is_empty() {
        let payload = eth::encode_block_bodies_response(request_id, &[]);
        pm.send_command(
            &node_id,
            PeerCommand::SendRaw {
                msg_id,
                payload: Arc::new(payload),
            },
        )
        .await;
        return;
    }

    // Convert hashes to B256 for the RPC call
    let b256_hashes: Vec<B256> = hashes.iter().map(|h| B256::from_slice(h)).collect();

    // Batch fetch blocks by hash (with full tx data)
    let blocks = match timeout(EL_RPC_TIMEOUT, eth.get_full_blocks_by_hashes(&b256_hashes)).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            warn!(err = %e, "batch get_full_blocks_by_hashes failed for GetBlockBodies");
            let payload = eth::encode_block_bodies_response(request_id, &[]);
            pm.send_command(
                &node_id,
                PeerCommand::SendRaw {
                    msg_id,
                    payload: Arc::new(payload),
                },
            )
            .await;
            return;
        }
        Err(_) => {
            warn!("EL RPC timeout for GetBlockBodies batch fetch");
            let payload = eth::encode_block_bodies_response(request_id, &[]);
            pm.send_command(
                &node_id,
                PeerCommand::SendRaw {
                    msg_id,
                    payload: Arc::new(payload),
                },
            )
            .await;
            return;
        }
    };

    // Encode bodies — stop at first missing block
    let mut bodies_rlp: Vec<Vec<u8>> = Vec::with_capacity(blocks.len());
    for block in &blocks {
        match block {
            Some(b) => {
                // Encode transactions
                let txs_encoded: Vec<Vec<u8>> =
                    b.transactions.iter().map(|tx| tx.rlp_encode()).collect();

                // Encode uncles — fetch by block hash (not number) to handle non-canonical blocks
                let block_hash = B256::from_slice(&hashes[bodies_rlp.len()]);
                let uncles_encoded = if b.uncle_hashes.is_empty() {
                    vec![]
                } else {
                    match timeout(
                        EL_RPC_TIMEOUT,
                        eth.get_uncles_for_block_hash(block_hash, b.uncle_hashes.len()),
                    )
                    .await
                    {
                        Ok(Ok(uncles)) => {
                            let encoded: Vec<Vec<u8>> = uncles
                                .iter()
                                .filter_map(|u| {
                                    u.as_ref().map(|ub| ub.to_block_header().rlp_encode())
                                })
                                .collect();
                            if encoded.len() != b.uncle_hashes.len() {
                                debug!(
                                    block = b.number,
                                    expected = b.uncle_hashes.len(),
                                    got = encoded.len(),
                                    "incomplete uncle data, stopping body response"
                                );
                                break;
                            }
                            encoded
                        }
                        Ok(Err(e)) => {
                            debug!(err = %e, block = b.number, "failed to fetch uncles, stopping body response");
                            break;
                        }
                        Err(_) => {
                            debug!(
                                block = b.number,
                                "EL RPC timeout fetching uncles, stopping body response"
                            );
                            break;
                        }
                    }
                };

                // Body = [txs_list, uncles_list]
                let body = encode_body_rlp(&txs_encoded, &uncles_encoded);
                bodies_rlp.push(body);
            }
            None => break,
        }
    }

    debug!(
        count = bodies_rlp.len(),
        node_id = %hex::encode(&node_id[..8]),
        "serving block bodies to peer"
    );

    let payload = eth::encode_block_bodies_response(request_id, &bodies_rlp);
    pm.send_command(
        &node_id,
        PeerCommand::SendRaw {
            msg_id,
            payload: Arc::new(payload),
        },
    )
    .await;
}

/// Serve a GetReceipts request by fetching data from the EL.
pub async fn serve_receipts(
    pm: Arc<PeerManager>,
    eth: Arc<EthClient>,
    node_id: [u8; 64],
    request: ReceiptsRequest,
) {
    let request_id = request.request_id;
    let msg_id = eth::ETH_MSG_OFFSET + eth::RECEIPTS_MSG_ID;

    // Cap the number of hashes
    let hashes: Vec<[u8; 32]> = if request.hashes.len() > MAX_RECEIPTS_SERVE {
        request.hashes[..MAX_RECEIPTS_SERVE].to_vec()
    } else {
        request.hashes
    };

    if hashes.is_empty() {
        let payload = eth::encode_receipts_response(request_id, &[]);
        pm.send_command(
            &node_id,
            PeerCommand::SendRaw {
                msg_id,
                payload: Arc::new(payload),
            },
        )
        .await;
        return;
    }

    // Fetch receipts directly by hash (avoids hash→number→canonical mismatch)
    let b256_hashes: Vec<B256> = hashes.iter().map(|h| B256::from_slice(h)).collect();

    // We also need block numbers for receipt RLP encoding (tx type prefix depends on fork).
    // Fetch blocks by hash to get their numbers.
    let blocks = match timeout(EL_RPC_TIMEOUT, eth.get_blocks_by_hashes(&b256_hashes)).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            warn!(err = %e, "batch get_blocks_by_hashes failed for GetReceipts");
            let payload = eth::encode_receipts_response(request_id, &[]);
            pm.send_command(
                &node_id,
                PeerCommand::SendRaw {
                    msg_id,
                    payload: Arc::new(payload),
                },
            )
            .await;
            return;
        }
        Err(_) => {
            warn!("EL RPC timeout for GetReceipts hash resolution");
            let payload = eth::encode_receipts_response(request_id, &[]);
            pm.send_command(
                &node_id,
                PeerCommand::SendRaw {
                    msg_id,
                    payload: Arc::new(payload),
                },
            )
            .await;
            return;
        }
    };

    // Collect (hash, number) pairs — stop at first missing
    let mut hash_number_pairs: Vec<(B256, u64)> = Vec::with_capacity(blocks.len());
    for (i, block) in blocks.iter().enumerate() {
        match block {
            Some(b) => hash_number_pairs.push((b256_hashes[i], b.number)),
            None => break,
        }
    }

    if hash_number_pairs.is_empty() {
        let payload = eth::encode_receipts_response(request_id, &[]);
        pm.send_command(
            &node_id,
            PeerCommand::SendRaw {
                msg_id,
                payload: Arc::new(payload),
            },
        )
        .await;
        return;
    }

    // Batch-fetch receipts by hash (not by number)
    let receipt_hashes: Vec<B256> = hash_number_pairs.iter().map(|(h, _)| *h).collect();
    let receipts_batch = match timeout(
        EL_RPC_TIMEOUT,
        eth.get_block_receipts_batch_by_hashes(&receipt_hashes),
    )
    .await
    {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            warn!(err = %e, "batch get_block_receipts_by_hashes failed for GetReceipts");
            let payload = eth::encode_receipts_response(request_id, &[]);
            pm.send_command(
                &node_id,
                PeerCommand::SendRaw {
                    msg_id,
                    payload: Arc::new(payload),
                },
            )
            .await;
            return;
        }
        Err(_) => {
            warn!("EL RPC timeout for GetReceipts batch fetch");
            let payload = eth::encode_receipts_response(request_id, &[]);
            pm.send_command(
                &node_id,
                PeerCommand::SendRaw {
                    msg_id,
                    payload: Arc::new(payload),
                },
            )
            .await;
            return;
        }
    };

    // Encode receipts — each block's receipts as an RLP list
    let mut block_receipts_rlp: Vec<Vec<u8>> = Vec::with_capacity(receipts_batch.len());
    for (i, maybe_receipts) in receipts_batch.iter().enumerate() {
        match maybe_receipts {
            Some(receipts) => {
                let block_num = hash_number_pairs[i].1;
                let encoded: Vec<Vec<u8>> =
                    receipts.iter().map(|r| r.rlp_encode(block_num)).collect();
                block_receipts_rlp.push(rlp_encode_list_from_encoded(&encoded));
            }
            None => break,
        }
    }

    debug!(
        count = block_receipts_rlp.len(),
        node_id = %hex::encode(&node_id[..8]),
        "serving receipts to peer"
    );

    let payload = eth::encode_receipts_response(request_id, &block_receipts_rlp);
    pm.send_command(
        &node_id,
        PeerCommand::SendRaw {
            msg_id,
            payload: Arc::new(payload),
        },
    )
    .await;
}

/// Encode a block body as RLP: [[tx1, tx2, ...], [uncle1, uncle2, ...]]
fn encode_body_rlp(txs_rlp: &[Vec<u8>], uncles_rlp: &[Vec<u8>]) -> Vec<u8> {
    let txs_list = rlp_encode_list_from_encoded(txs_rlp);
    let uncles_list = rlp_encode_list_from_encoded(uncles_rlp);
    rlp_encode_list_from_encoded(&[txs_list, uncles_list])
}
