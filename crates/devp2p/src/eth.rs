use crate::bytes::{decode_u32, decode_u64, encode_u32, encode_u64};
use crate::error::Error;
use crate::p2p;
use crate::rlp::{self, RlpItem};
use crate::session::Session;

pub const STATUS_MSG_ID: u8 = 0x00;
pub const NEW_BLOCK_HASHES_MSG_ID: u8 = 0x01;
pub const TRANSACTIONS_MSG_ID: u8 = 0x02;
pub const GET_BLOCK_HEADERS_MSG_ID: u8 = 0x03;
pub const BLOCK_HEADERS_MSG_ID: u8 = 0x04;
pub const GET_BLOCK_BODIES_MSG_ID: u8 = 0x05;
pub const BLOCK_BODIES_MSG_ID: u8 = 0x06;
pub const NEW_BLOCK_MSG_ID: u8 = 0x07;
pub const NEW_POOLED_TRANSACTION_HASHES_MSG_ID: u8 = 0x08;
pub const GET_POOLED_TRANSACTIONS_MSG_ID: u8 = 0x09;
pub const POOLED_TRANSACTIONS_MSG_ID: u8 = 0x0a;
pub const GET_RECEIPTS_MSG_ID: u8 = 0x0f;
pub const RECEIPTS_MSG_ID: u8 = 0x10;
pub const ETH_MSG_OFFSET: u8 = 0x10;

/// Extract the request_id from a snappy-compressed eth/68 request payload.
/// All eth/68 request messages are `[request_id, ...]`.
pub fn extract_request_id(compressed_payload: &[u8]) -> Result<u64, Error> {
    let decompressed = snap::raw::Decoder::new()
        .decompress_vec(compressed_payload)
        .map_err(|e| Error::Eth(format!("snappy decompress failed: {}", e)))?;
    let items = rlp::decode(&decompressed)?.into_list()?;
    if items.is_empty() {
        return Err(Error::Eth("empty request".to_string()));
    }
    let id_bytes = items[0].clone().into_bytes()?;
    Ok(decode_u64(&id_bytes))
}

/// Send an empty response for a given msg_id with the provided request_id.
/// Format: `[request_id, []]` → RLP → snappy → write_message.
pub async fn send_empty_response(
    session: &mut Session,
    response_msg_id: u8,
    request_id: u64,
) -> Result<(), Error> {
    let outer = RlpItem::List(vec![
        RlpItem::Bytes(encode_u64(request_id)),
        RlpItem::List(vec![]),
    ]);
    let payload = outer.encode();
    let compressed = snap::raw::Encoder::new()
        .compress_vec(&payload)
        .map_err(|e| Error::Eth(format!("snappy compress failed: {}", e)))?;
    session
        .write_message(ETH_MSG_OFFSET + response_msg_id, &compressed)
        .await
}

pub async fn send_status(session: &mut Session, status: &EthStatus) -> Result<(), Error> {
    let msg_id: u8 = ETH_MSG_OFFSET + STATUS_MSG_ID;
    let payload: Vec<u8> = status.to_rlp();
    let compressed: Vec<u8> = snap::raw::Encoder::new()
        .compress_vec(&payload)
        .map_err(|e| Error::Eth(format!("snappy compress failed: {}", e)))?;
    session.write_message(msg_id, &compressed).await
}

pub async fn receive_status(session: &mut Session) -> Result<EthStatus, Error> {
    let expected_id: u8 = ETH_MSG_OFFSET + STATUS_MSG_ID;

    let (msg_id, payload) = session.read_message().await?;

    if msg_id == p2p::DISCONNECT_MSG_ID {
        let decompressed: Vec<u8> = snap::raw::Decoder::new()
            .decompress_vec(&payload)
            .unwrap_or_else(|_| payload.clone());
        let reason = p2p::DisconnectReason::from_rlp(&decompressed);
        return Err(Error::Disconnected(reason.description()));
    }

    if msg_id != expected_id {
        return Err(Error::Eth(format!(
            "expected Status ({}), got msg_id {}",
            expected_id, msg_id
        )));
    }

    let decompressed: Vec<u8> = snap::raw::Decoder::new()
        .decompress_vec(&payload)
        .map_err(|e| Error::Eth(format!("snappy decompress failed: {}", e)))?;

    EthStatus::from_rlp(&decompressed)
}

/// Send GetBlockHeaders request (eth/68 format: [request_id, [block, amount, skip, reverse]])
pub async fn send_get_block_headers(
    session: &mut Session,
    request_id: u64,
    start: &[u8],
    limit: u64,
    skip: u64,
    reverse: bool,
) -> Result<(), Error> {
    let msg_id: u8 = ETH_MSG_OFFSET + GET_BLOCK_HEADERS_MSG_ID;

    let reverse_bytes = if reverse { vec![1u8] } else { vec![] };

    let inner = RlpItem::List(vec![
        RlpItem::Bytes(start.to_vec()),
        RlpItem::Bytes(encode_u64(limit)),
        RlpItem::Bytes(encode_u64(skip)),
        RlpItem::Bytes(reverse_bytes),
    ]);

    let outer = RlpItem::List(vec![RlpItem::Bytes(encode_u64(request_id)), inner]);

    let payload = outer.encode();
    let compressed = snap::raw::Encoder::new()
        .compress_vec(&payload)
        .map_err(|e| Error::Eth(format!("snappy compress failed: {}", e)))?;

    session.write_message(msg_id, &compressed).await
}

/// Send GetBlockBodies request (eth/68 format: [request_id, [hash1, hash2, ...]])
pub async fn send_get_block_bodies(
    session: &mut Session,
    request_id: u64,
    hashes: &[[u8; 32]],
) -> Result<(), Error> {
    let msg_id: u8 = ETH_MSG_OFFSET + GET_BLOCK_BODIES_MSG_ID;

    let hash_items: Vec<RlpItem> = hashes.iter().map(|h| RlpItem::Bytes(h.to_vec())).collect();

    let outer = RlpItem::List(vec![
        RlpItem::Bytes(encode_u64(request_id)),
        RlpItem::List(hash_items),
    ]);

    let payload = outer.encode();
    let compressed = snap::raw::Encoder::new()
        .compress_vec(&payload)
        .map_err(|e| Error::Eth(format!("snappy compress failed: {}", e)))?;

    session.write_message(msg_id, &compressed).await
}

pub struct ForkId {
    pub fork_hash: [u8; 4],
    pub fork_next: u64,
}

pub struct EthStatus {
    pub protocol_version: u32,
    pub network_id: u64,
    pub total_difficulty: Vec<u8>,
    pub best_hash: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub fork_id: ForkId,
    /// Current head block number (for EIP-2124 fork filter validation).
    pub head_number: u64,
    /// Pre-computed fork checksums for EIP-2124 validation.
    /// Built from genesis_hash + fork_blocks at startup.
    pub fork_filter: Option<ForkFilter>,
}

impl ForkId {
    pub fn from_rlp(item: &rlp::RlpItem) -> Result<ForkId, Error> {
        let items: Vec<rlp::RlpItem> = item.clone().into_list()?;

        if items.len() < 2 {
            return Err(Error::Eth("forkId missing fields".to_string()));
        }

        let hash_bytes: Vec<u8> = items[0].clone().into_bytes()?;
        if hash_bytes.len() != 4 {
            return Err(Error::Eth("forkHash must be 4 bytes".to_string()));
        }

        let mut fork_hash: [u8; 4] = [0u8; 4];
        fork_hash.copy_from_slice(&hash_bytes);

        let next_bytes: Vec<u8> = items[1].clone().into_bytes()?;
        let fork_next: u64 = decode_u64(&next_bytes);

        Ok(ForkId {
            fork_hash,
            fork_next,
        })
    }

    pub fn to_rlp(&self) -> Vec<u8> {
        let next_bytes: Vec<u8> = encode_u64(self.fork_next);

        let mut payload: Vec<u8> = Vec::new();
        payload.extend(rlp::encode_bytes(&self.fork_hash));
        payload.extend(rlp::encode_bytes(&next_bytes));

        rlp::encode_list_payload(&payload)
    }
}

/// EIP-2124 fork filter: validates a remote fork ID against local fork schedule.
#[derive(Debug, Clone)]
pub struct ForkFilter {
    /// All CRC32 checksums at each fork boundary, starting from genesis.
    /// sums[0] = CRC32(genesis_hash), sums[1] = CRC32(genesis_hash || fork_blocks[0]), etc.
    sums: Vec<[u8; 4]>,
    /// Fork block numbers (sorted, deduplicated, no block 0).
    forks: Vec<u64>,
}

impl ForkFilter {
    /// Build a fork filter from genesis hash and fork block numbers.
    /// Mirrors go-ethereum's `crc32.ChecksumIEEE(genesis) + crc32.Update(hash, IEEE, fork_be8)`.
    pub fn new(genesis_hash: &[u8; 32], fork_blocks: &[u64]) -> Self {
        // Sort, deduplicate, and remove block 0 (genesis is not a fork).
        let mut forks: Vec<u64> = fork_blocks.to_vec();
        forks.sort_unstable();
        forks.dedup();
        forks.retain(|&b| b != 0);

        // CRC32-IEEE of genesis hash
        let mut hash = crc32fast::hash(genesis_hash);

        let mut sums = Vec::with_capacity(forks.len() + 1);
        sums.push(hash.to_be_bytes());

        for &fork in &forks {
            // crc32.Update(hash, IEEETable, fork.to_be_bytes())
            let mut hasher = crc32fast::Hasher::new_with_initial(hash);
            hasher.update(&fork.to_be_bytes());
            hash = hasher.finalize();
            sums.push(hash.to_be_bytes());
        }

        Self { sums, forks }
    }

    /// Validate a remote fork ID against the local fork schedule.
    /// Returns Ok(()) if compatible, Err(reason) if not.
    pub fn validate(&self, remote: &ForkId, head: u64) -> Result<(), &'static str> {
        // Find where our head is in the fork schedule
        for (i, &fork) in self.forks.iter().enumerate() {
            if head >= fork {
                continue;
            }
            // head < fork[i]: we haven't passed fork i yet.
            // Our current checksum is sums[i].

            // Rule 1: local and remote checksums match
            if self.sums[i] == remote.fork_hash {
                // Rule 1a: remote announces a fork we already passed → incompatible
                if remote.fork_next > 0 && head >= remote.fork_next {
                    return Err("remote fork already passed locally");
                }
                // Rule 1b: compatible
                return Ok(());
            }

            // Rule 2: remote checksum is a subset (remote is behind us)
            for j in 0..i {
                if self.sums[j] == remote.fork_hash {
                    // Remote is behind — check if remote.next matches our next fork at that point
                    if self.forks[j] != remote.fork_next {
                        return Err("remote needs update (stale)");
                    }
                    return Ok(());
                }
            }

            // Rule 3: remote checksum is a superset (we're behind remote)
            for j in (i + 1)..self.sums.len() {
                if self.sums[j] == remote.fork_hash {
                    return Ok(());
                }
            }

            // Rule 4: no match at all — incompatible
            return Err("incompatible fork ID");
        }

        // Head is past all known forks. Our checksum is the last one.
        let last = self.sums.last().unwrap();
        if *last == remote.fork_hash {
            // Same final state
            if remote.fork_next > 0 && head >= remote.fork_next {
                return Err("remote fork already passed locally");
            }
            return Ok(());
        }

        // Check if remote is a subset
        for (j, sum) in self.sums.iter().enumerate() {
            if *sum == remote.fork_hash {
                if j < self.forks.len() && self.forks[j] != remote.fork_next {
                    return Err("remote needs update (stale)");
                }
                return Ok(());
            }
        }

        Err("incompatible fork ID")
    }
}

impl EthStatus {
    pub fn from_rlp(data: &[u8]) -> Result<EthStatus, Error> {
        let items: Vec<rlp::RlpItem> = rlp::decode(data)?.into_list()?;

        if items.len() < 6 {
            return Err(Error::Eth("status missing fields".to_string()));
        }

        let version_bytes: Vec<u8> = items[0].clone().into_bytes()?;
        let protocol_version: u32 = decode_u32(&version_bytes);

        let network_bytes: Vec<u8> = items[1].clone().into_bytes()?;
        let network_id: u64 = decode_u64(&network_bytes);

        let total_difficulty: Vec<u8> = items[2].clone().into_bytes()?;

        let best_bytes: Vec<u8> = items[3].clone().into_bytes()?;
        if best_bytes.len() != 32 {
            return Err(Error::Eth("bestHash must be 32 bytes".to_string()));
        }
        let mut best_hash: [u8; 32] = [0u8; 32];
        best_hash.copy_from_slice(&best_bytes);

        let genesis_bytes: Vec<u8> = items[4].clone().into_bytes()?;
        if genesis_bytes.len() != 32 {
            return Err(Error::Eth("genesisHash must be 32 bytes".to_string()));
        }
        let mut genesis_hash: [u8; 32] = [0u8; 32];
        genesis_hash.copy_from_slice(&genesis_bytes);

        let fork_id: ForkId = ForkId::from_rlp(&items[5])?;

        Ok(EthStatus {
            protocol_version,
            network_id,
            total_difficulty,
            best_hash,
            genesis_hash,
            fork_id,
            head_number: 0,
            fork_filter: None,
        })
    }

    pub fn to_rlp(&self) -> Vec<u8> {
        let version_bytes: Vec<u8> = encode_u32(self.protocol_version);
        let network_bytes: Vec<u8> = encode_u64(self.network_id);

        let mut payload: Vec<u8> = Vec::new();
        payload.extend(rlp::encode_bytes(&version_bytes));
        payload.extend(rlp::encode_bytes(&network_bytes));
        payload.extend(rlp::encode_bytes(&self.total_difficulty));
        payload.extend(rlp::encode_bytes(&self.best_hash));
        payload.extend(rlp::encode_bytes(&self.genesis_hash));
        payload.extend(self.fork_id.to_rlp());

        rlp::encode_list_payload(&payload)
    }
}

// ============================================================================
// Request decoding (for serving peers)
// ============================================================================

/// Start of a GetBlockHeaders request: by number or by hash.
#[derive(Debug)]
pub enum HeaderStart {
    ByNumber(u64),
    ByHash([u8; 32]),
}

/// Decoded GetBlockHeaders request.
#[derive(Debug)]
pub struct BlockHeadersRequest {
    pub request_id: u64,
    pub start: HeaderStart,
    pub limit: u64,
    pub skip: u64,
    pub reverse: bool,
}

/// Decode a snappy-compressed GetBlockHeaders request.
/// Format: `snappy(RLP([request_id, [start, limit, skip, reverse]]))`
pub fn decode_get_block_headers(compressed: &[u8]) -> Result<BlockHeadersRequest, Error> {
    let decompressed = snap::raw::Decoder::new()
        .decompress_vec(compressed)
        .map_err(|e| Error::Eth(format!("snappy decompress failed: {}", e)))?;
    let items = rlp::decode(&decompressed)?.into_list()?;
    if items.len() < 2 {
        return Err(Error::Eth("GetBlockHeaders: too few fields".to_string()));
    }

    let request_id = decode_u64(&items[0].clone().into_bytes()?);
    let inner = items[1].clone().into_list()?;
    if inner.len() < 4 {
        return Err(Error::Eth(
            "GetBlockHeaders inner: too few fields".to_string(),
        ));
    }

    let start_bytes = inner[0].clone().into_bytes()?;
    let start = if start_bytes.len() == 32 {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&start_bytes);
        HeaderStart::ByHash(hash)
    } else {
        HeaderStart::ByNumber(decode_u64(&start_bytes))
    };

    let limit = decode_u64(&inner[1].clone().into_bytes()?);
    let skip = decode_u64(&inner[2].clone().into_bytes()?);
    let reverse_bytes = inner[3].clone().into_bytes()?;
    let reverse = !reverse_bytes.is_empty() && reverse_bytes[0] != 0;

    Ok(BlockHeadersRequest {
        request_id,
        start,
        limit,
        skip,
        reverse,
    })
}

/// Decoded GetBlockBodies request.
#[derive(Debug)]
pub struct BlockBodiesRequest {
    pub request_id: u64,
    pub hashes: Vec<[u8; 32]>,
}

/// Decode a snappy-compressed GetBlockBodies request.
/// Format: `snappy(RLP([request_id, [hash1, hash2, ...]]))`
pub fn decode_get_block_bodies(compressed: &[u8]) -> Result<BlockBodiesRequest, Error> {
    let decompressed = snap::raw::Decoder::new()
        .decompress_vec(compressed)
        .map_err(|e| Error::Eth(format!("snappy decompress failed: {}", e)))?;
    let items = rlp::decode(&decompressed)?.into_list()?;
    if items.len() < 2 {
        return Err(Error::Eth("GetBlockBodies: too few fields".to_string()));
    }

    let request_id = decode_u64(&items[0].clone().into_bytes()?);
    let hash_items = items[1].clone().into_list()?;

    let mut hashes = Vec::with_capacity(hash_items.len());
    for item in hash_items {
        let bytes = item.into_bytes()?;
        if bytes.len() != 32 {
            return Err(Error::Eth(format!(
                "GetBlockBodies: hash must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        hashes.push(hash);
    }

    Ok(BlockBodiesRequest { request_id, hashes })
}

// ============================================================================
// Response encoding (for serving peers)
// ============================================================================

/// Snappy-compress data. Only fails on OOM (process is already dying).
fn snappy_compress(data: &[u8]) -> Vec<u8> {
    snap::raw::Encoder::new()
        .compress_vec(data)
        .expect("snappy compress: OOM")
}

/// Encode a BlockHeaders response: `snappy(RLP([request_id, [header₁, header₂, ...]]))`
/// Each header in `headers_rlp` is already a fully RLP-encoded header (list).
pub fn encode_block_headers_response(request_id: u64, headers_rlp: &[Vec<u8>]) -> Vec<u8> {
    // Build the inner list by concatenating pre-encoded headers
    let mut inner_payload = Vec::new();
    for h in headers_rlp {
        inner_payload.extend_from_slice(h);
    }
    let inner_list = rlp::encode_list_payload(&inner_payload);

    // Outer: [request_id, headers_list]
    let rid_rlp = rlp::encode_bytes(&encode_u64(request_id));
    let mut outer_payload = Vec::new();
    outer_payload.extend_from_slice(&rid_rlp);
    outer_payload.extend_from_slice(&inner_list);
    let outer = rlp::encode_list_payload(&outer_payload);

    snappy_compress(&outer)
}

/// Encode a BlockBodies response: `snappy(RLP([request_id, [body₁, body₂, ...]]))`
/// Each body in `bodies_rlp` is already a fully RLP-encoded body (list of [txs, uncles]).
pub fn encode_block_bodies_response(request_id: u64, bodies_rlp: &[Vec<u8>]) -> Vec<u8> {
    let mut inner_payload = Vec::new();
    for b in bodies_rlp {
        inner_payload.extend_from_slice(b);
    }
    let inner_list = rlp::encode_list_payload(&inner_payload);

    let rid_rlp = rlp::encode_bytes(&encode_u64(request_id));
    let mut outer_payload = Vec::new();
    outer_payload.extend_from_slice(&rid_rlp);
    outer_payload.extend_from_slice(&inner_list);
    let outer = rlp::encode_list_payload(&outer_payload);

    snappy_compress(&outer)
}

/// Encode a NewBlock message (msg_id 0x07).
///
/// Wire format: `snappy(RLP([[header, [tx1, tx2, ...], [uncle1, ...]], td]))`
///
/// All inputs are raw RLP-encoded bytes:
/// - `header_rlp`: the full RLP-encoded header (a list)
/// - `transactions_rlp`: each element is an RLP-encoded transaction
/// - `uncles_rlp`: each element is an RLP-encoded uncle header
/// - `td_bytes`: totalDifficulty as big-endian bytes (no leading zeros)
///
/// Returns the snappy-compressed payload ready for `write_message()`.
pub fn encode_new_block(
    header_rlp: &[u8],
    transactions_rlp: &[Vec<u8>],
    uncles_rlp: &[Vec<u8>],
    td_bytes: &[u8],
) -> Vec<u8> {
    // Build txs list: RLP list wrapping each pre-encoded tx
    let mut txs_payload = Vec::new();
    for tx in transactions_rlp {
        txs_payload.extend_from_slice(tx);
    }
    let txs_list = rlp::encode_list_payload(&txs_payload);

    // Build uncles list: RLP list wrapping each pre-encoded uncle header
    let mut uncles_payload = Vec::new();
    for uncle in uncles_rlp {
        uncles_payload.extend_from_slice(uncle);
    }
    let uncles_list = rlp::encode_list_payload(&uncles_payload);

    // Build block: [header, txs, uncles] — header_rlp is already an RLP list
    let mut block_payload = Vec::new();
    block_payload.extend_from_slice(header_rlp);
    block_payload.extend_from_slice(&txs_list);
    block_payload.extend_from_slice(&uncles_list);
    let block_list = rlp::encode_list_payload(&block_payload);

    // Encode td as RLP bytes
    let td_rlp = rlp::encode_bytes(td_bytes);

    // Outer: [block, td]
    let mut outer_payload = Vec::new();
    outer_payload.extend_from_slice(&block_list);
    outer_payload.extend_from_slice(&td_rlp);
    let outer = rlp::encode_list_payload(&outer_payload);

    // Snappy compress
    snappy_compress(&outer)
}

/// Encode a NewBlockHashes message (msg_id 0x01).
///
/// Wire format: `snappy(RLP([[hash1, number1], [hash2, number2], ...]))`
///
/// Returns the snappy-compressed payload ready for `write_message()`.
pub fn encode_new_block_hashes(entries: &[([u8; 32], u64)]) -> Vec<u8> {
    let items: Vec<rlp::RlpItem> = entries
        .iter()
        .map(|(hash, number)| {
            rlp::RlpItem::List(vec![
                rlp::RlpItem::Bytes(hash.to_vec()),
                rlp::RlpItem::Bytes(encode_u64(*number)),
            ])
        })
        .collect();

    let outer = rlp::RlpItem::List(items);
    let payload = outer.encode();

    snappy_compress(&payload)
}

/// Decoded GetReceipts request.
#[derive(Debug)]
pub struct ReceiptsRequest {
    pub request_id: u64,
    pub hashes: Vec<[u8; 32]>,
}

/// Decode a snappy-compressed GetReceipts request.
/// Format: `snappy(RLP([request_id, [hash1, hash2, ...]]))`
pub fn decode_get_receipts(compressed: &[u8]) -> Result<ReceiptsRequest, Error> {
    let decompressed = snap::raw::Decoder::new()
        .decompress_vec(compressed)
        .map_err(|e| Error::Eth(format!("snappy decompress failed: {}", e)))?;
    let items = rlp::decode(&decompressed)?.into_list()?;
    if items.len() < 2 {
        return Err(Error::Eth("GetReceipts: too few fields".to_string()));
    }

    let request_id = decode_u64(&items[0].clone().into_bytes()?);
    let hash_items = items[1].clone().into_list()?;

    let mut hashes = Vec::with_capacity(hash_items.len());
    for item in hash_items {
        let bytes = item.into_bytes()?;
        if bytes.len() != 32 {
            return Err(Error::Eth(format!(
                "GetReceipts: hash must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes);
        hashes.push(hash);
    }

    Ok(ReceiptsRequest { request_id, hashes })
}

/// Encode a Receipts response: `snappy(RLP([request_id, [block₁_receipts, block₂_receipts, ...]]))`
/// Each element in `block_receipts_rlp` is an already RLP-encoded list of receipts for one block.
pub fn encode_receipts_response(request_id: u64, block_receipts_rlp: &[Vec<u8>]) -> Vec<u8> {
    let mut inner_payload = Vec::new();
    for b in block_receipts_rlp {
        inner_payload.extend_from_slice(b);
    }
    let inner_list = rlp::encode_list_payload(&inner_payload);

    let rid_rlp = rlp::encode_bytes(&encode_u64(request_id));
    let mut outer_payload = Vec::new();
    outer_payload.extend_from_slice(&rid_rlp);
    outer_payload.extend_from_slice(&inner_list);
    let outer = rlp::encode_list_payload(&outer_payload);

    snappy_compress(&outer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fork_id_roundtrip() {
        let fork_id = ForkId {
            fork_hash: [0xfc, 0x64, 0xec, 0x04],
            fork_next: 1150000,
        };

        let encoded = fork_id.to_rlp();
        let decoded = ForkId::from_rlp(&rlp::decode(&encoded).unwrap()).unwrap();

        assert_eq!(decoded.fork_hash, fork_id.fork_hash);
        assert_eq!(decoded.fork_next, fork_id.fork_next);
    }

    #[test]
    fn test_eth_status_roundtrip() {
        let status = EthStatus {
            protocol_version: 68,
            network_id: 1,
            total_difficulty: vec![0x01, 0x00],
            best_hash: [0xAA; 32],
            genesis_hash: [0xBB; 32],
            fork_id: ForkId {
                fork_hash: [0xfc, 0x64, 0xec, 0x04],
                fork_next: 0,
            },
            head_number: 0,
            fork_filter: None,
        };

        let encoded = status.to_rlp();
        let decoded = EthStatus::from_rlp(&encoded).unwrap();

        assert_eq!(decoded.protocol_version, 68);
        assert_eq!(decoded.network_id, 1);
        assert_eq!(decoded.total_difficulty, vec![0x01, 0x00]);
        assert_eq!(decoded.best_hash, [0xAA; 32]);
        assert_eq!(decoded.genesis_hash, [0xBB; 32]);
        assert_eq!(decoded.fork_id.fork_hash, [0xfc, 0x64, 0xec, 0x04]);
        assert_eq!(decoded.fork_id.fork_next, 0);
    }

    #[test]
    fn test_get_block_headers_encode() {
        // Test that the request RLP structure is correct
        let request_id = 42u64;
        let start = [0xAA; 32];

        let reverse_bytes: Vec<u8> = vec![];
        let inner = RlpItem::List(vec![
            RlpItem::Bytes(start.to_vec()),
            RlpItem::Bytes(encode_u64(10)),
            RlpItem::Bytes(encode_u64(0)),
            RlpItem::Bytes(reverse_bytes),
        ]);

        let outer = RlpItem::List(vec![RlpItem::Bytes(encode_u64(request_id)), inner]);

        let encoded = outer.encode();
        let decoded = rlp::decode(&encoded).unwrap().into_list().unwrap();
        assert_eq!(decoded.len(), 2);
        let rid = decode_u64(&decoded[0].clone().into_bytes().unwrap());
        assert_eq!(rid, 42);
    }

    #[test]
    fn test_encode_new_block_hashes_roundtrip() {
        let entries = vec![([0xAA; 32], 100u64), ([0xBB; 32], 200u64)];
        let compressed = encode_new_block_hashes(&entries);

        // Decompress and decode
        let decompressed = snap::raw::Decoder::new()
            .decompress_vec(&compressed)
            .unwrap();
        let items = rlp::decode(&decompressed).unwrap().into_list().unwrap();
        assert_eq!(items.len(), 2);

        let entry0 = items[0].clone().into_list().unwrap();
        let hash0 = entry0[0].clone().into_bytes().unwrap();
        let num0 = decode_u64(&entry0[1].clone().into_bytes().unwrap());
        assert_eq!(hash0, vec![0xAA; 32]);
        assert_eq!(num0, 100);

        let entry1 = items[1].clone().into_list().unwrap();
        let hash1 = entry1[0].clone().into_bytes().unwrap();
        let num1 = decode_u64(&entry1[1].clone().into_bytes().unwrap());
        assert_eq!(hash1, vec![0xBB; 32]);
        assert_eq!(num1, 200);
    }

    #[test]
    fn test_decode_get_block_headers_by_number() {
        let request_id = 42u64;
        let start_num = 1000u64;
        let inner = RlpItem::List(vec![
            RlpItem::Bytes(encode_u64(start_num)),
            RlpItem::Bytes(encode_u64(10)),
            RlpItem::Bytes(encode_u64(0)),
            RlpItem::Bytes(vec![]),
        ]);
        let outer = RlpItem::List(vec![RlpItem::Bytes(encode_u64(request_id)), inner]);
        let payload = outer.encode();
        let compressed = snap::raw::Encoder::new().compress_vec(&payload).unwrap();

        let req = decode_get_block_headers(&compressed).unwrap();
        assert_eq!(req.request_id, 42);
        match req.start {
            HeaderStart::ByNumber(n) => assert_eq!(n, 1000),
            _ => panic!("expected ByNumber"),
        }
        assert_eq!(req.limit, 10);
        assert_eq!(req.skip, 0);
        assert!(!req.reverse);
    }

    #[test]
    fn test_decode_get_block_headers_by_hash() {
        let request_id = 7u64;
        let hash = [0xAA; 32];
        let inner = RlpItem::List(vec![
            RlpItem::Bytes(hash.to_vec()),
            RlpItem::Bytes(encode_u64(1)),
            RlpItem::Bytes(encode_u64(0)),
            RlpItem::Bytes(vec![1]),
        ]);
        let outer = RlpItem::List(vec![RlpItem::Bytes(encode_u64(request_id)), inner]);
        let payload = outer.encode();
        let compressed = snap::raw::Encoder::new().compress_vec(&payload).unwrap();

        let req = decode_get_block_headers(&compressed).unwrap();
        assert_eq!(req.request_id, 7);
        match req.start {
            HeaderStart::ByHash(h) => assert_eq!(h, [0xAA; 32]),
            _ => panic!("expected ByHash"),
        }
        assert_eq!(req.limit, 1);
        assert!(req.reverse);
    }

    #[test]
    fn test_decode_get_block_bodies() {
        let request_id = 99u64;
        let h1 = [0xAA; 32];
        let h2 = [0xBB; 32];
        let outer = RlpItem::List(vec![
            RlpItem::Bytes(encode_u64(request_id)),
            RlpItem::List(vec![
                RlpItem::Bytes(h1.to_vec()),
                RlpItem::Bytes(h2.to_vec()),
            ]),
        ]);
        let payload = outer.encode();
        let compressed = snap::raw::Encoder::new().compress_vec(&payload).unwrap();

        let req = decode_get_block_bodies(&compressed).unwrap();
        assert_eq!(req.request_id, 99);
        assert_eq!(req.hashes.len(), 2);
        assert_eq!(req.hashes[0], h1);
        assert_eq!(req.hashes[1], h2);
    }

    #[test]
    fn test_encode_block_headers_response_roundtrip() {
        // Create a fake header RLP
        let fake_header = RlpItem::List(vec![
            RlpItem::Bytes(vec![0x01, 0x02]),
            RlpItem::Bytes(vec![0x03]),
        ]);
        let header_rlp = fake_header.encode();

        let compressed = encode_block_headers_response(42, std::slice::from_ref(&header_rlp));

        // Decompress and verify structure: [request_id, [header1, ...]]
        let decompressed = snap::raw::Decoder::new()
            .decompress_vec(&compressed)
            .unwrap();
        let outer = rlp::decode(&decompressed).unwrap().into_list().unwrap();
        assert_eq!(outer.len(), 2);

        let rid = decode_u64(&outer[0].clone().into_bytes().unwrap());
        assert_eq!(rid, 42);

        let headers = outer[1].clone().into_list().unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].encode(), header_rlp);
    }

    #[test]
    fn test_encode_block_bodies_response_roundtrip() {
        // Body = [[txs], [uncles]] — empty
        let empty_body = RlpItem::List(vec![RlpItem::List(vec![]), RlpItem::List(vec![])]);
        let body_rlp = empty_body.encode();

        let compressed = encode_block_bodies_response(55, std::slice::from_ref(&body_rlp));

        let decompressed = snap::raw::Decoder::new()
            .decompress_vec(&compressed)
            .unwrap();
        let outer = rlp::decode(&decompressed).unwrap().into_list().unwrap();
        assert_eq!(outer.len(), 2);

        let rid = decode_u64(&outer[0].clone().into_bytes().unwrap());
        assert_eq!(rid, 55);

        let bodies = outer[1].clone().into_list().unwrap();
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0].encode(), body_rlp);
    }

    #[test]
    fn test_encode_new_block_structure() {
        // Create a minimal fake header RLP (just an RLP list with one bytes item)
        let fake_header = RlpItem::List(vec![RlpItem::Bytes(vec![0x01, 0x02])]);
        let header_rlp = fake_header.encode();

        // One fake transaction (RLP bytes)
        let tx1 = rlp::encode_bytes(&[0xDE, 0xAD]);
        let transactions = vec![tx1];

        // No uncles
        let uncles: Vec<Vec<u8>> = vec![];

        // TD = 1000
        let td_bytes = encode_u64(1000);

        let compressed = encode_new_block(&header_rlp, &transactions, &uncles, &td_bytes);

        // Decompress and verify structure: [[header, [txs], [uncles]], td]
        let decompressed = snap::raw::Decoder::new()
            .decompress_vec(&compressed)
            .unwrap();
        let outer = rlp::decode(&decompressed).unwrap().into_list().unwrap();
        assert_eq!(outer.len(), 2); // [block, td]

        // block = [header, txs, uncles]
        let block = outer[0].clone().into_list().unwrap();
        assert_eq!(block.len(), 3);

        // td
        let td = decode_u64(&outer[1].clone().into_bytes().unwrap());
        assert_eq!(td, 1000);
    }

    #[test]
    fn test_fork_filter_same_state() {
        // Two nodes at the same fork state should be compatible
        let genesis = [0xAA; 32];
        let forks = vec![100, 200, 300];
        let filter = ForkFilter::new(&genesis, &forks);

        // Head past all forks: our checksum is sums[3] (after all 3 forks)
        let remote = ForkId {
            fork_hash: filter.sums[3],
            fork_next: 0,
        };
        assert!(filter.validate(&remote, 400).is_ok());
    }

    #[test]
    fn test_fork_filter_remote_behind() {
        // Remote is at fork 1, we're at fork 3 — subset, should accept
        // if remote.fork_next matches our fork[1]
        let genesis = [0xAA; 32];
        let forks = vec![100, 200, 300];
        let filter = ForkFilter::new(&genesis, &forks);

        let remote = ForkId {
            fork_hash: filter.sums[1], // after fork 100, before fork 200
            fork_next: 200,            // matches forks[1]
        };
        assert!(filter.validate(&remote, 400).is_ok());
    }

    #[test]
    fn test_fork_filter_remote_behind_wrong_next() {
        // Remote is at fork 1 but announces wrong next fork — stale
        let genesis = [0xAA; 32];
        let forks = vec![100, 200, 300];
        let filter = ForkFilter::new(&genesis, &forks);

        let remote = ForkId {
            fork_hash: filter.sums[1], // after fork 100
            fork_next: 999,            // doesn't match forks[1]=200
        };
        assert!(filter.validate(&remote, 400).is_err());
    }

    #[test]
    fn test_fork_filter_we_are_behind() {
        // We're at fork 1, remote is at fork 3 — superset, should accept
        let genesis = [0xAA; 32];
        let forks = vec![100, 200, 300];
        let filter = ForkFilter::new(&genesis, &forks);

        let remote = ForkId {
            fork_hash: filter.sums[3], // after all forks
            fork_next: 0,
        };
        // Our head is between fork 100 and 200
        assert!(filter.validate(&remote, 150).is_ok());
    }

    #[test]
    fn test_fork_filter_incompatible() {
        // Remote has a completely different fork hash — incompatible
        let genesis = [0xAA; 32];
        let forks = vec![100, 200, 300];
        let filter = ForkFilter::new(&genesis, &forks);

        let remote = ForkId {
            fork_hash: [0xFF, 0xFF, 0xFF, 0xFF],
            fork_next: 0,
        };
        assert!(filter.validate(&remote, 400).is_err());
    }

    #[test]
    fn test_fork_filter_remote_announces_passed_fork() {
        // Remote and local have same hash, but remote announces a fork
        // that we've already passed — rule 1a, incompatible
        let genesis = [0xAA; 32];
        let forks = vec![100, 200, 300];
        let filter = ForkFilter::new(&genesis, &forks);

        let remote = ForkId {
            fork_hash: filter.sums[2], // both at fork 200
            fork_next: 250,            // remote thinks fork at 250
        };
        // We're at 400, so we've passed 250 without forking
        assert!(filter.validate(&remote, 400).is_err());
    }

    #[test]
    fn test_fork_filter_no_forks() {
        // No forks at all — only genesis checksum
        let genesis = [0xBB; 32];
        let filter = ForkFilter::new(&genesis, &[]);

        // Same genesis hash → compatible
        let remote = ForkId {
            fork_hash: filter.sums[0],
            fork_next: 0,
        };
        assert!(filter.validate(&remote, 0).is_ok());

        // Different hash → incompatible
        let remote2 = ForkId {
            fork_hash: [0x00, 0x00, 0x00, 0x00],
            fork_next: 0,
        };
        assert!(filter.validate(&remote2, 0).is_err());
    }

    #[test]
    fn test_fork_filter_crc32_matches_go_ethereum() {
        // ETC mainnet genesis hash
        let genesis_hash =
            hex::decode("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3")
                .unwrap();
        let mut genesis: [u8; 32] = [0u8; 32];
        genesis.copy_from_slice(&genesis_hash);

        // Verify CRC32 of genesis hash matches go-ethereum's 0xfc64ec04
        let hash = crc32fast::hash(&genesis);
        assert_eq!(hash.to_be_bytes(), [0xfc, 0x64, 0xec, 0x04]);

        // Build filter with Homestead fork at block 1_150_000
        let filter = ForkFilter::new(&genesis, &[1_150_000]);
        // sums[0] = CRC32(genesis) = 0xfc64ec04
        assert_eq!(filter.sums[0], [0xfc, 0x64, 0xec, 0x04]);
        // sums[1] = CRC32(genesis || 1150000_be8) — should match go-ethereum
        // go-ethereum: checksumUpdate(0xfc64ec04, 1150000) using big-endian u64
        let mut hasher = crc32fast::Hasher::new_with_initial(0xfc64ec04);
        hasher.update(&1_150_000u64.to_be_bytes());
        let expected = hasher.finalize();
        assert_eq!(filter.sums[1], expected.to_be_bytes());
    }
}
