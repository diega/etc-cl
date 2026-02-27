pub mod decode;
pub mod mess;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Instant;

use alloy_primitives::B256;
use eth_rpc::EthClient;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use mess::MessConfig;

use chain::tracker::ChainTracker;
use chain::types::{bytes_to_u256, td_to_rlp_bytes, BlockHeader};
use chain::uncle_pool::UnclePool;
use consensus::uncle::validate_uncles_basic;
use decode::{
    block_to_payload_with_hash, decode_block_body, decode_block_header, decode_new_block,
    decode_new_block_hashes, hash_raw_header, DecodedBody,
};
use devp2p::peer_manager::{BlockBroadcast, PeerCommand, PeerManager};
use engine_api::client::EngineClient;
use engine_api::types::{
    ExecutionPayload, ForkChoiceResponse, ForkchoiceState, PayloadAttributes, PayloadStatus,
    STATUS_ACCEPTED, STATUS_INVALID, STATUS_SYNCING, STATUS_VALID,
};

// ---------------------------------------------------------------------------
// Traits for testability
// ---------------------------------------------------------------------------

pub trait SyncPeerManager: Send + Sync {
    fn send_command(
        &self,
        node_id: &[u8; 64],
        cmd: PeerCommand,
    ) -> impl std::future::Future<Output = bool> + Send;

    fn broadcast_block(
        &self,
        block: &BlockBroadcast<'_>,
    ) -> impl std::future::Future<Output = ()> + Send;
}

pub trait SyncEngine: Send + Sync {
    fn new_payload_v2(
        &self,
        payload: &ExecutionPayload,
    ) -> impl std::future::Future<Output = Result<PayloadStatus, engine_api::client::ClientError>> + Send;

    fn new_payload_v2_batch(
        &self,
        payloads: &[&ExecutionPayload],
    ) -> impl std::future::Future<Output = Result<Vec<PayloadStatus>, engine_api::client::ClientError>>
           + Send;

    fn forkchoice_updated_v2(
        &self,
        state: &ForkchoiceState,
        attrs: Option<&PayloadAttributes>,
    ) -> impl std::future::Future<Output = Result<ForkChoiceResponse, engine_api::client::ClientError>>
           + Send;
}

impl SyncPeerManager for PeerManager {
    async fn send_command(&self, node_id: &[u8; 64], cmd: PeerCommand) -> bool {
        PeerManager::send_command(self, node_id, cmd).await
    }

    async fn broadcast_block(&self, block: &BlockBroadcast<'_>) {
        PeerManager::broadcast_block(self, block).await
    }
}

impl SyncEngine for EngineClient {
    async fn new_payload_v2(
        &self,
        payload: &ExecutionPayload,
    ) -> Result<PayloadStatus, engine_api::client::ClientError> {
        EngineClient::new_payload_v2(self, payload).await
    }

    async fn new_payload_v2_batch(
        &self,
        payloads: &[&ExecutionPayload],
    ) -> Result<Vec<PayloadStatus>, engine_api::client::ClientError> {
        EngineClient::new_payload_v2_batch(self, payloads).await
    }

    async fn forkchoice_updated_v2(
        &self,
        state: &ForkchoiceState,
        attrs: Option<&PayloadAttributes>,
    ) -> Result<ForkChoiceResponse, engine_api::client::ClientError> {
        EngineClient::forkchoice_updated_v2(self, state, attrs).await
    }
}

pub const HEADER_BATCH_SIZE: u64 = 192;
pub const BODY_CHUNK_SIZE: usize = 128;
pub const MAX_BUFFER_SIZE: usize = 2048;
pub const BODY_TIMEOUT_SECS: u64 = 15;
pub const HEADER_TIMEOUT_SECS: u64 = 15;
pub const FCU_INTERVAL: u64 = 64;
pub const MAX_FAILED_REQUESTS: u32 = 3;
/// Maximum number of ethash caches to keep in memory (each ~16 MB).
const MAX_ETHASH_CACHES: usize = 3;
/// Maximum size of the seen_blocks set before it is cleared.
const SEEN_BLOCKS_CAP: usize = 10_000;
/// Number of blocks to batch-drain to the EL at once.
const DRAIN_BATCH_SIZE: usize = 64;
/// When a peer's TD exceeds ours by more than this many blocks' worth of
/// average difficulty, fall back from TipFollowing to Pipeline sync.
const PIPELINE_FALLBACK_BLOCKS: u64 = 1000;

struct BlockEntry {
    header: BlockHeader,
    block_hash: B256,
    body: Option<DecodedBody>,
}

struct BodyRequest {
    peer_id: [u8; 64],
    request_id: u64,
    block_numbers: Vec<u64>,
    sent_at: Instant,
}

struct PeerInfo {
    td: Vec<u8>,
    best_hash: [u8; 32],
    failed_requests: u32,
}

/// The minimum number of peers required before starting catch-up sync.
const CATCHUP_MIN_PEERS: usize = 2;
/// How long to wait for CATCHUP_MIN_PEERS before falling back to Pipeline with 1 peer.
const CATCHUP_PEER_WAIT_SECS: u64 = 30;
/// How far behind the tip to set the FCU target (blocks).
const CATCHUP_OFFSET: u64 = 64;
/// High-level sync phase.
enum SyncPhase {
    /// Wait for peers, query best header, send FCU to let EL sync via eth/68.
    CatchUp(CatchUpState),
    /// CL-driven pipeline sync (existing behavior).
    Pipeline,
    /// Following the chain tip in real-time via NewBlock/NewBlockHashes.
    TipFollowing,
}

/// Sub-states within the CatchUp phase.
enum CatchUpState {
    /// Waiting for enough peers with good TD.
    WaitingForPeers { entered_at: Instant },
    /// Sent GetBlockHeaders(best_hash, 1) to learn the best block number.
    QueryingBestHeader {
        peer: [u8; 64],
        request_id: u64,
        sent_at: Instant,
    },
    /// Sent GetBlockHeaders(best_number - CATCHUP_OFFSET, 1) to learn the target hash.
    QueryingTargetHeader {
        peer: [u8; 64],
        best_number: u64,
        request_id: u64,
        sent_at: Instant,
    },
    /// FCU has been sent; re-send periodically until EL reports VALID.
    Syncing {
        target_hash: B256,
        target_number: u64,
    },
}

struct PendingRequest {
    request_id: u64,
    peer: [u8; 64],
    sent_at: Instant,
}

/// Timeout for tip fetch requests (seconds).
const TIP_FETCH_TIMEOUT_SECS: u64 = 15;
/// Timeout for orphan blocks (seconds).
const ORPHAN_TIMEOUT_SECS: u64 = 60;
/// Maximum total orphan entries across all parent hashes.
const MAX_ORPHAN_ENTRIES: usize = 256;
/// Maximum number of ancestor headers to fetch in a single batch during reorgs.
const REORG_ANCESTOR_LIMIT: u64 = 16;

/// A pending tip-fetch: we asked a peer for a header or body by hash.
struct PendingTipFetch {
    peer: [u8; 64],
    request_id: u64,
    block_hash: B256,
    block_number: u64,
    sent_at: Instant,
    /// After getting the header, we fetch the body with a second request.
    phase: TipFetchPhase,
}

enum TipFetchPhase {
    /// Awaiting header response.
    Header,
    /// Got header, awaiting body response.
    Body {
        header: Box<BlockHeader>,
        header_rlp: Vec<u8>,
    },
    /// Awaiting a batch of ancestor headers (reorg path).
    AncestorHeaders,
    /// Got ancestor headers, awaiting their bodies.
    AncestorBodies {
        /// Stored oldest-first for correct processing order.
        headers: Vec<(BlockHeader, Vec<u8>)>,
    },
}

/// A complete block received at the chain tip (from NewBlock, fetch, or orphan resolution).
struct TipBlock {
    header: BlockHeader,
    header_rlp: Vec<u8>,
    block_hash: B256,
    transactions: Vec<Vec<u8>>,
    uncles: Vec<BlockHeader>,
}

/// An orphan block whose parent is unknown.
struct OrphanEntry {
    header: BlockHeader,
    header_rlp: Vec<u8>,
    transactions: Vec<Vec<u8>>,
    uncles: Vec<BlockHeader>,
    received_at: Instant,
    /// The peer that sent this orphan (to request parent from).
    from_peer: [u8; 64],
}

pub struct SyncManager {
    chain: ChainTracker,
    next_request_id: u64,
    peers: HashMap<[u8; 64], PeerInfo>,

    // Sync phase: CatchUp (EL syncs via eth/68) or Pipeline (CL-driven)
    phase: SyncPhase,

    // Header fetch — single peer
    header_peer: Option<[u8; 64]>,
    pending_header_request: Option<PendingRequest>,

    // Pipeline buffer — ordered by block number
    buffer: BTreeMap<u64, BlockEntry>,
    buffer_drain_head: u64,

    // Multi-peer body dispatch
    pending_body_requests: Vec<BodyRequest>,

    // Track which block numbers have an in-flight body request
    inflight_body_blocks: BTreeSet<u64>,

    // Processing state
    blocks_since_fcu: u64,
    ethash_caches: HashMap<u64, Arc<Vec<u8>>>,
    last_header: Option<BlockHeader>,

    // Whether we've finished fetching headers (peer returned 0)
    headers_exhausted: bool,

    // Skip PoW verification (for tests)
    skip_pow: bool,

    // TipFollowing state
    /// Pending tip fetches keyed by request_id.
    pending_tip_fetches: HashMap<u64, PendingTipFetch>,
    /// Orphan blocks keyed by missing parent hash (multiple siblings possible).
    orphan_blocks: HashMap<B256, Vec<OrphanEntry>>,
    /// Current recursion depth for orphan resolution (prevents runaway chains).
    orphan_resolve_depth: u32,
    /// Block hashes we've already seen (to avoid re-processing).
    /// Double-buffered: when `seen_blocks` exceeds SEEN_BLOCKS_CAP, it is
    /// rotated to `seen_blocks_prev` instead of being cleared entirely.
    seen_blocks: std::collections::HashSet<B256>,
    seen_blocks_prev: std::collections::HashSet<B256>,

    // Uncle pool for mining
    uncle_pool: UnclePool,

    // MESS (ECBP-1100) state
    mess_config: MessConfig,
    mess_active: bool,
    eth_client: Option<EthClient>,
    /// Timestamp of the current head block (tracked for MESS stale-head detection).
    head_timestamp: u64,
    /// Non-blocking backoff: when the EL returns SYNCING, we set this instant
    /// and skip drain_and_process until the backoff expires.
    syncing_backoff_until: Option<Instant>,

    /// Channel to notify the mining coordinator when a new head is accepted.
    new_head_tx: Option<mpsc::Sender<(B256, u64)>>,
}

impl SyncManager {
    pub fn new(chain: ChainTracker, mess_config: MessConfig, eth_endpoint: Option<&str>) -> Self {
        let head = chain.head_number();
        let eth_client = eth_endpoint.map(EthClient::new);
        if !mess_config.is_disabled() {
            info!("MESS (ECBP-1100) configured, will activate when conditions are met");
        }
        Self {
            chain,
            next_request_id: 1,
            peers: HashMap::new(),
            phase: SyncPhase::CatchUp(CatchUpState::WaitingForPeers {
                entered_at: Instant::now(),
            }),
            header_peer: None,
            pending_header_request: None,
            buffer: BTreeMap::new(),
            buffer_drain_head: head + 1,
            pending_body_requests: Vec::new(),
            inflight_body_blocks: BTreeSet::new(),
            blocks_since_fcu: 0,
            ethash_caches: HashMap::new(),
            last_header: None,
            headers_exhausted: false,
            skip_pow: false,
            pending_tip_fetches: HashMap::new(),
            orphan_blocks: HashMap::new(),
            orphan_resolve_depth: 0,
            seen_blocks: std::collections::HashSet::new(),
            seen_blocks_prev: std::collections::HashSet::new(),
            uncle_pool: UnclePool::new(),
            mess_config,
            mess_active: false,
            eth_client,
            head_timestamp: 0,
            syncing_backoff_until: None,
            new_head_tx: None,
        }
    }

    /// Set the head timestamp (used at startup to initialize from EL state).
    pub fn set_head_timestamp(&mut self, ts: u64) {
        self.head_timestamp = ts;
    }

    /// Set a channel to notify when a new head block is accepted.
    pub fn set_new_head_notify(&mut self, tx: mpsc::Sender<(B256, u64)>) {
        self.new_head_tx = Some(tx);
    }

    /// Skip PoW verification (for testing only).
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn set_skip_pow(&mut self, skip: bool) {
        self.skip_pow = skip;
    }

    /// Force Pipeline mode (for testing only).
    #[cfg(any(test, feature = "test-helpers"))]
    pub fn set_pipeline_mode(&mut self) {
        self.phase = SyncPhase::Pipeline;
    }

    pub fn chain(&self) -> &ChainTracker {
        &self.chain
    }

    pub fn chain_mut(&mut self) -> &mut ChainTracker {
        &mut self.chain
    }

    pub fn is_tip_following(&self) -> bool {
        matches!(self.phase, SyncPhase::TipFollowing)
    }

    /// Get current uncle candidates for mining.
    pub fn get_uncle_candidates(&self) -> Vec<BlockHeader> {
        self.uncle_pool.get_best_uncles(self.chain.head_number())
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        id
    }

    fn has_no_header_peer(&self) -> bool {
        self.header_peer.is_none()
    }

    pub async fn on_peer_connected(
        &mut self,
        node_id: [u8; 64],
        client_id: &str,
        td: Vec<u8>,
        best_hash: [u8; 32],
        peer_manager: &(impl SyncPeerManager + ?Sized),
    ) {
        let _ = client_id; // used by caller for logging
        self.peers.insert(
            node_id,
            PeerInfo {
                td,
                best_hash,
                failed_requests: 0,
            },
        );

        self.update_mess_status();

        match &self.phase {
            SyncPhase::CatchUp(CatchUpState::WaitingForPeers { .. }) => {
                self.try_catchup_start(peer_manager).await;
            }
            SyncPhase::Pipeline => {
                if self.has_no_header_peer() {
                    self.try_start_sync(peer_manager).await;
                } else {
                    // New peer available — try to dispatch bodies to it
                    self.dispatch_body_requests(peer_manager).await;
                }
            }
            SyncPhase::TipFollowing => {
                // Check if this peer has significantly higher TD — fall back to Pipeline
                let Some(peer_info) = self.peers.get(&node_id) else {
                    return;
                };
                let peer_td = bytes_to_u256(&peer_info.td);
                let our_td = self.chain.head_td();
                // Dynamic threshold: avg_difficulty_per_block * PIPELINE_FALLBACK_BLOCKS.
                // If we have no blocks yet (head_number == 0), don't trigger pipeline
                // since we have no data to estimate difficulty.
                let head_number = self.chain.head_number();
                let threshold = if head_number == 0 {
                    alloy_primitives::U256::MAX
                } else {
                    let avg_difficulty = our_td / alloy_primitives::U256::from(head_number);
                    avg_difficulty * alloy_primitives::U256::from(PIPELINE_FALLBACK_BLOCKS)
                };
                if peer_td > our_td + threshold {
                    info!(
                        peer_td = %peer_td,
                        our_td = %our_td,
                        "tip: peer has much higher TD, falling back to pipeline"
                    );
                    self.phase = SyncPhase::Pipeline;
                    self.try_start_sync(peer_manager).await;
                }
            }
            _ => {
                // In other CatchUp sub-states, nothing to do on new peer
            }
        }
    }

    pub async fn on_peer_disconnected(
        &mut self,
        node_id: [u8; 64],
        peer_manager: &(impl SyncPeerManager + ?Sized),
    ) {
        self.peers.remove(&node_id);
        self.update_mess_status();

        // If this was our header peer, rotate
        if self.header_peer == Some(node_id) {
            info!(
                node_id = %hex::encode(&node_id[..8]),
                "header peer disconnected, rotating"
            );
            self.pending_header_request = None;
            self.pick_header_peer();
            if self.header_peer.is_some() && !self.headers_exhausted {
                self.request_headers(peer_manager).await;
            }
        }

        // Redistribute any body requests from this peer
        let mut redistributed = Vec::new();
        self.pending_body_requests.retain(|req| {
            if req.peer_id == node_id {
                redistributed.extend(req.block_numbers.iter().copied());
                false
            } else {
                true
            }
        });
        for num in &redistributed {
            self.inflight_body_blocks.remove(num);
        }

        if !redistributed.is_empty() {
            debug!(
                count = redistributed.len(),
                "redistributing bodies from disconnected peer"
            );
            self.dispatch_body_requests(peer_manager).await;
        }

        // If we lost all peers, reset
        if self.peers.is_empty() {
            self.reset_sync_state();
        }
    }

    pub async fn on_block_headers(
        &mut self,
        node_id: [u8; 64],
        request_id: u64,
        headers_raw: Vec<Vec<u8>>,
        peer_manager: &(impl SyncPeerManager + ?Sized),
        engine: &(impl SyncEngine + ?Sized),
    ) {
        // Handle CatchUp-phase header responses
        if self
            .handle_catchup_headers(node_id, request_id, &headers_raw, peer_manager, engine)
            .await
        {
            return;
        }

        // Handle TipFollowing fetch responses
        if matches!(self.phase, SyncPhase::TipFollowing) {
            // Check for batch ancestor header response first
            if let Some((body_req_id, hashes)) =
                self.handle_ancestor_headers(node_id, request_id, &headers_raw)
            {
                if self.pending_tip_fetches.contains_key(&body_req_id) {
                    let cmd = PeerCommand::GetBlockBodies {
                        request_id: body_req_id,
                        hashes: hashes.iter().map(|h| h.0).collect(),
                    };
                    if !peer_manager.send_command(&node_id, cmd).await {
                        debug!(peer = %hex::encode(&node_id[..8]), "send_command failed for tip fetch");
                    }
                }
                return;
            }

            if let Some((body_req_id, block_hash)) =
                self.handle_tip_fetch_header(node_id, request_id, &headers_raw)
            {
                // If we got a header, send GetBlockBodies
                if self.pending_tip_fetches.contains_key(&body_req_id) {
                    let cmd = PeerCommand::GetBlockBodies {
                        request_id: body_req_id,
                        hashes: vec![block_hash.0],
                    };
                    if !peer_manager.send_command(&node_id, cmd).await {
                        debug!(peer = %hex::encode(&node_id[..8]), "send_command failed for tip fetch");
                    }
                }
                return;
            }
        }

        // Verify this is our pending header request (Pipeline mode)
        let expected = matches!(&self.pending_header_request, Some(req) if req.request_id == request_id && req.peer == node_id);
        if !expected {
            return;
        }
        self.pending_header_request = None;

        // 0 headers = caught up
        if headers_raw.is_empty() {
            info!("sync caught up, no more headers");
            self.headers_exhausted = true;

            // If buffer is empty and no body requests pending, we're done
            if self.buffer.is_empty() && self.pending_body_requests.is_empty() {
                self.send_fcu(engine).await;
                self.transition_to_tip_following();
            }
            return;
        }

        // Determine expected parent hash and number for continuity validation
        let (expected_parent, mut expected_number) =
            if let Some((&num, entry)) = self.buffer.iter().next_back() {
                (entry.block_hash, num + 1)
            } else {
                (
                    self.chain.head_hash().unwrap_or(B256::ZERO),
                    self.buffer_drain_head,
                )
            };
        let mut prev_hash = expected_parent;

        // Decode and validate headers
        let mut decoded = Vec::with_capacity(headers_raw.len());
        for (i, raw) in headers_raw.iter().enumerate() {
            let header = match decode_block_header(raw) {
                Ok(h) => h,
                Err(e) => {
                    warn!(err = %e, index = i, "header decode failed, removing peer");
                    self.remove_header_peer_and_rotate(node_id, peer_manager)
                        .await;
                    return;
                }
            };

            let block_hash = hash_raw_header(raw);

            if header.parent_hash != prev_hash {
                warn!(
                    index = i,
                    expected = %prev_hash,
                    got = %header.parent_hash,
                    "headers not contiguous (parent_hash), removing peer"
                );
                self.remove_header_peer_and_rotate(node_id, peer_manager)
                    .await;
                return;
            }

            if header.number != expected_number {
                warn!(
                    index = i,
                    expected = expected_number,
                    got = header.number,
                    "headers not contiguous (number), removing peer"
                );
                self.remove_header_peer_and_rotate(node_id, peer_manager)
                    .await;
                return;
            }

            prev_hash = block_hash;
            expected_number += 1;
            decoded.push((block_hash, raw.clone(), header));
        }

        // Validate difficulty.
        // Note: if the parent of the first header can't be fetched from the EL,
        // we skip difficulty validation for that header only. PoW verification
        // (below) does NOT cover this — it validates work against the difficulty
        // declared in the header, not that the declared difficulty is correct per
        // the parent. However, the EL will reject any header with wrong difficulty
        // via newPayload (INVALID), so the worst case is wasted pipeline work,
        // not a consensus violation. Rejecting the batch on transient EL errors
        // would stall sync unnecessarily.
        for i in 0..decoded.len() {
            let parent = if i == 0 {
                // Try last header from buffer, then last_header, then fetch from EL
                if let Some(entry) = self.buffer.values().next_back() {
                    entry.header.clone()
                } else if let Some(h) = &self.last_header {
                    h.clone()
                } else if let Some(ref eth_client) = self.eth_client {
                    match eth_client.get_block_by_hash(decoded[0].2.parent_hash).await {
                        Ok(block) => block.to_block_header(),
                        Err(e) => {
                            warn!(
                                err = %e,
                                parent = %decoded[0].2.parent_hash,
                                "failed to fetch parent from EL, skipping difficulty validation for first header"
                            );
                            continue;
                        }
                    }
                } else {
                    warn!(
                        "no EL client available, skipping difficulty validation for first header"
                    );
                    continue;
                }
            } else {
                decoded[i - 1].2.clone()
            };
            let header = &decoded[i].2;
            if let Err(e) = consensus::difficulty::validate_difficulty(header, &parent) {
                warn!(err = %e, "difficulty validation failed, removing peer");
                self.remove_header_peer_and_rotate(node_id, peer_manager)
                    .await;
                return;
            }
        }

        // PoW verification: verify ALL headers in the batch
        if !self.skip_pow && !decoded.is_empty() {
            let epochs_needed: BTreeSet<(u64, u64)> = decoded
                .iter()
                .map(|(_, _, h)| {
                    let num = h.number;
                    (
                        consensus::ethash::epoch(num),
                        consensus::ethash::epoch_length(num),
                    )
                })
                .collect();

            let caches: HashMap<u64, Arc<Vec<u8>>> = epochs_needed
                .iter()
                .map(|&(ep, ep_len)| (ep, self.get_ethash_cache_for_epoch(ep, ep_len)))
                .collect();

            let headers_for_pow: Vec<BlockHeader> =
                decoded.iter().map(|(_, _, h)| h.clone()).collect();

            let pow_result = match tokio::task::spawn_blocking(move || {
                for header in &headers_for_pow {
                    let ep = consensus::ethash::epoch(header.number);
                    let cache = caches.get(&ep).unwrap();
                    if let Err(e) = consensus::ethash::verify_pow(header, cache) {
                        return Err((header.number, format!("{}", e)));
                    }
                }
                Ok(())
            })
            .await
            {
                Ok(result) => result,
                Err(e) => {
                    error!(err = %e, "PoW verification task failed");
                    return;
                }
            };

            if let Err((number, e)) = pow_result {
                warn!(err = %e, number, "invalid PoW, removing peer");
                self.remove_header_peer_and_rotate(node_id, peer_manager)
                    .await;
                return;
            }
        }

        info!(
            count = decoded.len(),
            from = decoded.first().map(|h| h.2.number).unwrap_or(0),
            to = decoded.last().map(|h| h.2.number).unwrap_or(0),
            verified_pow = decoded.len(),
            "decoded headers"
        );

        // Insert into buffer
        for (block_hash, _raw, header) in decoded {
            self.buffer.insert(
                header.number,
                BlockEntry {
                    header,
                    block_hash,
                    body: None,
                },
            );
        }

        // Pipeline: dispatch bodies AND request next headers concurrently
        self.dispatch_body_requests(peer_manager).await;

        // Request next batch if buffer not too large (backpressure)
        if self.buffer.len() < MAX_BUFFER_SIZE && !self.headers_exhausted {
            self.request_headers(peer_manager).await;
        }
    }

    pub async fn on_block_bodies(
        &mut self,
        node_id: [u8; 64],
        request_id: u64,
        bodies_raw: Vec<Vec<u8>>,
        peer_manager: &(impl SyncPeerManager + ?Sized),
        engine: &(impl SyncEngine + ?Sized),
    ) {
        // Handle TipFollowing fetch body responses
        if matches!(self.phase, SyncPhase::TipFollowing) {
            if let Some(fetch) = self.pending_tip_fetches.remove(&request_id) {
                if fetch.peer == node_id {
                    // Handle batch ancestor bodies
                    if let TipFetchPhase::AncestorBodies { headers } = fetch.phase {
                        if bodies_raw.len() != headers.len() {
                            debug!(
                                expected = headers.len(),
                                got = bodies_raw.len(),
                                "ancestor fetch: body count mismatch"
                            );
                            // Process whatever we got (oldest-first, already ordered)
                        }
                        let count = bodies_raw.len().min(headers.len());
                        for i in 0..count {
                            let (ref header, ref header_rlp) = headers[i];
                            match decode_block_body(&bodies_raw[i]) {
                                Ok(body) => {
                                    let block_hash = hash_raw_header(header_rlp);
                                    self.process_tip_block(
                                        TipBlock {
                                            header: header.clone(),
                                            header_rlp: header_rlp.clone(),
                                            block_hash,
                                            transactions: body.transactions,
                                            uncles: body.uncles,
                                        },
                                        node_id,
                                        peer_manager,
                                        engine,
                                    )
                                    .await;
                                }
                                Err(e) => {
                                    debug!(err = %e, index = i, "ancestor fetch: body decode failed");
                                    break;
                                }
                            }
                        }
                        return;
                    }

                    if let TipFetchPhase::Body { header, header_rlp } = fetch.phase {
                        if let Some(body_raw) = bodies_raw.first() {
                            match decode_block_body(body_raw) {
                                Ok(body) => {
                                    let block_hash = hash_raw_header(&header_rlp);
                                    self.process_tip_block(
                                        TipBlock {
                                            header: *header,
                                            header_rlp,
                                            block_hash,
                                            transactions: body.transactions,
                                            uncles: body.uncles,
                                        },
                                        node_id,
                                        peer_manager,
                                        engine,
                                    )
                                    .await;
                                }
                                Err(e) => {
                                    debug!(err = %e, "tip fetch: body decode failed");
                                }
                            }
                        } else {
                            debug!("tip fetch: peer returned 0 bodies");
                        }
                        return;
                    }
                }
                // If we didn't match, put it back (shouldn't happen)
                self.pending_tip_fetches.insert(request_id, fetch);
            }
        }

        // Find the matching body request
        let req_idx = self
            .pending_body_requests
            .iter()
            .position(|req| req.request_id == request_id && req.peer_id == node_id);

        let req_idx = match req_idx {
            Some(i) => i,
            None => return,
        };

        let body_req = self.pending_body_requests.remove(req_idx);

        if bodies_raw.len() > body_req.block_numbers.len() {
            warn!(
                bodies = bodies_raw.len(),
                expected = body_req.block_numbers.len(),
                "more bodies than requested, removing peer"
            );
            self.remove_body_peer(node_id);
            for num in &body_req.block_numbers {
                self.inflight_body_blocks.remove(num);
            }
            self.dispatch_body_requests(peer_manager).await;
            return;
        }

        // Empty response = peer doesn't have these blocks, penalize
        if bodies_raw.is_empty() {
            debug!(
                peer = %hex::encode(&node_id[..8]),
                requested = body_req.block_numbers.len(),
                "peer returned 0 bodies, penalizing"
            );
            if let Some(info) = self.peers.get_mut(&node_id) {
                info.failed_requests += 1;
            }
            for num in &body_req.block_numbers {
                self.inflight_body_blocks.remove(num);
            }
            self.dispatch_body_requests(peer_manager).await;
            return;
        }

        // Match bodies to block numbers (in order).
        // Validate transactions_root against the header we already have — this
        // catches both reordered responses and corrupted/wrong body data.
        let matched = bodies_raw.len();
        for (i, body_raw) in bodies_raw.iter().enumerate() {
            let block_num = body_req.block_numbers[i];
            self.inflight_body_blocks.remove(&block_num);

            let body = match decode_block_body(body_raw) {
                Ok(b) => b,
                Err(e) => {
                    warn!(err = %e, block = block_num, "body decode failed, removing peer");
                    self.remove_body_peer(node_id);
                    // Un-mark remaining inflight blocks
                    for num in &body_req.block_numbers[i..] {
                        self.inflight_body_blocks.remove(num);
                    }
                    self.dispatch_body_requests(peer_manager).await;
                    return;
                }
            };

            if let Some(entry) = self.buffer.get_mut(&block_num) {
                // Verify transactions_root matches the header
                let tx_root = chain::trie::ordered_trie_root(&body.transactions);
                if tx_root != entry.header.transactions_root {
                    warn!(
                        block = block_num,
                        expected = %entry.header.transactions_root,
                        got = %tx_root,
                        "body transactions_root mismatch, removing peer"
                    );
                    self.remove_body_peer(node_id);
                    for num in &body_req.block_numbers[i..] {
                        self.inflight_body_blocks.remove(num);
                    }
                    self.dispatch_body_requests(peer_manager).await;
                    return;
                }
                entry.body = Some(body);
            }
        }

        // Un-mark any blocks that weren't returned (partial response)
        if matched < body_req.block_numbers.len() {
            debug!(
                got = matched,
                requested = body_req.block_numbers.len(),
                "partial body response"
            );
            for num in &body_req.block_numbers[matched..] {
                self.inflight_body_blocks.remove(num);
            }
        }

        // Drain contiguous complete blocks to EL
        self.drain_and_process(engine).await;

        // Dispatch more body requests for remaining blocks
        self.dispatch_body_requests(peer_manager).await;

        // If headers were paused due to backpressure, resume
        if self.buffer.len() < MAX_BUFFER_SIZE
            && !self.headers_exhausted
            && self.pending_header_request.is_none()
        {
            self.request_headers(peer_manager).await;
        }

        // Check if sync is complete
        if self.headers_exhausted && self.buffer.is_empty() && self.pending_body_requests.is_empty()
        {
            info!("pipeline sync complete");
            self.send_fcu(engine).await;
            self.transition_to_tip_following();
        }
    }

    pub async fn check_timeouts(&mut self, peer_manager: &(impl SyncPeerManager + ?Sized)) {
        let now = Instant::now();

        // Check WaitingForPeers timeout: if we have at least 1 good peer but
        // haven't reached CATCHUP_MIN_PEERS, fall back to Pipeline after timeout
        if let SyncPhase::CatchUp(CatchUpState::WaitingForPeers { entered_at }) = &self.phase {
            if now.duration_since(*entered_at).as_secs() >= CATCHUP_PEER_WAIT_SECS {
                let good_peers: usize = self
                    .peers
                    .iter()
                    .filter(|(_, info)| {
                        !info.td.is_empty() && info.failed_requests < MAX_FAILED_REQUESTS
                    })
                    .count();
                if good_peers >= 1 {
                    warn!(
                        good_peers,
                        min_required = CATCHUP_MIN_PEERS,
                        "catch-up: timed out waiting for peers, falling back to pipeline"
                    );
                    self.phase = SyncPhase::Pipeline;
                    self.try_start_sync(peer_manager).await;
                    return;
                }
            }
        }

        // Check catch-up phase timeouts
        let catchup_timed_out = match &self.phase {
            SyncPhase::CatchUp(CatchUpState::QueryingBestHeader { peer, sent_at, .. }) => {
                if now.duration_since(*sent_at).as_secs() >= HEADER_TIMEOUT_SECS {
                    let peer_id = *peer;
                    warn!(
                        node_id = %hex::encode(&peer_id[..8]),
                        "catch-up: best header request timed out"
                    );
                    if let Some(info) = self.peers.get_mut(&peer_id) {
                        info.failed_requests += 1;
                    }
                    true
                } else {
                    false
                }
            }
            SyncPhase::CatchUp(CatchUpState::QueryingTargetHeader { peer, sent_at, .. }) => {
                if now.duration_since(*sent_at).as_secs() >= HEADER_TIMEOUT_SECS {
                    let peer_id = *peer;
                    warn!(
                        node_id = %hex::encode(&peer_id[..8]),
                        "catch-up: target header request timed out"
                    );
                    if let Some(info) = self.peers.get_mut(&peer_id) {
                        info.failed_requests += 1;
                    }
                    true
                } else {
                    false
                }
            }
            _ => false,
        };
        if catchup_timed_out {
            // Reset to WaitingForPeers and try again with a different peer
            self.phase = SyncPhase::CatchUp(CatchUpState::WaitingForPeers {
                entered_at: Instant::now(),
            });
            // Trigger peer selection again
            self.try_catchup_start(peer_manager).await;
        }

        // Check header request timeout (Pipeline mode)
        if let Some(ref req) = self.pending_header_request {
            if now.duration_since(req.sent_at).as_secs() >= HEADER_TIMEOUT_SECS {
                let peer_id = req.peer;
                warn!(
                    node_id = %hex::encode(&peer_id[..8]),
                    "header request timed out, rotating"
                );
                if let Some(info) = self.peers.get_mut(&peer_id) {
                    info.failed_requests += 1;
                }
                self.pending_header_request = None;
                self.pick_header_peer();
                if self.header_peer.is_some() && !self.headers_exhausted {
                    self.request_headers(peer_manager).await;
                }
            }
        }

        // Check body request timeouts individually
        let mut timed_out = Vec::new();
        for (i, req) in self.pending_body_requests.iter().enumerate() {
            if now.duration_since(req.sent_at).as_secs() >= BODY_TIMEOUT_SECS {
                timed_out.push(i);
            }
        }

        if !timed_out.is_empty() {
            // Remove in reverse order to preserve indices
            let mut redistributed_blocks = Vec::new();
            for &i in timed_out.iter().rev() {
                let req = self.pending_body_requests.remove(i);
                warn!(
                    node_id = %hex::encode(&req.peer_id[..8]),
                    blocks = req.block_numbers.len(),
                    "body request timed out, redistributing"
                );
                if let Some(info) = self.peers.get_mut(&req.peer_id) {
                    info.failed_requests += 1;
                }
                for num in &req.block_numbers {
                    self.inflight_body_blocks.remove(num);
                }
                redistributed_blocks.extend(req.block_numbers);
            }

            if !redistributed_blocks.is_empty() {
                self.dispatch_body_requests(peer_manager).await;
            }
        }

        // TipFollowing: clean up timed-out tip fetches
        if matches!(self.phase, SyncPhase::TipFollowing) {
            let timed_out_ids: Vec<u64> = self
                .pending_tip_fetches
                .iter()
                .filter(|(_, f)| now.duration_since(f.sent_at).as_secs() >= TIP_FETCH_TIMEOUT_SECS)
                .map(|(id, _)| *id)
                .collect();
            for id in timed_out_ids {
                if let Some(fetch) = self.pending_tip_fetches.remove(&id) {
                    debug!(
                        request_id = fetch.request_id,
                        block_number = fetch.block_number,
                        hash = %fetch.block_hash,
                        "tip fetch timed out"
                    );
                }
            }

            // Clean up old orphans (remove individual expired entries, drop key if empty)
            let mut empty_parents: Vec<B256> = Vec::new();
            for (parent, entries) in self.orphan_blocks.iter_mut() {
                entries
                    .retain(|o| now.duration_since(o.received_at).as_secs() < ORPHAN_TIMEOUT_SECS);
                if entries.is_empty() {
                    empty_parents.push(*parent);
                }
            }
            for hash in empty_parents {
                debug!(parent = %hash, "orphan entries expired");
                self.orphan_blocks.remove(&hash);
            }

            // Limit seen_blocks set to avoid unbounded growth (double-buffer rotation)
            if self.seen_blocks.len() > SEEN_BLOCKS_CAP {
                self.seen_blocks_prev = std::mem::take(&mut self.seen_blocks);
            }
        }
    }

    /// Dispatch body requests to available peers for blocks in the buffer that
    /// don't have a body yet and aren't already in-flight.
    async fn dispatch_body_requests(&mut self, peer_manager: &(impl SyncPeerManager + ?Sized)) {
        // Collect blocks needing bodies
        let needed: Vec<(u64, [u8; 32])> = self
            .buffer
            .iter()
            .filter(|(num, entry)| entry.body.is_none() && !self.inflight_body_blocks.contains(num))
            .map(|(num, entry)| (*num, entry.block_hash.0))
            .collect();

        if needed.is_empty() {
            return;
        }

        // Get available peers: connected, not at max failures, not already doing a body request
        let busy_peers: BTreeSet<[u8; 64]> = self
            .pending_body_requests
            .iter()
            .map(|r| r.peer_id)
            .collect();

        let mut available_peers: Vec<[u8; 64]> = self
            .peers
            .iter()
            .filter(|(id, info)| {
                info.failed_requests < MAX_FAILED_REQUESTS
                    && !busy_peers.contains(*id)
                    && !info.td.is_empty() // skip peers with no TD (wrong network / no chain)
            })
            .map(|(id, _)| *id)
            .collect();

        debug!(
            needed = needed.len(),
            available_peers = available_peers.len(),
            busy_peers = busy_peers.len(),
            pending_body_reqs = self.pending_body_requests.len(),
            buffer_size = self.buffer.len(),
            "dispatch_body_requests"
        );

        if available_peers.is_empty() {
            return;
        }

        // Chunk the needed blocks and assign to peers
        for chunk in needed.chunks(BODY_CHUNK_SIZE) {
            if available_peers.is_empty() {
                break;
            }

            let peer_id = available_peers.remove(0);
            let block_numbers: Vec<u64> = chunk.iter().map(|(num, _)| *num).collect();
            let hashes: Vec<[u8; 32]> = chunk.iter().map(|(_, hash)| *hash).collect();

            let request_id = self.next_id();
            let cmd = PeerCommand::GetBlockBodies { request_id, hashes };

            if peer_manager.send_command(&peer_id, cmd).await {
                info!(
                    peer = %hex::encode(&peer_id[..8]),
                    count = block_numbers.len(),
                    from = block_numbers.first().copied().unwrap_or(0),
                    to = block_numbers.last().copied().unwrap_or(0),
                    request_id,
                    "dispatched body request"
                );
                for &num in &block_numbers {
                    self.inflight_body_blocks.insert(num);
                }
                self.pending_body_requests.push(BodyRequest {
                    peer_id,
                    request_id,
                    block_numbers,
                    sent_at: Instant::now(),
                });
            } else {
                warn!(
                    peer = %hex::encode(&peer_id[..8]),
                    "send_command failed for body request"
                );
            }
        }
    }

    /// Drain contiguous complete blocks from the buffer and submit to the EL in batches.
    async fn drain_and_process(&mut self, engine: &(impl SyncEngine + ?Sized)) {
        // Non-blocking backoff: if the EL was SYNCING, skip until the backoff expires.
        if let Some(until) = self.syncing_backoff_until {
            if Instant::now() < until {
                return;
            }
            self.syncing_backoff_until = None;
        }

        loop {
            // Collect a batch of contiguous blocks with valid uncle hashes.
            let mut batch_entries: Vec<(BlockHeader, B256, ExecutionPayload)> = Vec::new();

            loop {
                if batch_entries.len() >= DRAIN_BATCH_SIZE {
                    break;
                }
                let num = self.buffer_drain_head + batch_entries.len() as u64;

                // Peek at the entry first (don't remove yet)
                let entry = match self.buffer.get(&num) {
                    Some(e) if e.body.is_some() => e,
                    _ => break,
                };

                // Validate uncles (count, depth, hash) BEFORE removing.
                // We use validate_uncles_basic (no known-uncles set) because the CL is
                // stateless and doesn't track recent uncles. Full duplicate-uncle validation
                // is performed by the EL when it executes the block via newPayload.
                let body = entry.body.as_ref().unwrap();
                if let Err(e) = validate_uncles_basic(&entry.header, &body.uncles) {
                    warn!(
                        block = entry.header.number,
                        err = %e,
                        "uncle validation failed, dropping block"
                    );
                    self.buffer.remove(&num);
                    self.buffer_drain_head = num + 1;
                    break;
                }

                // Now safe to remove and build payload
                let entry = self.buffer.remove(&num).unwrap();
                let body = entry.body.unwrap();
                let payload = block_to_payload_with_hash(
                    &entry.header,
                    entry.block_hash,
                    &body.uncles,
                    &body.transactions,
                );

                batch_entries.push((entry.header, entry.block_hash, payload));
            }

            if batch_entries.is_empty() {
                break;
            }

            // Submit batch to EL.
            let payload_refs: Vec<&ExecutionPayload> =
                batch_entries.iter().map(|(_, _, p)| p).collect();

            info!(
                count = batch_entries.len(),
                from = batch_entries.first().map(|(h, _, _)| h.number).unwrap_or(0),
                to = batch_entries.last().map(|(h, _, _)| h.number).unwrap_or(0),
                "submitting block batch to EL"
            );

            let statuses = match engine.new_payload_v2_batch(&payload_refs).await {
                Ok(s) => s,
                Err(e) => {
                    error!(err = %e, "EL connection error, pausing sync");
                    self.reset_sync_state();
                    return;
                }
            };

            debug!(count = statuses.len(), "batch newPayloadV2 response");

            // Process results one by one.
            for (i, status) in statuses.into_iter().enumerate() {
                let (ref header, ref block_hash, _) = batch_entries[i];

                if status.status == STATUS_INVALID {
                    warn!(
                        number = header.number,
                        hash = %block_hash,
                        err = ?status.validation_error,
                        "EL returned INVALID"
                    );
                    self.buffer.clear();
                    self.inflight_body_blocks.clear();
                    self.pending_body_requests.clear();
                    self.reset_sync_state();
                    return;
                }

                if status.status == STATUS_SYNCING {
                    warn!(
                        number = header.number,
                        status = %status.status,
                        "EL is syncing, pausing pipeline (backoff 5s)"
                    );
                    // Don't advance buffer_drain_head — will retry these blocks
                    self.syncing_backoff_until =
                        Some(Instant::now() + std::time::Duration::from_secs(5));
                    return;
                }

                // VALID = fully validated; ACCEPTED = EL queued it for async validation
                // (e.g. parent not yet processed). Both are OK during pipeline sync.
                if status.status == STATUS_VALID || status.status == STATUS_ACCEPTED {
                    debug!(
                        number = header.number,
                        hash = %block_hash,
                        status = %status.status,
                        "block accepted"
                    );
                } else {
                    warn!(
                        number = header.number,
                        status = %status.status,
                        "newPayload unexpected status"
                    );
                }

                // Advance in-memory chain tracker
                let new_td = self.chain.head_td() + header.difficulty;
                self.chain.advance_head(*block_hash, header.number, new_td);

                self.head_timestamp = header.timestamp;
                self.last_header = Some(header.clone());
                self.blocks_since_fcu += 1;
                self.buffer_drain_head = header.number + 1;
            }

            if self.blocks_since_fcu >= FCU_INTERVAL {
                self.send_fcu(engine).await;
            }
        }
    }

    fn get_ethash_cache_for_epoch(&mut self, ep: u64, ep_len: u64) -> Arc<Vec<u8>> {
        if !self.ethash_caches.contains_key(&ep) && self.ethash_caches.len() >= MAX_ETHASH_CACHES {
            let furthest = *self
                .ethash_caches
                .keys()
                .max_by_key(|&&k| k.abs_diff(ep))
                .unwrap();
            info!(evicted_epoch = furthest, "evicting old ethash cache");
            self.ethash_caches.remove(&furthest);
        }

        Arc::clone(self.ethash_caches.entry(ep).or_insert_with(|| {
            info!(epoch = ep, "generating ethash cache");
            Arc::new(consensus::ethash::make_cache(ep, ep_len))
        }))
    }

    /// Update MESS active status based on current peer count and head age.
    fn update_mess_status(&mut self) {
        if self.mess_config.is_disabled() {
            return;
        }
        let head_timestamp = self.head_timestamp;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let was_active = self.mess_active;
        self.mess_active = mess::should_be_active(self.peers.len(), head_timestamp, now);
        if self.mess_active != was_active {
            info!(
                "MESS {}",
                if self.mess_active {
                    "activated"
                } else {
                    "deactivated"
                }
            );
        }
    }

    async fn try_start_sync(&mut self, peer_manager: &(impl SyncPeerManager + ?Sized)) {
        self.pick_header_peer();

        if let Some(peer_id) = self.header_peer {
            info!(
                node_id = %hex::encode(&peer_id[..8]),
                head = self.chain.head_number(),
                "starting pipeline sync"
            );
            self.headers_exhausted = false;
            self.buffer_drain_head = self.chain.head_number() + 1;
            self.request_headers(peer_manager).await;
        }
    }

    fn pick_header_peer(&mut self) {
        self.header_peer = self
            .peers
            .iter()
            .filter(|(_, info)| info.failed_requests < MAX_FAILED_REQUESTS)
            .max_by_key(|(_, info)| bytes_to_u256(&info.td))
            .map(|(id, _)| *id);
    }

    async fn request_headers(&mut self, peer_manager: &(impl SyncPeerManager + ?Sized)) {
        // Backpressure: don't request if buffer is too large
        if self.buffer.len() >= MAX_BUFFER_SIZE {
            debug!(
                buffer_size = self.buffer.len(),
                "backpressure: skipping header request"
            );
            return;
        }

        // Don't send if there's already a pending request
        if self.pending_header_request.is_some() {
            return;
        }

        let peer_id = match self.header_peer {
            Some(id) => id,
            None => return,
        };

        // Start from after the highest block in the buffer, or head+1
        let start_number = if let Some((&last_num, _)) = self.buffer.iter().next_back() {
            last_num + 1
        } else {
            self.buffer_drain_head
        };

        let start = devp2p::bytes::encode_u64(start_number);
        let request_id = self.next_id();

        let cmd = PeerCommand::GetBlockHeaders {
            request_id,
            start,
            limit: HEADER_BATCH_SIZE,
            skip: 0,
            reverse: false,
        };

        if peer_manager.send_command(&peer_id, cmd).await {
            self.pending_header_request = Some(PendingRequest {
                request_id,
                peer: peer_id,
                sent_at: Instant::now(),
            });
            debug!(
                from = start_number,
                batch = HEADER_BATCH_SIZE,
                request_id,
                "requested headers"
            );
        } else {
            warn!("failed to send GetBlockHeaders to peer");
        }
    }

    async fn send_fcu(&mut self, engine: &(impl SyncEngine + ?Sized)) {
        let fcs = self.chain.fork_choice_state();

        let state = ForkchoiceState {
            head_block_hash: fcs.head,
            safe_block_hash: fcs.safe,
            finalized_block_hash: fcs.finalized,
        };

        match engine.forkchoice_updated_v2(&state, None).await {
            Ok(resp) => {
                if resp.payload_status.status == STATUS_VALID {
                    info!(
                        status = %resp.payload_status.status,
                        head = %fcs.head,
                        "forkchoice updated"
                    );
                } else {
                    warn!(
                        status = %resp.payload_status.status,
                        head = %fcs.head,
                        "FCU non-VALID response"
                    );
                }
            }
            Err(e) => {
                error!(err = %e, "forkchoice update failed");
            }
        }

        self.blocks_since_fcu = 0;
    }

    async fn remove_header_peer_and_rotate(
        &mut self,
        node_id: [u8; 64],
        peer_manager: &(impl SyncPeerManager + ?Sized),
    ) {
        self.peers.remove(&node_id);
        self.pending_header_request = None;
        self.pick_header_peer();
        if self.header_peer.is_some() && !self.headers_exhausted {
            self.request_headers(peer_manager).await;
        }
    }

    fn remove_body_peer(&mut self, node_id: [u8; 64]) {
        self.peers.remove(&node_id);
        // If the removed peer was also the header peer, clear the pending
        // header request and pick a new one to avoid a pipeline stall.
        if self.header_peer == Some(node_id) {
            self.pending_header_request = None;
            self.pick_header_peer();
        }
    }

    /// Try to start catch-up by picking the best peer and querying its best header.
    async fn try_catchup_start(&mut self, peer_manager: &(impl SyncPeerManager + ?Sized)) {
        if !matches!(
            self.phase,
            SyncPhase::CatchUp(CatchUpState::WaitingForPeers { .. })
        ) {
            return;
        }

        let good_peers: usize = self
            .peers
            .iter()
            .filter(|(_, info)| !info.td.is_empty() && info.failed_requests < MAX_FAILED_REQUESTS)
            .count();

        if good_peers < CATCHUP_MIN_PEERS {
            return;
        }

        let best_peer = self
            .peers
            .iter()
            .filter(|(_, info)| !info.td.is_empty() && info.failed_requests < MAX_FAILED_REQUESTS)
            .max_by_key(|(_, info)| bytes_to_u256(&info.td))
            .map(|(id, info)| (*id, info.best_hash));

        if let Some((peer_id, peer_best_hash)) = best_peer {
            let request_id = self.next_id();
            let cmd = PeerCommand::GetBlockHeaders {
                request_id,
                start: peer_best_hash.to_vec(),
                limit: 1,
                skip: 0,
                reverse: false,
            };
            if peer_manager.send_command(&peer_id, cmd).await {
                info!(
                    peer = %hex::encode(&peer_id[..8]),
                    best_hash = %hex::encode(&peer_best_hash[..8]),
                    "catch-up: querying best header"
                );
                self.phase = SyncPhase::CatchUp(CatchUpState::QueryingBestHeader {
                    peer: peer_id,
                    request_id,
                    sent_at: Instant::now(),
                });
            }
        }
    }

    fn reset_sync_state(&mut self) {
        self.header_peer = None;
        self.pending_header_request = None;
        self.pending_body_requests.clear();
        self.inflight_body_blocks.clear();
        self.buffer.clear();
        self.headers_exhausted = false;
    }

    /// Handle header responses during CatchUp phase. Returns true if consumed.
    async fn handle_catchup_headers(
        &mut self,
        node_id: [u8; 64],
        request_id: u64,
        headers_raw: &[Vec<u8>],
        peer_manager: &(impl SyncPeerManager + ?Sized),
        engine: &(impl SyncEngine + ?Sized),
    ) -> bool {
        match &self.phase {
            SyncPhase::CatchUp(CatchUpState::QueryingBestHeader {
                peer,
                request_id: rid,
                ..
            }) if *peer == node_id && *rid == request_id => {}
            SyncPhase::CatchUp(CatchUpState::QueryingTargetHeader {
                peer,
                request_id: rid,
                ..
            }) if *peer == node_id && *rid == request_id => {}
            _ => return false,
        }

        if headers_raw.is_empty() {
            warn!("catch-up: peer returned 0 headers, falling back to pipeline");
            self.phase = SyncPhase::Pipeline;
            self.try_start_sync(peer_manager).await;
            return true;
        }

        let header = match decode_block_header(&headers_raw[0]) {
            Ok(h) => h,
            Err(e) => {
                warn!(err = %e, "catch-up: failed to decode header, falling back to pipeline");
                self.phase = SyncPhase::Pipeline;
                self.try_start_sync(peer_manager).await;
                return true;
            }
        };

        // Take ownership of phase to inspect state
        let phase = std::mem::replace(
            &mut self.phase,
            SyncPhase::CatchUp(CatchUpState::WaitingForPeers {
                entered_at: Instant::now(),
            }),
        );

        match phase {
            SyncPhase::CatchUp(CatchUpState::QueryingBestHeader { peer, .. }) => {
                let best_number = header.number;
                let our_head = self.chain.head_number();

                if best_number <= our_head {
                    // Peer is behind us, skip catch-up and go straight to pipeline
                    info!(
                        best_number,
                        our_head, "catch-up: peer is behind our head, switching to pipeline"
                    );
                    self.phase = SyncPhase::Pipeline;
                    self.buffer_drain_head = our_head + 1;
                    self.try_start_sync(peer_manager).await;
                    return true;
                }

                if best_number <= CATCHUP_OFFSET {
                    // Chain is too short for catch-up, go straight to pipeline
                    info!(
                        best_number,
                        "catch-up: chain too short, switching to pipeline"
                    );
                    self.phase = SyncPhase::Pipeline;
                    self.try_start_sync(peer_manager).await;
                    return true;
                }

                let target_number = best_number - CATCHUP_OFFSET;
                let req_id = self.next_id();
                let cmd = PeerCommand::GetBlockHeaders {
                    request_id: req_id,
                    start: devp2p::bytes::encode_u64(target_number),
                    limit: 1,
                    skip: 0,
                    reverse: false,
                };

                if peer_manager.send_command(&peer, cmd).await {
                    info!(
                        best_number,
                        target_number, "catch-up: querying target header"
                    );
                    self.phase = SyncPhase::CatchUp(CatchUpState::QueryingTargetHeader {
                        peer,
                        best_number: target_number,
                        request_id: req_id,
                        sent_at: Instant::now(),
                    });
                } else {
                    warn!("catch-up: failed to send target header request");
                    self.phase = SyncPhase::Pipeline;
                    self.try_start_sync(peer_manager).await;
                }
            }
            SyncPhase::CatchUp(CatchUpState::QueryingTargetHeader { best_number, .. }) => {
                let target_hash = hash_raw_header(&headers_raw[0]);
                info!(
                    target_number = best_number,
                    target_hash = %target_hash,
                    "catch-up: sending FCU to EL"
                );

                let state = ForkchoiceState {
                    head_block_hash: target_hash,
                    safe_block_hash: target_hash,
                    finalized_block_hash: B256::ZERO,
                };

                match engine.forkchoice_updated_v2(&state, None).await {
                    Ok(resp) => {
                        info!(
                            status = %resp.payload_status.status,
                            target = %target_hash,
                            "catch-up: FCU response"
                        );
                        if resp.payload_status.status == STATUS_VALID {
                            self.transition_to_pipeline(target_hash, best_number, peer_manager)
                                .await;
                        } else {
                            self.phase = SyncPhase::CatchUp(CatchUpState::Syncing {
                                target_hash,
                                target_number: best_number,
                            });
                        }
                    }
                    Err(e) => {
                        error!(err = %e, "catch-up: FCU failed");
                        self.phase = SyncPhase::CatchUp(CatchUpState::Syncing {
                            target_hash,
                            target_number: best_number,
                        });
                    }
                }
            }
            _ => {
                warn!("unexpected catch-up phase in handle_catchup_headers");
                return true;
            }
        }

        true
    }

    /// Called periodically (every ~10s) to re-send FCU during CatchUp::Syncing.
    pub async fn poll_catchup_fcu(
        &mut self,
        engine: &(impl SyncEngine + ?Sized),
        peer_manager: &(impl SyncPeerManager + ?Sized),
    ) {
        let (target_hash, target_number) = match &self.phase {
            SyncPhase::CatchUp(CatchUpState::Syncing {
                target_hash,
                target_number,
            }) => (*target_hash, *target_number),
            _ => return,
        };

        let state = ForkchoiceState {
            head_block_hash: target_hash,
            safe_block_hash: target_hash,
            finalized_block_hash: B256::ZERO,
        };

        match engine.forkchoice_updated_v2(&state, None).await {
            Ok(resp) => {
                info!(
                    status = %resp.payload_status.status,
                    target = %target_hash,
                    target_number,
                    "catch-up: FCU poll"
                );
                if resp.payload_status.status == STATUS_VALID {
                    self.transition_to_pipeline(target_hash, target_number, peer_manager)
                        .await;
                } else if resp.payload_status.status == STATUS_INVALID {
                    warn!(
                        target = %target_hash,
                        target_number,
                        "catch-up: EL marked target INVALID, restarting catch-up"
                    );
                    self.phase = SyncPhase::CatchUp(CatchUpState::WaitingForPeers {
                        entered_at: Instant::now(),
                    });
                    self.try_catchup_start(peer_manager).await;
                }
            }
            Err(e) => {
                error!(err = %e, "catch-up: FCU poll failed");
            }
        }
    }

    /// Transition from CatchUp to Pipeline mode after EL has synced to target.
    async fn transition_to_pipeline(
        &mut self,
        target_hash: B256,
        target_number: u64,
        peer_manager: &(impl SyncPeerManager + ?Sized),
    ) {
        info!(
            target_number,
            target_hash = %target_hash,
            "catch-up complete, switching to pipeline sync"
        );

        // Fetch real TD from EL (chain DB is unreliable for catch-up blocks).
        // On failure, set_head preserves the previous TD. This is acceptable:
        // TD is only used for peer comparison and local fork-choice race tiebreaking,
        // the EL has the authoritative TD and will reject invalid payloads regardless,
        // and the next catchup/sync iteration will correct it.
        let td = if let Some(ref eth_client) = self.eth_client {
            match eth_client.get_block_by_hash(target_hash).await {
                Ok(block) => block.total_difficulty,
                Err(e) => {
                    warn!(err = %e, "catch-up: failed to fetch TD from EL");
                    None
                }
            }
        } else {
            None
        };
        if td.is_none() {
            error!(
                target_number,
                "catch-up: TD unknown, preserving previous TD (may be stale)"
            );
        }
        self.chain.set_head(target_hash, target_number, td);

        self.phase = SyncPhase::Pipeline;
        self.buffer_drain_head = target_number + 1;
        self.try_start_sync(peer_manager).await;
    }

    // -----------------------------------------------------------------------
    // TipFollowing
    // -----------------------------------------------------------------------

    fn transition_to_tip_following(&mut self) {
        info!(
            head = self.chain.head_number(),
            "entered tip-following mode"
        );
        self.reset_sync_state();
        self.phase = SyncPhase::TipFollowing;
        self.pending_tip_fetches.clear();
        self.orphan_blocks.clear();

        // Notify mining coordinator so it can start generating work immediately
        if let Some(ref tx) = self.new_head_tx {
            if let Some(hash) = self.chain.head_hash() {
                let _ = tx.try_send((hash, self.head_timestamp));
            }
        }
    }

    /// Handle a NewBlock broadcast.
    pub async fn on_new_block(
        &mut self,
        node_id: [u8; 64],
        payload: Vec<u8>,
        peer_manager: &(impl SyncPeerManager + ?Sized),
        engine: &(impl SyncEngine + ?Sized),
    ) {
        if !matches!(self.phase, SyncPhase::TipFollowing) {
            return;
        }

        let decoded = match decode_new_block(&payload) {
            Ok(d) => d,
            Err(e) => {
                debug!(err = %e, "failed to decode NewBlock");
                return;
            }
        };

        let block_hash = hash_raw_header(&decoded.header_rlp);

        // Skip if already known
        if self.seen_blocks.contains(&block_hash) || self.seen_blocks_prev.contains(&block_hash) {
            return;
        }
        if self.chain.head_hash() == Some(block_hash) {
            self.seen_blocks.insert(block_hash);
            return;
        }

        info!(
            number = decoded.header.number,
            hash = %block_hash,
            td = %decoded.td,
            "received NewBlock"
        );

        self.process_tip_block(
            TipBlock {
                header: decoded.header,
                header_rlp: decoded.header_rlp,
                block_hash,
                transactions: decoded.transactions,
                uncles: decoded.uncles,
            },
            node_id,
            peer_manager,
            engine,
        )
        .await;
    }

    /// Handle a NewBlockHashes broadcast.
    pub async fn on_new_block_hashes(
        &mut self,
        node_id: [u8; 64],
        payload: Vec<u8>,
        peer_manager: &(impl SyncPeerManager + ?Sized),
    ) {
        if !matches!(self.phase, SyncPhase::TipFollowing) {
            return;
        }

        let entries = match decode_new_block_hashes(&payload) {
            Ok(e) => e,
            Err(e) => {
                debug!(err = %e, "failed to decode NewBlockHashes");
                return;
            }
        };

        for (hash, number) in entries {
            // Skip if already known
            if self.seen_blocks.contains(&hash) || self.seen_blocks_prev.contains(&hash) {
                continue;
            }
            if self.chain.head_hash() == Some(hash) {
                self.seen_blocks.insert(hash);
                continue;
            }
            // Skip if already being fetched
            if self
                .pending_tip_fetches
                .values()
                .any(|f| f.block_hash == hash)
            {
                continue;
            }

            // Request header from announcing peer
            let request_id = self.next_id();
            let cmd = PeerCommand::GetBlockHeaders {
                request_id,
                start: hash.as_slice().to_vec(),
                limit: 1,
                skip: 0,
                reverse: false,
            };

            if peer_manager.send_command(&node_id, cmd).await {
                debug!(
                    number,
                    hash = %hash,
                    "tip: requesting header for announced block"
                );
                self.pending_tip_fetches.insert(
                    request_id,
                    PendingTipFetch {
                        peer: node_id,
                        request_id,
                        block_hash: hash,
                        block_number: number,
                        sent_at: Instant::now(),
                        phase: TipFetchPhase::Header,
                    },
                );
            }
        }
    }

    /// Process a complete tip block (from NewBlock or fetched via NewBlockHashes).
    async fn process_tip_block(
        &mut self,
        tip: TipBlock,
        from_peer: [u8; 64],
        peer_manager: &(impl SyncPeerManager + ?Sized),
        engine: &(impl SyncEngine + ?Sized),
    ) {
        let TipBlock {
            header,
            header_rlp,
            block_hash,
            transactions,
            uncles,
        } = tip;

        // Check if parent is our current head (common case for tip following)
        let parent_known = self.chain.head_hash() == Some(header.parent_hash)
            || self.seen_blocks.contains(&header.parent_hash)
            || self.seen_blocks_prev.contains(&header.parent_hash);
        if !parent_known {
            debug!(
                number = header.number,
                parent = %header.parent_hash,
                "tip: parent unknown, buffering as orphan"
            );
            let parent_hash = header.parent_hash;
            let header_number = header.number;
            // Cap orphan entries to avoid unbounded memory growth
            let total_orphans: usize = self.orphan_blocks.values().map(|v| v.len()).sum();
            if total_orphans >= MAX_ORPHAN_ENTRIES {
                debug!("orphan pool full ({MAX_ORPHAN_ENTRIES}), dropping block");
                return;
            }
            self.orphan_blocks
                .entry(parent_hash)
                .or_default()
                .push(OrphanEntry {
                    header,
                    header_rlp,
                    transactions,
                    uncles,
                    received_at: Instant::now(),
                    from_peer,
                });
            // Request a batch of ancestor headers from the peer (reverse order)
            let request_id = self.next_id();
            let cmd = PeerCommand::GetBlockHeaders {
                request_id,
                start: parent_hash.as_slice().to_vec(),
                limit: REORG_ANCESTOR_LIMIT,
                skip: 0,
                reverse: true,
            };
            if peer_manager.send_command(&from_peer, cmd).await {
                self.pending_tip_fetches.insert(
                    request_id,
                    PendingTipFetch {
                        peer: from_peer,
                        request_id,
                        block_hash: parent_hash,
                        block_number: header_number.saturating_sub(1),
                        sent_at: Instant::now(),
                        phase: TipFetchPhase::AncestorHeaders,
                    },
                );
            }
            return;
        }

        // Compute TD from trusted sources only (never trust peer-announced TD).
        // If parent is our head, use head_td. Otherwise, fetch parent TD from EL.
        let (td, parent_header_for_validation) =
            if self.chain.head_hash() == Some(header.parent_hash) {
                let parent_td = self.chain.head_td();
                (parent_td + header.difficulty, self.last_header.clone())
            } else if let Some(ref eth_client) = self.eth_client {
                match eth_client.get_block_by_hash(header.parent_hash).await {
                    Ok(block) => {
                        let parent_td = block
                            .total_difficulty
                            .unwrap_or(alloy_primitives::U256::ZERO);
                        let parent_hdr = block.to_block_header();
                        (parent_td + header.difficulty, Some(parent_hdr))
                    }
                    Err(e) => {
                        debug!(err = %e, "tip: couldn't fetch parent from EL, dropping block");
                        return;
                    }
                }
            } else {
                debug!("tip: no EL client and parent is not head, dropping block");
                return;
            };

        // Validate header fields against parent
        if let Some(ref parent_header) = parent_header_for_validation {
            if !validate_tip_header(&header, parent_header) {
                return;
            }
        }

        // Validate uncles (count, depth, hash). Basic validation only — the CL is
        // stateless and doesn't maintain a set of recent uncles for duplicate detection.
        // The EL performs full uncle validation (including duplicates) in newPayload.
        if let Err(e) = validate_uncles_basic(&header, &uncles) {
            warn!(number = header.number, err = %e, "tip: uncle validation failed");
            return;
        }

        // MESS check: if this block would cause a reorg, verify antigravity
        if !self.check_mess_reorg(&header, td).await {
            return;
        }

        // Verify PoW
        if !self.verify_tip_pow(&header).await {
            return;
        }

        // Submit payload to EL and get validation status
        let el_status_valid = match self
            .submit_tip_to_el(&header, block_hash, &uncles, &transactions, engine)
            .await
        {
            Some(valid) => valid,
            None => return,
        };

        // Update in-memory chain tracker
        let is_new_head = td > self.chain.head_td();

        self.seen_blocks.insert(block_hash);

        if is_new_head {
            self.chain.set_head(block_hash, header.number, Some(td));
            self.last_header = Some(header.clone());
            self.head_timestamp = header.timestamp;

            // Notify mining coordinator of new head
            if let Some(ref tx) = self.new_head_tx {
                let _ = tx.try_send((block_hash, header.timestamp));
            }

            // Uncle pool: prune old entries and mark uncles from this block as used
            self.uncle_pool.prune(header.number);
            let uncle_hashes: Vec<B256> = uncles.iter().map(|u| u.hash()).collect();
            if !uncle_hashes.is_empty() {
                self.uncle_pool.mark_used(&uncle_hashes, header.number);
            }

            info!(
                number = header.number,
                hash = %block_hash,
                "new tip head"
            );
            self.send_fcu(engine).await;

            // Only broadcast to peers when the EL returned VALID (not ACCEPTED).
            // ACCEPTED means the block was queued for async validation and may
            // later be found invalid — broadcasting prematurely would propagate
            // a potentially bad block to the network.
            if el_status_valid {
                let uncles_rlp: Vec<Vec<u8>> = uncles.iter().map(|u| u.rlp_encode()).collect();
                let td_bytes = td_to_rlp_bytes(&td);
                peer_manager
                    .broadcast_block(&BlockBroadcast {
                        header_rlp: &header_rlp,
                        block_hash: block_hash.as_ref(),
                        block_number: header.number,
                        transactions_rlp: &transactions,
                        uncles_rlp: &uncles_rlp,
                        td_bytes: &td_bytes,
                        exclude: Some(&from_peer),
                    })
                    .await;
            }
        } else {
            // Block is valid but lost the TD race — add as uncle candidate
            self.uncle_pool.add_candidate(header.clone(), block_hash);
        }

        // Try to resolve orphans: any orphan whose parent_hash == block_hash
        self.try_resolve_orphans(block_hash, peer_manager, engine)
            .await;
    }

    /// Check MESS reorg rules. Returns true if the block should proceed, false if rejected.
    async fn check_mess_reorg(&mut self, header: &BlockHeader, td: alloy_primitives::U256) -> bool {
        let head_hash = self.chain.head_hash().unwrap_or(B256::ZERO);
        if header.parent_hash == head_hash
            || !self.mess_active
            || !self.mess_config.is_enabled_at(header.number)
        {
            return true;
        }

        let eth_client = match self.eth_client {
            Some(ref client) => client,
            None => return true,
        };

        // Stale head check (event-driven, not timer)
        let head_timestamp_secs = self.head_timestamp;
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now_secs.saturating_sub(head_timestamp_secs) > mess::STALE_HEAD_THRESHOLD {
            info!("MESS deactivated: head is stale");
            self.mess_active = false;
            return true;
        }

        match mess::find_common_ancestor(eth_client, head_hash, header.parent_hash).await {
            Some((_, ancestor_number, ancestor_time, ancestor_td)) => {
                let head_td = self.chain.head_td();
                let local_sub_td = head_td.saturating_sub(ancestor_td);
                let proposed_sub_td = td.saturating_sub(ancestor_td);
                let time_delta = head_timestamp_secs.saturating_sub(ancestor_time);
                if !mess::is_reorg_allowed(&local_sub_td, &proposed_sub_td, time_delta) {
                    warn!(
                        block = header.number,
                        ancestor = ancestor_number,
                        time_delta,
                        "MESS rejected reorg"
                    );
                    return false;
                }
                debug!(
                    block = header.number,
                    ancestor = ancestor_number,
                    time_delta,
                    "MESS allowed reorg"
                );
            }
            None => {
                // Fail-open: couldn't find ancestor, allow the reorg
                warn!("MESS: couldn't find common ancestor, allowing reorg (fail-open)");
            }
        }
        true
    }

    /// Verify PoW for a tip block. Returns true if valid (or if PoW is skipped).
    async fn verify_tip_pow(&mut self, header: &BlockHeader) -> bool {
        if self.skip_pow {
            return true;
        }
        let ep = consensus::ethash::epoch(header.number);
        let ep_len = consensus::ethash::epoch_length(header.number);
        let cache = self.get_ethash_cache_for_epoch(ep, ep_len);
        let header_clone = header.clone();
        let pow_result = match tokio::task::spawn_blocking(move || {
            consensus::ethash::verify_pow(&header_clone, &cache)
        })
        .await
        {
            Ok(result) => result,
            Err(e) => {
                error!(err = %e, "PoW verification task failed");
                return false;
            }
        };
        if let Err(e) = pow_result {
            warn!(err = %e, number = header.number, "tip: invalid PoW");
            return false;
        }
        true
    }

    /// Submit a tip block payload to the EL. Returns Some(true) if VALID,
    /// Some(false) if ACCEPTED/other, or None if the block should be dropped.
    async fn submit_tip_to_el(
        &self,
        header: &BlockHeader,
        block_hash: B256,
        uncles: &[BlockHeader],
        transactions: &[Vec<u8>],
        engine: &(impl SyncEngine + ?Sized),
    ) -> Option<bool> {
        let payload = block_to_payload_with_hash(header, block_hash, uncles, transactions);

        match engine.new_payload_v2(&payload).await {
            Ok(status) => {
                // VALID = fully validated; ACCEPTED = EL queued for async validation.
                // Both are OK for tip-following blocks from peers.
                if status.status == STATUS_VALID || status.status == STATUS_ACCEPTED {
                    debug!(
                        number = header.number,
                        hash = %block_hash,
                        status = %status.status,
                        "tip: block accepted by EL"
                    );
                    Some(status.status == STATUS_VALID)
                } else if status.status == STATUS_INVALID {
                    warn!(
                        number = header.number,
                        hash = %block_hash,
                        err = ?status.validation_error,
                        "tip: EL returned INVALID"
                    );
                    None
                } else if status.status == STATUS_SYNCING {
                    warn!(
                        number = header.number,
                        hash = %hex::encode(block_hash.as_slice()),
                        "tip: EL is syncing, skipping block"
                    );
                    None
                } else {
                    debug!(
                        number = header.number,
                        status = %status.status,
                        "tip: newPayload status"
                    );
                    Some(false)
                }
            }
            Err(e) => {
                error!(err = %e, "tip: EL connection error");
                None
            }
        }
    }

    /// Maximum recursion depth for orphan resolution.
    /// Prevents stack overflow if a long chain of orphans is queued.
    const MAX_ORPHAN_RESOLVE_DEPTH: u32 = 8;

    /// Try to resolve orphan blocks whose parent is now known.
    async fn try_resolve_orphans(
        &mut self,
        parent_hash: B256,
        peer_manager: &(impl SyncPeerManager + ?Sized),
        engine: &(impl SyncEngine + ?Sized),
    ) {
        let prev_depth = self.orphan_resolve_depth;
        if self.orphan_resolve_depth >= Self::MAX_ORPHAN_RESOLVE_DEPTH {
            warn!(
                depth = self.orphan_resolve_depth,
                "tip: orphan resolution depth limit reached, deferring"
            );
            return;
        }
        self.orphan_resolve_depth += 1;

        if let Some(orphans) = self.orphan_blocks.remove(&parent_hash) {
            for orphan in orphans {
                let orphan_hash = hash_raw_header(&orphan.header_rlp);
                let peer = orphan.from_peer;
                info!(
                    number = orphan.header.number,
                    hash = %orphan_hash,
                    "tip: resolving orphan block"
                );
                // Box the future to avoid infinite type recursion
                Box::pin(self.process_tip_block(
                    TipBlock {
                        header: orphan.header,
                        header_rlp: orphan.header_rlp,
                        block_hash: orphan_hash,
                        transactions: orphan.transactions,
                        uncles: orphan.uncles,
                    },
                    peer,
                    peer_manager,
                    engine,
                ))
                .await;
            }
        }

        self.orphan_resolve_depth = prev_depth;
    }

    /// Handle batch ancestor header responses (reorg path).
    /// Returns `Some((body_request_id, hashes))` if we decoded headers and need bodies.
    fn handle_ancestor_headers(
        &mut self,
        node_id: [u8; 64],
        request_id: u64,
        headers_raw: &[Vec<u8>],
    ) -> Option<(u64, Vec<B256>)> {
        let fetch = self.pending_tip_fetches.get(&request_id)?;
        if fetch.peer != node_id {
            return None;
        }
        if !matches!(fetch.phase, TipFetchPhase::AncestorHeaders) {
            return None;
        }

        let fetch = self.pending_tip_fetches.remove(&request_id)?;

        if headers_raw.is_empty() {
            debug!(hash = %fetch.block_hash, "ancestor fetch: peer returned 0 headers");
            return None;
        }

        // Decode all headers
        let mut decoded: Vec<(BlockHeader, Vec<u8>, B256)> = Vec::with_capacity(headers_raw.len());
        for (i, raw) in headers_raw.iter().enumerate() {
            match decode_block_header(raw) {
                Ok(header) => {
                    let block_hash = hash_raw_header(raw);
                    decoded.push((header, raw.clone(), block_hash));
                }
                Err(e) => {
                    debug!(err = %e, index = i, "ancestor fetch: header decode failed");
                    break;
                }
            }
        }

        if decoded.is_empty() {
            return None;
        }

        // Headers arrive newest-first (reverse: true). Verify the first header
        // (the newest, i.e. the one we requested by hash) matches fetch.block_hash.
        if decoded[0].2 != fetch.block_hash {
            debug!(
                expected = %fetch.block_hash,
                got = %decoded[0].2,
                "ancestor fetch: first header hash mismatch, discarding"
            );
            return None;
        }

        // Reverse to oldest-first for processing
        decoded.reverse();

        // Validate contiguity: each header's hash must equal the next header's parent_hash
        for i in 0..decoded.len().saturating_sub(1) {
            if decoded[i].2 != decoded[i + 1].0.parent_hash {
                debug!(
                    index = i,
                    hash = %decoded[i].2,
                    next_parent = %decoded[i + 1].0.parent_hash,
                    "ancestor fetch: headers not contiguous, discarding"
                );
                return None;
            }
        }

        info!(
            count = decoded.len(),
            from = decoded.first().map(|h| h.0.number).unwrap_or(0),
            to = decoded.last().map(|h| h.0.number).unwrap_or(0),
            "ancestor fetch: decoded headers (oldest-first)"
        );

        // Collect hashes for body request (oldest-first order)
        let hashes: Vec<B256> = decoded.iter().map(|(_, _, h)| *h).collect();

        // Store headers for when bodies arrive
        let headers: Vec<(BlockHeader, Vec<u8>)> = decoded
            .into_iter()
            .map(|(header, rlp, _)| (header, rlp))
            .collect();

        let body_request_id = self.next_id();
        self.pending_tip_fetches.insert(
            body_request_id,
            PendingTipFetch {
                peer: node_id,
                request_id: body_request_id,
                block_hash: fetch.block_hash,
                block_number: fetch.block_number,
                sent_at: Instant::now(),
                phase: TipFetchPhase::AncestorBodies { headers },
            },
        );

        Some((body_request_id, hashes))
    }

    /// Handle header/body responses for tip fetches. Returns true if consumed.
    fn handle_tip_fetch_header(
        &mut self,
        node_id: [u8; 64],
        request_id: u64,
        headers_raw: &[Vec<u8>],
    ) -> Option<(u64, B256)> {
        // Check if this is a tip fetch response
        let fetch = self.pending_tip_fetches.get(&request_id)?;
        if fetch.peer != node_id {
            return None;
        }
        if !matches!(fetch.phase, TipFetchPhase::Header) {
            return None;
        }

        let fetch = self.pending_tip_fetches.remove(&request_id)?;

        if headers_raw.is_empty() {
            debug!(hash = %fetch.block_hash, "tip fetch: peer returned 0 headers");
            return None;
        }

        let header_rlp = &headers_raw[0];
        let header = match decode_block_header(header_rlp) {
            Ok(h) => h,
            Err(e) => {
                debug!(err = %e, "tip fetch: failed to decode header");
                return None;
            }
        };

        // Verify the returned header matches the hash we requested
        let block_hash = hash_raw_header(header_rlp);
        if block_hash != fetch.block_hash {
            debug!(
                expected = %fetch.block_hash,
                got = %block_hash,
                "tip fetch: header hash mismatch, discarding"
            );
            return None;
        }

        // Now request body
        let body_request_id = self.next_id();

        self.pending_tip_fetches.insert(
            body_request_id,
            PendingTipFetch {
                peer: node_id,
                request_id: body_request_id,
                block_hash,
                block_number: header.number,
                sent_at: Instant::now(),
                phase: TipFetchPhase::Body {
                    header: Box::new(header),
                    header_rlp: header_rlp.to_vec(),
                },
            },
        );

        // Return the body request_id so the caller can send the GetBlockBodies
        Some((body_request_id, block_hash))
    }
}

/// Validate a tip block header against its parent.
/// Returns true if valid, false (with warning logged) if invalid.
fn validate_tip_header(header: &BlockHeader, parent: &BlockHeader) -> bool {
    if let Err(e) = consensus::difficulty::validate_difficulty(header, parent) {
        warn!(err = %e, number = header.number, "tip: difficulty validation failed");
        return false;
    }
    // Timestamp must be strictly greater than parent
    if header.timestamp <= parent.timestamp {
        warn!(
            number = header.number,
            timestamp = header.timestamp,
            parent_timestamp = parent.timestamp,
            "tip: timestamp not greater than parent"
        );
        return false;
    }
    // Gas limit: must be within ±1/1024 of parent
    let parent_limit = parent.gas_limit;
    let diff = header.gas_limit.abs_diff(parent_limit);
    let max_delta = parent_limit / 1024;
    if diff >= max_delta || header.gas_limit < 5000 {
        warn!(
            number = header.number,
            gas_limit = header.gas_limit,
            parent_gas_limit = parent_limit,
            "tip: gas limit out of range"
        );
        return false;
    }
    // Extra data: max 32 bytes (ETC/ETH consensus rule)
    if header.extra_data.len() > 32 {
        warn!(
            number = header.number,
            extra_data_len = header.extra_data.len(),
            "tip: extra_data exceeds 32 bytes"
        );
        return false;
    }
    true
}
