use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use alloy_primitives::{Address, B256, U256};

use chain::tracker::ChainTracker;
use chain::types::{empty_uncle_hash, BlockHeader};
use consensus::difficulty::calculate_difficulty;
use devp2p::peer_manager::{BlockBroadcast, PeerCommand};
use engine_api::types::{
    ExecutionPayload, ForkChoiceResponse, ForkchoiceState, PayloadAttributes, PayloadStatus,
    STATUS_VALID,
};
use sync::{
    SyncEngine, SyncManager, SyncPeerManager, FCU_INTERVAL, HEADER_BATCH_SIZE, MAX_BUFFER_SIZE,
};

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct RecordedCommand {
    peer_id: [u8; 64],
    cmd: RecordedPeerCmd,
}

#[derive(Clone, Debug)]
enum RecordedPeerCmd {
    GetBlockHeaders {
        request_id: u64,
        #[allow(dead_code)]
        start: Vec<u8>,
        #[allow(dead_code)]
        limit: u64,
    },
    GetBlockBodies {
        request_id: u64,
        hashes: Vec<[u8; 32]>,
    },
}

struct MockPeerManager {
    commands: Arc<Mutex<Vec<RecordedCommand>>>,
    /// Peers for which send_command returns true. If None, all succeed.
    #[allow(dead_code)]
    active_peers: Arc<Mutex<Option<HashSet<[u8; 64]>>>>,
}

impl MockPeerManager {
    fn new() -> Self {
        Self {
            commands: Arc::new(Mutex::new(Vec::new())),
            active_peers: Arc::new(Mutex::new(None)),
        }
    }

    fn commands(&self) -> Vec<RecordedCommand> {
        self.commands.lock().unwrap().clone()
    }

    fn clear_commands(&self) {
        self.commands.lock().unwrap().clear();
    }
}

impl SyncPeerManager for MockPeerManager {
    async fn broadcast_block(&self, _block: &BlockBroadcast<'_>) {
        // no-op in tests
    }

    async fn send_command(&self, node_id: &[u8; 64], cmd: PeerCommand) -> bool {
        let active = self.active_peers.lock().unwrap();
        if let Some(ref set) = *active {
            if !set.contains(node_id) {
                return false;
            }
        }
        drop(active);

        let recorded = match cmd {
            PeerCommand::GetBlockHeaders {
                request_id,
                start,
                limit,
                ..
            } => RecordedPeerCmd::GetBlockHeaders {
                request_id,
                start,
                limit,
            },
            PeerCommand::GetBlockBodies { request_id, hashes } => {
                RecordedPeerCmd::GetBlockBodies { request_id, hashes }
            }
            PeerCommand::SendRaw { .. } => return true,
        };

        self.commands.lock().unwrap().push(RecordedCommand {
            peer_id: *node_id,
            cmd: recorded,
        });
        true
    }
}

struct MockEngine {
    payloads: Arc<Mutex<Vec<ExecutionPayload>>>,
    fcu_count: Arc<AtomicU64>,
    status: String,
}

impl MockEngine {
    fn new() -> Self {
        Self {
            payloads: Arc::new(Mutex::new(Vec::new())),
            fcu_count: Arc::new(AtomicU64::new(0)),
            status: STATUS_VALID.to_string(),
        }
    }

    fn payload_count(&self) -> usize {
        self.payloads.lock().unwrap().len()
    }

    fn fcu_count(&self) -> u64 {
        self.fcu_count.load(Ordering::Relaxed)
    }

    fn payloads(&self) -> Vec<ExecutionPayload> {
        self.payloads.lock().unwrap().clone()
    }
}

impl SyncEngine for MockEngine {
    async fn new_payload_v2(
        &self,
        payload: &ExecutionPayload,
    ) -> Result<PayloadStatus, engine_api::client::ClientError> {
        self.payloads.lock().unwrap().push(payload.clone());
        Ok(PayloadStatus {
            status: self.status.clone(),
            latest_valid_hash: Some(payload.block_hash),
            validation_error: None,
        })
    }

    async fn new_payload_v2_batch(
        &self,
        payloads: &[&ExecutionPayload],
    ) -> Result<Vec<PayloadStatus>, engine_api::client::ClientError> {
        let mut results = Vec::with_capacity(payloads.len());
        for payload in payloads {
            results.push(self.new_payload_v2(payload).await?);
        }
        Ok(results)
    }

    async fn forkchoice_updated_v2(
        &self,
        _state: &ForkchoiceState,
        _attrs: Option<&PayloadAttributes>,
    ) -> Result<ForkChoiceResponse, engine_api::client::ClientError> {
        self.fcu_count.fetch_add(1, Ordering::Relaxed);
        Ok(ForkChoiceResponse {
            payload_status: PayloadStatus {
                status: STATUS_VALID.to_string(),
                latest_valid_hash: None,
                validation_error: None,
            },
            payload_id: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn peer_id(n: u8) -> [u8; 64] {
    let mut id = [0u8; 64];
    id[0] = n;
    id
}

/// Starting block number for test chains (post-ECIP1041 = no difficulty bomb).
const TEST_START_BLOCK: u64 = 6_000_000;
/// Base timestamp for test genesis.
const TEST_BASE_TIMESTAMP: u64 = 1_600_000_000;

/// Create an in-memory ChainTracker with head at TEST_START_BLOCK.
/// Returns (chain, head_hash, head_header).
fn test_chain() -> (ChainTracker, B256, BlockHeader) {
    let mut chain = ChainTracker::new();

    // Create a "head" header at TEST_START_BLOCK.
    let head_header = BlockHeader {
        parent_hash: B256::ZERO,
        uncle_hash: empty_uncle_hash(),
        coinbase: Address::ZERO,
        state_root: B256::ZERO,
        transactions_root: chain::trie::empty_trie_hash(),
        receipts_root: B256::ZERO,
        logs_bloom: [0u8; 256],
        difficulty: U256::from(131_072u64),
        number: TEST_START_BLOCK,
        gas_limit: 5_000_000,
        gas_used: 0,
        timestamp: TEST_BASE_TIMESTAMP + TEST_START_BLOCK * 14,
        extra_data: vec![],
        mix_hash: B256::ZERO,
        nonce: [0u8; 8],
        base_fee: None,
    };
    let head_hash = head_header.hash();
    chain.init_from_el(head_hash, TEST_START_BLOCK, U256::from(131_072u64));

    (chain, head_hash, head_header)
}

/// Generate a contiguous chain of N headers starting after `parent`.
/// Uses `calculate_difficulty` so headers pass validation.
fn generate_test_chain(
    parent: &BlockHeader,
    parent_hash: B256,
    count: u64,
) -> Vec<(Vec<u8>, BlockHeader)> {
    let mut chain = Vec::new();
    let mut prev_hash = parent_hash;
    let mut prev_header = parent.clone();

    for _ in 0..count {
        let number = prev_header.number + 1;
        let timestamp = prev_header.timestamp + 14;
        let difficulty = calculate_difficulty(&prev_header, timestamp);

        let header = BlockHeader {
            parent_hash: prev_hash,
            uncle_hash: empty_uncle_hash(),
            coinbase: Address::ZERO,
            state_root: B256::ZERO,
            transactions_root: chain::trie::empty_trie_hash(),
            receipts_root: B256::ZERO,
            logs_bloom: [0u8; 256],
            difficulty,
            number,
            gas_limit: 5_000_000,
            gas_used: 0,
            timestamp,
            extra_data: vec![],
            mix_hash: B256::ZERO,
            nonce: [0u8; 8],
            base_fee: None,
        };

        let raw = header.rlp_encode();
        prev_hash = header.hash();
        prev_header = header.clone();
        chain.push((raw, header));
    }

    chain
}

/// Encode an empty block body as RLP: [[],[]] (no txs, no uncles).
fn empty_body_rlp() -> Vec<u8> {
    vec![0xc2, 0xc0, 0xc0]
}

/// Extract (request_id, peer_id) for the first GetBlockHeaders command.
fn find_header_request(cmds: &[RecordedCommand]) -> Option<(u64, [u8; 64])> {
    cmds.iter().find_map(|c| match &c.cmd {
        RecordedPeerCmd::GetBlockHeaders { request_id, .. } => Some((*request_id, c.peer_id)),
        _ => None,
    })
}

/// Extract all GetBlockBodies commands.
fn find_body_requests(cmds: &[RecordedCommand]) -> Vec<(u64, [u8; 64], Vec<[u8; 32]>)> {
    cmds.iter()
        .filter_map(|c| match &c.cmd {
            RecordedPeerCmd::GetBlockBodies { request_id, hashes } => {
                Some((*request_id, c.peer_id, hashes.clone()))
            }
            _ => None,
        })
        .collect()
}

/// Create a SyncManager with skip_pow enabled (for testing).
fn test_sync(chain: ChainTracker) -> SyncManager {
    let mess_config = sync::mess::MessConfig {
        activation_block: None,
        flag: None,
    };
    let mut sync = SyncManager::new(chain, mess_config, None);
    sync.set_skip_pow(true);
    sync.set_pipeline_mode(); // Tests exercise pipeline mode directly
    sync
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_pipeline_basic_flow() {
    let (chain, head_hash, head_header) = test_chain();
    let mut sync = test_sync(chain);
    let pm = MockPeerManager::new();
    let engine = MockEngine::new();

    let total_blocks = HEADER_BATCH_SIZE * 2;
    let all_headers = generate_test_chain(&head_header, head_hash, total_blocks);
    let batch1: Vec<_> = all_headers[..HEADER_BATCH_SIZE as usize].to_vec();
    let batch2: Vec<_> = all_headers[HEADER_BATCH_SIZE as usize..].to_vec();

    // Connect peers → should trigger header request
    let p1 = peer_id(1);
    let p2 = peer_id(2);
    sync.on_peer_connected(p1, "test-peer-1", vec![1], [0u8; 32], &pm)
        .await;
    sync.on_peer_connected(p2, "test-peer-2", vec![1], [0u8; 32], &pm)
        .await;

    let cmds = pm.commands();
    let (req_id, peer) = find_header_request(&cmds).expect("should have header request");
    pm.clear_commands();

    // Feed batch 1 headers
    let headers_raw: Vec<Vec<u8>> = batch1.iter().map(|(raw, _)| raw.clone()).collect();
    sync.on_block_headers(peer, req_id, headers_raw, &pm, &engine)
        .await;

    let cmds = pm.commands();
    let body_reqs = find_body_requests(&cmds);
    assert!(
        !body_reqs.is_empty(),
        "should have body requests after headers"
    );
    let header_req = find_header_request(&cmds);
    assert!(header_req.is_some(), "should request next batch of headers");
    pm.clear_commands();

    // Feed bodies for batch 1
    for (req_id, body_peer, hashes) in &body_reqs {
        let bodies: Vec<Vec<u8>> = hashes.iter().map(|_| empty_body_rlp()).collect();
        sync.on_block_bodies(*body_peer, *req_id, bodies, &pm, &engine)
            .await;
    }

    assert!(
        engine.payload_count() >= HEADER_BATCH_SIZE as usize,
        "should have processed batch 1, got {}",
        engine.payload_count()
    );

    pm.clear_commands();

    // Feed batch 2 headers
    let (req_id2, peer2) = header_req.unwrap();
    let headers_raw2: Vec<Vec<u8>> = batch2.iter().map(|(raw, _)| raw.clone()).collect();
    sync.on_block_headers(peer2, req_id2, headers_raw2, &pm, &engine)
        .await;

    let cmds = pm.commands();
    let body_reqs2 = find_body_requests(&cmds);
    pm.clear_commands();

    // Feed bodies for batch 2
    for (req_id, body_peer, hashes) in &body_reqs2 {
        let bodies: Vec<Vec<u8>> = hashes.iter().map(|_| empty_body_rlp()).collect();
        sync.on_block_bodies(*body_peer, *req_id, bodies, &pm, &engine)
            .await;
    }

    // Signal headers exhausted
    let cmds = pm.commands();
    if let Some((req_id3, peer3)) = find_header_request(&cmds) {
        pm.clear_commands();
        sync.on_block_headers(peer3, req_id3, vec![], &pm, &engine)
            .await;
    }

    assert_eq!(
        engine.payload_count(),
        total_blocks as usize,
        "all blocks should be processed"
    );

    // Payloads should arrive in sequential order
    let payloads = engine.payloads();
    let start = TEST_START_BLOCK + 1;
    for (i, p) in payloads.iter().enumerate() {
        assert_eq!(
            p.block_number,
            start + i as u64,
            "payloads must be in sequential order"
        );
    }

    assert!(engine.fcu_count() > 0, "FCU should have been called");
}

#[tokio::test]
async fn test_empty_body_response_penalizes_peer() {
    let (chain, head_hash, head_header) = test_chain();
    let mut sync = test_sync(chain);
    let pm = MockPeerManager::new();
    let engine = MockEngine::new();

    let headers = generate_test_chain(&head_header, head_hash, 10);

    let p1 = peer_id(1);
    let p2 = peer_id(2);
    sync.on_peer_connected(p1, "peer1", vec![1], [0u8; 32], &pm)
        .await;
    sync.on_peer_connected(p2, "peer2", vec![1], [0u8; 32], &pm)
        .await;

    let cmds = pm.commands();
    let (req_id, peer) = find_header_request(&cmds).unwrap();
    pm.clear_commands();

    let headers_raw: Vec<Vec<u8>> = headers.iter().map(|(raw, _)| raw.clone()).collect();
    sync.on_block_headers(peer, req_id, headers_raw, &pm, &engine)
        .await;

    let cmds = pm.commands();
    let body_reqs = find_body_requests(&cmds);
    assert!(!body_reqs.is_empty());
    pm.clear_commands();

    // First peer returns 0 bodies
    let (body_req_id, body_peer, _) = &body_reqs[0];
    sync.on_block_bodies(*body_peer, *body_req_id, vec![], &pm, &engine)
        .await;

    // Should have re-dispatched bodies to another peer
    let cmds = pm.commands();
    let new_body_reqs = find_body_requests(&cmds);
    assert!(
        !new_body_reqs.is_empty(),
        "should redistribute bodies after empty response"
    );
}

#[tokio::test]
async fn test_partial_body_response() {
    let (chain, head_hash, head_header) = test_chain();
    let mut sync = test_sync(chain);
    let pm = MockPeerManager::new();
    let engine = MockEngine::new();

    let count = 10u64;
    let headers = generate_test_chain(&head_header, head_hash, count);

    let p1 = peer_id(1);
    sync.on_peer_connected(p1, "peer1", vec![1], [0u8; 32], &pm)
        .await;

    let cmds = pm.commands();
    let (req_id, peer) = find_header_request(&cmds).unwrap();
    pm.clear_commands();

    let headers_raw: Vec<Vec<u8>> = headers.iter().map(|(raw, _)| raw.clone()).collect();
    sync.on_block_headers(peer, req_id, headers_raw, &pm, &engine)
        .await;

    let cmds = pm.commands();
    let body_reqs = find_body_requests(&cmds);
    assert!(!body_reqs.is_empty());
    pm.clear_commands();

    // Return only 60% of requested bodies
    let (body_req_id, body_peer, hashes) = &body_reqs[0];
    let partial_count = (hashes.len() * 6) / 10;
    let partial_bodies: Vec<Vec<u8>> = (0..partial_count).map(|_| empty_body_rlp()).collect();

    sync.on_block_bodies(*body_peer, *body_req_id, partial_bodies, &pm, &engine)
        .await;

    // The partial_count blocks that arrived should be processed
    assert_eq!(
        engine.payload_count(),
        partial_count,
        "partial bodies should be processed"
    );

    // Remaining should be re-dispatched
    let cmds = pm.commands();
    let new_body_reqs = find_body_requests(&cmds);
    assert!(
        !new_body_reqs.is_empty(),
        "should dispatch body requests for remaining blocks"
    );
}

#[tokio::test]
async fn test_body_timeout_redistribution() {
    let (chain, head_hash, head_header) = test_chain();
    let mut sync = test_sync(chain);
    let pm = MockPeerManager::new();
    let engine = MockEngine::new();

    let headers = generate_test_chain(&head_header, head_hash, 10);

    let p1 = peer_id(1);
    let p2 = peer_id(2);
    sync.on_peer_connected(p1, "peer1", vec![1], [0u8; 32], &pm)
        .await;
    sync.on_peer_connected(p2, "peer2", vec![1], [0u8; 32], &pm)
        .await;

    let cmds = pm.commands();
    let (req_id, peer) = find_header_request(&cmds).unwrap();
    pm.clear_commands();

    let headers_raw: Vec<Vec<u8>> = headers.iter().map(|(raw, _)| raw.clone()).collect();
    sync.on_block_headers(peer, req_id, headers_raw, &pm, &engine)
        .await;

    let cmds = pm.commands();
    let body_reqs = find_body_requests(&cmds);
    assert!(!body_reqs.is_empty(), "should have body requests");
    pm.clear_commands();

    // Simulate timeout via peer disconnect (equivalent effect: redistribute)
    let (_, body_peer, _) = &body_reqs[0];
    sync.on_peer_disconnected(*body_peer, &pm).await;

    let cmds = pm.commands();
    let new_body_reqs = find_body_requests(&cmds);
    assert!(
        !new_body_reqs.is_empty(),
        "should redistribute bodies after peer disconnect"
    );
}

#[tokio::test]
async fn test_peer_disconnect_mid_sync() {
    let (chain, head_hash, head_header) = test_chain();
    let mut sync = test_sync(chain);
    let pm = MockPeerManager::new();
    let engine = MockEngine::new();

    let headers = generate_test_chain(&head_header, head_hash, 20);

    let p1 = peer_id(1);
    let p2 = peer_id(2);
    let p3 = peer_id(3);
    sync.on_peer_connected(p1, "peer1", vec![1], [0u8; 32], &pm)
        .await;
    sync.on_peer_connected(p2, "peer2", vec![1], [0u8; 32], &pm)
        .await;
    sync.on_peer_connected(p3, "peer3", vec![1], [0u8; 32], &pm)
        .await;

    let cmds = pm.commands();
    let (req_id, peer) = find_header_request(&cmds).unwrap();
    pm.clear_commands();

    let headers_raw: Vec<Vec<u8>> = headers.iter().map(|(raw, _)| raw.clone()).collect();
    sync.on_block_headers(peer, req_id, headers_raw, &pm, &engine)
        .await;

    let cmds = pm.commands();
    let body_reqs = find_body_requests(&cmds);
    pm.clear_commands();

    // Disconnect peer with in-flight body request — should not panic
    if !body_reqs.is_empty() {
        let (_, disc_peer, _) = &body_reqs[0];
        sync.on_peer_disconnected(*disc_peer, &pm).await;

        let cmds = pm.commands();
        let new_body_reqs = find_body_requests(&cmds);
        assert!(
            !new_body_reqs.is_empty(),
            "disconnected peer's blocks should be redistributed"
        );
    }
}

#[tokio::test]
async fn test_backpressure() {
    let (chain, head_hash, head_header) = test_chain();
    let mut sync = test_sync(chain);
    let pm = MockPeerManager::new();
    let engine = MockEngine::new();

    let batch_count = (MAX_BUFFER_SIZE as u64 / HEADER_BATCH_SIZE) + 2;
    let total = batch_count * HEADER_BATCH_SIZE;
    let all_headers = generate_test_chain(&head_header, head_hash, total);

    let p1 = peer_id(1);
    sync.on_peer_connected(p1, "peer1", vec![1], [0u8; 32], &pm)
        .await;

    let mut fed = 0usize;
    let mut backpressure_hit = false;

    // Get initial header request
    let cmds = pm.commands();
    let mut last_header_req = find_header_request(&cmds);
    pm.clear_commands();

    // Feed batches until backpressure stops header requests
    for _ in 0..20 {
        let (req_id, peer) = match last_header_req {
            Some(r) => r,
            None => {
                backpressure_hit = true;
                break;
            }
        };

        let end = std::cmp::min(fed + HEADER_BATCH_SIZE as usize, all_headers.len());
        let batch: Vec<Vec<u8>> = all_headers[fed..end]
            .iter()
            .map(|(raw, _)| raw.clone())
            .collect();

        sync.on_block_headers(peer, req_id, batch, &pm, &engine)
            .await;
        fed = end;

        let cmds = pm.commands();
        last_header_req = find_header_request(&cmds);
        pm.clear_commands();
    }

    assert!(
        backpressure_hit,
        "backpressure should stop header requests before buffer exceeds limit, fed {} headers",
        fed
    );
    assert!(
        fed >= MAX_BUFFER_SIZE,
        "should have fed at least MAX_BUFFER_SIZE headers before backpressure, fed {}",
        fed
    );
}

#[tokio::test]
async fn test_headers_exhausted_completion() {
    let (chain, head_hash, head_header) = test_chain();
    let mut sync = test_sync(chain);
    let pm = MockPeerManager::new();
    let engine = MockEngine::new();

    let count = 10u64;
    let headers = generate_test_chain(&head_header, head_hash, count);

    let p1 = peer_id(1);
    sync.on_peer_connected(p1, "peer1", vec![1], [0u8; 32], &pm)
        .await;

    let cmds = pm.commands();
    let (req_id, peer) = find_header_request(&cmds).unwrap();
    pm.clear_commands();

    let headers_raw: Vec<Vec<u8>> = headers.iter().map(|(raw, _)| raw.clone()).collect();
    sync.on_block_headers(peer, req_id, headers_raw, &pm, &engine)
        .await;

    let cmds = pm.commands();
    let body_reqs = find_body_requests(&cmds);
    let header_req2 = find_header_request(&cmds);
    pm.clear_commands();

    // Feed all bodies
    for (req_id, body_peer, hashes) in &body_reqs {
        let bodies: Vec<Vec<u8>> = hashes.iter().map(|_| empty_body_rlp()).collect();
        sync.on_block_bodies(*body_peer, *req_id, bodies, &pm, &engine)
            .await;
    }

    // Signal headers exhausted
    if let Some((req_id2, peer2)) = header_req2 {
        pm.clear_commands();
        sync.on_block_headers(peer2, req_id2, vec![], &pm, &engine)
            .await;
    }

    assert_eq!(engine.payload_count(), count as usize);
    assert!(engine.fcu_count() > 0, "should send FCU on completion");
}

#[tokio::test]
async fn test_fcu_interval() {
    let (chain, head_hash, head_header) = test_chain();
    let mut sync = test_sync(chain);
    let pm = MockPeerManager::new();
    let engine = MockEngine::new();

    let count = FCU_INTERVAL + 10;
    let headers = generate_test_chain(&head_header, head_hash, count);

    let p1 = peer_id(1);
    sync.on_peer_connected(p1, "peer1", vec![1], [0u8; 32], &pm)
        .await;

    let cmds = pm.commands();
    let (req_id, peer) = find_header_request(&cmds).unwrap();
    pm.clear_commands();

    let headers_raw: Vec<Vec<u8>> = headers.iter().map(|(raw, _)| raw.clone()).collect();
    sync.on_block_headers(peer, req_id, headers_raw, &pm, &engine)
        .await;

    let cmds = pm.commands();
    let body_reqs = find_body_requests(&cmds);
    pm.clear_commands();

    for (req_id, body_peer, hashes) in &body_reqs {
        let bodies: Vec<Vec<u8>> = hashes.iter().map(|_| empty_body_rlp()).collect();
        sync.on_block_bodies(*body_peer, *req_id, bodies, &pm, &engine)
            .await;
    }

    assert!(
        engine.fcu_count() >= 1,
        "should call FCU every {} blocks, got {} FCU calls for {} blocks",
        FCU_INTERVAL,
        engine.fcu_count(),
        count
    );

    assert_eq!(engine.payload_count(), count as usize);
}
