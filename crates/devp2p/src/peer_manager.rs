use std::collections::HashMap;
use std::sync::Arc;

use k256::ecdsa::SigningKey;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, RwLock};
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::connection::{accept_as_responder, connect_as_initiator};
use crate::constants::{CLIENT_ID, PING_INTERVAL};
use crate::crypto::{parse_uncompressed_pubkey, pubkey_to_node_id};
use crate::eth::{self, EthStatus};
use crate::p2p::{self, Capability, HelloMessage};
use crate::session::Session;
use crate::types::NodeInfo;

#[derive(Debug)]
pub enum PeerEvent {
    Connected {
        node_id: [u8; 64],
        client_id: String,
        td: Vec<u8>,
        best_hash: [u8; 32],
    },
    Disconnected {
        node_id: [u8; 64],
        reason: String,
    },
    BlockHeaders {
        node_id: [u8; 64],
        request_id: u64,
        headers: Vec<Vec<u8>>,
    },
    BlockBodies {
        node_id: [u8; 64],
        request_id: u64,
        bodies: Vec<Vec<u8>>,
    },
    NewBlock {
        node_id: [u8; 64],
        payload: Vec<u8>,
    },
    NewBlockHashes {
        node_id: [u8; 64],
        payload: Vec<u8>,
    },
    GetBlockHeadersRequest {
        node_id: [u8; 64],
        request: eth::BlockHeadersRequest,
    },
    GetBlockBodiesRequest {
        node_id: [u8; 64],
        request: eth::BlockBodiesRequest,
    },
    GetReceiptsRequest {
        node_id: [u8; 64],
        request: eth::ReceiptsRequest,
    },
}

#[derive(Debug)]
pub enum PeerCommand {
    GetBlockHeaders {
        request_id: u64,
        start: Vec<u8>,
        limit: u64,
        skip: u64,
        reverse: bool,
    },
    GetBlockBodies {
        request_id: u64,
        hashes: Vec<[u8; 32]>,
    },
    /// Send a pre-encoded, pre-compressed message to this peer.
    SendRaw { msg_id: u8, payload: Arc<Vec<u8>> },
}

struct PeerHandle {
    cmd_tx: mpsc::Sender<PeerCommand>,
}

/// Pre-encoded block data for broadcasting to peers.
pub struct BlockBroadcast<'a> {
    pub header_rlp: &'a [u8],
    pub block_hash: &'a [u8; 32],
    pub block_number: u64,
    pub transactions_rlp: &'a [Vec<u8>],
    pub uncles_rlp: &'a [Vec<u8>],
    pub td_bytes: &'a [u8],
    pub exclude: Option<&'a [u8; 64]>,
}

pub struct PeerManager {
    static_key: SigningKey,
    node_id: [u8; 64],
    listen_port: u16,
    eth_status: Arc<RwLock<EthStatus>>,
    active_peers: Arc<RwLock<HashMap<[u8; 64], PeerHandle>>>,
    event_tx: mpsc::Sender<PeerEvent>,
    max_peers: usize,
}

impl PeerManager {
    pub fn new(
        static_key: SigningKey,
        listen_port: u16,
        eth_status: EthStatus,
        max_peers: usize,
    ) -> (Self, mpsc::Receiver<PeerEvent>) {
        let (event_tx, event_rx) = mpsc::channel(256);
        let node_id = pubkey_to_node_id(&static_key);

        let manager = PeerManager {
            static_key,
            node_id,
            listen_port,
            eth_status: Arc::new(RwLock::new(eth_status)),
            active_peers: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
            max_peers,
        };

        (manager, event_rx)
    }

    pub async fn start_listener(&self) -> Result<(), crate::error::Error> {
        let addr = format!("0.0.0.0:{}", self.listen_port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| crate::error::Error::Io(format!("failed to bind {}: {}", addr, e)))?;

        info!(port = self.listen_port, "P2P TCP listener started");

        let static_key = self.static_key.clone();
        let active_peers = self.active_peers.clone();
        let eth_status = self.eth_status.clone();
        let event_tx = self.event_tx.clone();
        let node_id = self.node_id;
        let listen_port = self.listen_port;
        let max_peers = self.max_peers;

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let peer_count = active_peers.read().await.len();
                        if peer_count >= max_peers {
                            debug!(addr = %addr, "rejecting connection, max peers reached");
                            continue;
                        }

                        debug!(addr = %addr, "incoming connection");
                        let key = static_key.clone();
                        let peers = active_peers.clone();
                        let status = eth_status.clone();
                        let tx = event_tx.clone();

                        let handle = tokio::spawn(async move {
                            match accept_as_responder(stream, &key).await {
                                Ok(session) => {
                                    run_peer_session(
                                        session,
                                        node_id,
                                        listen_port,
                                        status,
                                        peers,
                                        tx,
                                    )
                                    .await;
                                }
                                Err(e) => {
                                    debug!(addr = %addr, err = %e, "inbound handshake failed");
                                }
                            }
                        });

                        // We store after spawning; the peer loop itself manages the HashMap entry
                        drop(handle);
                    }
                    Err(e) => {
                        warn!(err = %e, "accept failed");
                    }
                }
            }
        });

        Ok(())
    }

    pub async fn connect_to(&self, node: &NodeInfo) {
        let peer_count = self.active_peers.read().await.len();
        if peer_count >= self.max_peers {
            return;
        }

        // Don't connect to self
        if node.pubkey == self.node_id {
            return;
        }

        // Don't connect if already connected
        if self.active_peers.read().await.contains_key(&node.pubkey) {
            return;
        }

        let remote_pubkey = match parse_uncompressed_pubkey(&node.pubkey) {
            Ok(pk) => pk,
            Err(_) => return,
        };

        let addr = format!("{}:{}", node.addr.ip(), node.tcp_port);
        let static_key = self.static_key.clone();
        let active_peers = self.active_peers.clone();
        let eth_status = self.eth_status.clone();
        let event_tx = self.event_tx.clone();
        let node_id = self.node_id;
        let listen_port = self.listen_port;

        tokio::spawn(async move {
            match connect_as_initiator(&addr, &static_key, &remote_pubkey).await {
                Ok(session) => {
                    run_peer_session(
                        session,
                        node_id,
                        listen_port,
                        eth_status,
                        active_peers,
                        event_tx,
                    )
                    .await;
                }
                Err(e) => {
                    debug!(addr, err = %e, "outbound connection failed");
                }
            }
        });
    }

    pub async fn peer_count(&self) -> usize {
        self.active_peers.read().await.len()
    }

    /// Update the local EthStatus broadcast to new peers.
    /// Called when the chain head progresses.
    pub async fn update_eth_status(
        &self,
        best_hash: [u8; 32],
        td: Vec<u8>,
        genesis_hash: Option<[u8; 32]>,
        head_number: Option<u64>,
    ) {
        let mut status = self.eth_status.write().await;
        status.best_hash = best_hash;
        status.total_difficulty = td;
        if let Some(gh) = genesis_hash {
            status.genesis_hash = gh;
        }
        if let Some(n) = head_number {
            status.head_number = n;
        }
    }

    /// Send a graceful disconnect to all active peers and wait briefly for delivery.
    pub async fn shutdown(&self) {
        let disconnect_rlp = p2p::DisconnectReason::ClientQuitting.to_rlp();
        let compressed = snap::raw::Encoder::new()
            .compress_vec(&disconnect_rlp)
            .unwrap_or(disconnect_rlp);

        let compressed = Arc::new(compressed);
        let peers = self.active_peers.read().await;
        let count = peers.len();
        for handle in peers.values() {
            let _ = handle.cmd_tx.try_send(PeerCommand::SendRaw {
                msg_id: p2p::DISCONNECT_MSG_ID,
                payload: Arc::clone(&compressed),
            });
        }
        drop(peers);

        if count > 0 {
            // Give a short window for disconnect messages to be sent on the wire
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            info!(peers = count, "sent disconnect to all peers");
        }
    }

    /// Send a command to a specific peer. Returns true if the command was queued.
    pub async fn send_command(&self, node_id: &[u8; 64], cmd: PeerCommand) -> bool {
        let peers = self.active_peers.read().await;
        if let Some(handle) = peers.get(node_id) {
            handle.cmd_tx.try_send(cmd).is_ok()
        } else {
            false
        }
    }

    /// Broadcast a new block to peers following eth protocol rules:
    /// - Full `NewBlock` to sqrt(n) randomly chosen peers
    /// - `NewBlockHashes` to the rest
    pub async fn broadcast_block(&self, block: &BlockBroadcast<'_>) {
        use rand::seq::SliceRandom;
        use rand::SeedableRng;

        // Collect eligible peers
        let peers = self.active_peers.read().await;
        let mut eligible: Vec<[u8; 64]> = peers
            .keys()
            .filter(|id| block.exclude != Some(*id))
            .copied()
            .collect();
        drop(peers);

        if eligible.is_empty() {
            return;
        }

        // Encode both messages once, wrap in Arc to avoid cloning large payloads
        let new_block_payload: Arc<Vec<u8>> = Arc::new(eth::encode_new_block(
            block.header_rlp,
            block.transactions_rlp,
            block.uncles_rlp,
            block.td_bytes,
        ));
        let new_block_hashes_payload: Arc<Vec<u8>> = Arc::new(eth::encode_new_block_hashes(&[(
            *block.block_hash,
            block.block_number,
        )]));

        let new_block_msg_id = eth::ETH_MSG_OFFSET + eth::NEW_BLOCK_MSG_ID;
        let new_block_hashes_msg_id = eth::ETH_MSG_OFFSET + eth::NEW_BLOCK_HASHES_MSG_ID;

        // sqrt(n) peers get the full block
        let full_count = (eligible.len() as f64).sqrt().ceil() as usize;

        let mut rng = rand::rngs::StdRng::from_entropy();
        eligible.shuffle(&mut rng);

        let peers = self.active_peers.read().await;
        for (i, node_id) in eligible.iter().enumerate() {
            if let Some(handle) = peers.get(node_id) {
                if i < full_count {
                    let _ = handle.cmd_tx.try_send(PeerCommand::SendRaw {
                        msg_id: new_block_msg_id,
                        payload: Arc::clone(&new_block_payload),
                    });
                } else {
                    let _ = handle.cmd_tx.try_send(PeerCommand::SendRaw {
                        msg_id: new_block_hashes_msg_id,
                        payload: Arc::clone(&new_block_hashes_payload),
                    });
                }
            }
        }
        drop(peers);

        debug!(
            block = block.block_number,
            full = full_count,
            hashes = eligible.len().saturating_sub(full_count),
            "broadcast block to peers"
        );
    }
}

/// Send a Disconnect message to a peer. The payload must be snappy-compressed
/// after Hello exchange (p2p v5).
async fn send_disconnect(
    session: &mut Session,
    reason: p2p::DisconnectReason,
) -> Result<(), crate::error::Error> {
    let rlp = reason.to_rlp();
    let compressed = snap::raw::Encoder::new().compress_vec(&rlp).unwrap_or(rlp);
    session
        .write_message(p2p::DISCONNECT_MSG_ID, &compressed)
        .await
}

async fn run_peer_session(
    mut session: Session,
    our_node_id: [u8; 64],
    listen_port: u16,
    eth_status: Arc<RwLock<EthStatus>>,
    active_peers: Arc<RwLock<HashMap<[u8; 64], PeerHandle>>>,
    event_tx: mpsc::Sender<PeerEvent>,
) {
    let remote_pubkey = session.remote_pubkey;

    // Send Hello
    let hello = HelloMessage::new(
        CLIENT_ID,
        vec![Capability::new("eth", 68)],
        listen_port,
        our_node_id,
    );

    if let Err(e) = session
        .write_message(p2p::HELLO_MSG_ID, &hello.to_rlp())
        .await
    {
        debug!(err = %e, "failed to send Hello");
        return;
    }

    // Receive Hello
    let remote_hello = match session.read_message().await {
        Ok((msg_id, payload)) => {
            if msg_id == p2p::DISCONNECT_MSG_ID {
                // Pre-Hello: snappy is NOT yet active, so use the raw payload.
                let reason = p2p::DisconnectReason::from_rlp(&payload);
                debug!(reason = %reason.description(), "peer disconnected during Hello");
                return;
            }
            if msg_id != p2p::HELLO_MSG_ID {
                debug!(msg_id, "unexpected message during Hello");
                return;
            }
            match HelloMessage::from_rlp(&payload) {
                Ok(h) => h,
                Err(e) => {
                    debug!(err = %e, "failed to parse Hello");
                    return;
                }
            }
        }
        Err(e) => {
            debug!(err = %e, "failed to read Hello");
            return;
        }
    };

    // Check eth/68 capability
    let has_eth68 = remote_hello
        .capabilities
        .iter()
        .any(|c| c.name == "eth" && c.version == 68);

    if !has_eth68 {
        debug!(
            client = remote_hello.client_id,
            "peer doesn't support eth/68"
        );
        let _ = send_disconnect(&mut session, p2p::DisconnectReason::UselessPeer).await;
        return;
    }

    info!(
        client = remote_hello.client_id,
        node_id = %hex::encode(&remote_pubkey[..8]),
        "Hello exchanged"
    );

    // Exchange Status
    let status = eth_status.read().await;
    if let Err(e) = eth::send_status(&mut session, &status).await {
        debug!(err = %e, "failed to send Status");
        return;
    }
    drop(status);

    let remote_status = match eth::receive_status(&mut session).await {
        Ok(s) => s,
        Err(e) => {
            debug!(err = %e, "failed to receive Status");
            return;
        }
    };

    // Validate peer compatibility (network_id + genesis_hash + fork_id EIP-2124)
    {
        let local = eth_status.read().await;
        if remote_status.network_id != local.network_id {
            debug!(
                remote = remote_status.network_id,
                local = local.network_id,
                "peer network_id mismatch, disconnecting"
            );
            drop(local);
            let _ = send_disconnect(&mut session, p2p::DisconnectReason::UselessPeer).await;
            return;
        }
        if remote_status.genesis_hash != local.genesis_hash {
            debug!(
                remote = %hex::encode(remote_status.genesis_hash),
                local = %hex::encode(local.genesis_hash),
                "peer genesis hash mismatch, disconnecting"
            );
            drop(local);
            let _ = send_disconnect(&mut session, p2p::DisconnectReason::UselessPeer).await;
            return;
        }
        if let Some(ref filter) = local.fork_filter {
            if let Err(reason) = filter.validate(&remote_status.fork_id, local.head_number) {
                debug!(
                    reason,
                    remote_hash = %hex::encode(remote_status.fork_id.fork_hash),
                    remote_next = remote_status.fork_id.fork_next,
                    "peer fork_id incompatible (EIP-2124), disconnecting"
                );
                drop(local);
                let _ = send_disconnect(&mut session, p2p::DisconnectReason::UselessPeer).await;
                return;
            }
        }
    }

    info!(
        network = remote_status.network_id,
        td_len = remote_status.total_difficulty.len(),
        node_id = %hex::encode(&remote_pubkey[..8]),
        "Status exchanged"
    );

    // Register peer with command channel
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<PeerCommand>(64);
    {
        let mut peers = active_peers.write().await;
        peers.insert(remote_pubkey, PeerHandle { cmd_tx });
    }

    if event_tx
        .send(PeerEvent::Connected {
            node_id: remote_pubkey,
            client_id: remote_hello.client_id.clone(),
            td: remote_status.total_difficulty.clone(),
            best_hash: remote_status.best_hash,
        })
        .await
        .is_err()
    {
        warn!("event channel closed");
        let mut peers = active_peers.write().await;
        peers.remove(&remote_pubkey);
        return;
    }

    // Per-peer message loop
    let mut ping_timer = interval(PING_INTERVAL);
    ping_timer.tick().await; // skip first immediate tick

    // After Hello (p2p v5), ALL messages must carry snappy-compressed payloads.
    // Ping/Pong body = snappy_compress(RLP empty list = 0xc0).
    let snappy_empty_list = snap::raw::Encoder::new()
        .compress_vec(&[0xc0])
        .expect("snappy compress of 1 byte cannot fail");

    let disconnect_reason = loop {
        tokio::select! {
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    PeerCommand::GetBlockHeaders { request_id, start, limit, skip, reverse } => {
                        if let Err(e) = eth::send_get_block_headers(&mut session, request_id, &start, limit, skip, reverse).await {
                            break format!("send GetBlockHeaders failed: {}", e);
                        }
                    }
                    PeerCommand::GetBlockBodies { request_id, hashes } => {
                        if let Err(e) = eth::send_get_block_bodies(&mut session, request_id, &hashes).await {
                            break format!("send GetBlockBodies failed: {}", e);
                        }
                    }
                    PeerCommand::SendRaw { msg_id, payload } => {
                        if let Err(e) = session.write_message(msg_id, &payload).await {
                            break format!("send raw msg 0x{:02x} failed: {}", msg_id, e);
                        }
                    }
                }
            }
            _ = ping_timer.tick() => {
                if let Err(e) = session.write_message(p2p::PING_MSG_ID, &snappy_empty_list).await {
                    break format!("ping send failed: {}", e);
                }
            }
            result = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                session.read_message(),
            ) => {
                let result = match result {
                    Ok(r) => r,
                    Err(_) => break "read timeout (30s)".to_string(),
                };
                match result {
                    Ok((msg_id, payload)) => {
                        match msg_id {
                            p2p::PING_MSG_ID => {
                                if let Err(e) = session.write_message(p2p::PONG_MSG_ID, &snappy_empty_list).await {
                                    break format!("pong send failed: {}", e);
                                }
                            }
                            p2p::PONG_MSG_ID => {
                                // Peer is alive, nothing to do
                            }
                            p2p::DISCONNECT_MSG_ID => {
                                let decompressed = snap::raw::Decoder::new()
                                    .decompress_vec(&payload)
                                    .unwrap_or(payload);
                                let reason = p2p::DisconnectReason::from_rlp(&decompressed);
                                break reason.description();
                            }
                            id if id == eth::ETH_MSG_OFFSET + eth::BLOCK_HEADERS_MSG_ID => {
                                let decompressed = match snap::raw::Decoder::new().decompress_vec(&payload) {
                                    Ok(d) => d,
                                    Err(e) => {
                                        warn!(err = %e, "snappy decompress failed for BlockHeaders");
                                        continue;
                                    }
                                };
                                if let Ok(items) = crate::rlp::decode(&decompressed) {
                                    if let Ok(list) = items.into_list() {
                                        if list.len() >= 2 {
                                            let rid_bytes = match list[0].clone().into_bytes() {
                                                Ok(b) => b,
                                                Err(e) => {
                                                    warn!(err = %e, "BlockHeaders: failed to decode request_id");
                                                    continue;
                                                }
                                            };
                                            let request_id = crate::bytes::decode_u64(&rid_bytes);
                                            let header_items = match list[1].clone().into_list() {
                                                Ok(l) => l,
                                                Err(e) => {
                                                    warn!(err = %e, "BlockHeaders: failed to decode headers list");
                                                    continue;
                                                }
                                            };
                                            let headers: Vec<Vec<u8>> = header_items
                                                .into_iter()
                                                .map(|i| i.encode())
                                                .collect();
                                            if event_tx
                                                .send(PeerEvent::BlockHeaders {
                                                    node_id: remote_pubkey,
                                                    request_id,
                                                    headers,
                                                })
                                                .await
                                                .is_err()
                                            {
                                                warn!("event channel closed");
                                                break "event channel closed".to_string();
                                            }
                                        }
                                    }
                                }
                            }
                            id if id == eth::ETH_MSG_OFFSET + eth::BLOCK_BODIES_MSG_ID => {
                                let decompressed = match snap::raw::Decoder::new().decompress_vec(&payload) {
                                    Ok(d) => d,
                                    Err(e) => {
                                        warn!(err = %e, "snappy decompress failed for BlockBodies");
                                        continue;
                                    }
                                };
                                if let Ok(items) = crate::rlp::decode(&decompressed) {
                                    if let Ok(list) = items.into_list() {
                                        if list.len() >= 2 {
                                            let rid_bytes = match list[0].clone().into_bytes() {
                                                Ok(b) => b,
                                                Err(e) => {
                                                    warn!(err = %e, "BlockBodies: failed to decode request_id");
                                                    continue;
                                                }
                                            };
                                            let request_id = crate::bytes::decode_u64(&rid_bytes);
                                            let body_items = match list[1].clone().into_list() {
                                                Ok(l) => l,
                                                Err(e) => {
                                                    warn!(err = %e, "BlockBodies: failed to decode bodies list");
                                                    continue;
                                                }
                                            };
                                            let bodies: Vec<Vec<u8>> = body_items
                                                .into_iter()
                                                .map(|i| i.encode())
                                                .collect();
                                            if event_tx
                                                .send(PeerEvent::BlockBodies {
                                                    node_id: remote_pubkey,
                                                    request_id,
                                                    bodies,
                                                })
                                                .await
                                                .is_err()
                                            {
                                                warn!("event channel closed");
                                                break "event channel closed".to_string();
                                            }
                                        }
                                    }
                                }
                            }
                            // NewBlock broadcast — forward to sync
                            id if id == eth::ETH_MSG_OFFSET + eth::NEW_BLOCK_MSG_ID => {
                                if event_tx
                                    .send(PeerEvent::NewBlock {
                                        node_id: remote_pubkey,
                                        payload,
                                    })
                                    .await
                                    .is_err()
                                {
                                    warn!("event channel closed");
                                    break "event channel closed".to_string();
                                }
                            }
                            // NewBlockHashes broadcast — forward to sync
                            id if id == eth::ETH_MSG_OFFSET + eth::NEW_BLOCK_HASHES_MSG_ID => {
                                if event_tx
                                    .send(PeerEvent::NewBlockHashes {
                                        node_id: remote_pubkey,
                                        payload,
                                    })
                                    .await
                                    .is_err()
                                {
                                    warn!("event channel closed");
                                    break "event channel closed".to_string();
                                }
                            }
                            // Tx broadcasts — EL maintains its own eth/68 peer network and handles
                            // tx gossip independently (txBroadcastLoop runs unconditionally in
                            // beacon mode). No need to duplicate this work in the CL.
                            id if id == eth::ETH_MSG_OFFSET + eth::TRANSACTIONS_MSG_ID
                                || id == eth::ETH_MSG_OFFSET + eth::NEW_POOLED_TRANSACTION_HASHES_MSG_ID =>
                            {
                                debug!(msg_id, "ignoring tx broadcast");
                            }
                            // Request messages — forward to main loop for real data serving
                            id if id == eth::ETH_MSG_OFFSET + eth::GET_BLOCK_HEADERS_MSG_ID => {
                                match eth::decode_get_block_headers(&payload) {
                                    Ok(request) => {
                                        if event_tx
                                            .send(PeerEvent::GetBlockHeadersRequest {
                                                node_id: remote_pubkey,
                                                request,
                                            })
                                            .await
                                            .is_err()
                                        {
                                            warn!("event channel closed");
                                            break "event channel closed".to_string();
                                        }
                                    }
                                    Err(e) => {
                                        debug!(err = %e, "failed to decode GetBlockHeaders");
                                        // Fallback: try to send empty response
                                        if let Ok(rid) = eth::extract_request_id(&payload) {
                                            if let Err(e) = eth::send_empty_response(&mut session, eth::BLOCK_HEADERS_MSG_ID, rid).await {
                                                break format!("send empty BlockHeaders failed: {}", e);
                                            }
                                        }
                                    }
                                }
                            }
                            id if id == eth::ETH_MSG_OFFSET + eth::GET_BLOCK_BODIES_MSG_ID => {
                                match eth::decode_get_block_bodies(&payload) {
                                    Ok(request) => {
                                        if event_tx
                                            .send(PeerEvent::GetBlockBodiesRequest {
                                                node_id: remote_pubkey,
                                                request,
                                            })
                                            .await
                                            .is_err()
                                        {
                                            warn!("event channel closed");
                                            break "event channel closed".to_string();
                                        }
                                    }
                                    Err(e) => {
                                        debug!(err = %e, "failed to decode GetBlockBodies");
                                        if let Ok(rid) = eth::extract_request_id(&payload) {
                                            if let Err(e) = eth::send_empty_response(&mut session, eth::BLOCK_BODIES_MSG_ID, rid).await {
                                                break format!("send empty BlockBodies failed: {}", e);
                                            }
                                        }
                                    }
                                }
                            }
                            // GetPooledTransactions — respond empty. The CL has no tx pool;
                            // tx gossip is handled entirely by the EL's own peer network.
                            id if id == eth::ETH_MSG_OFFSET + eth::GET_POOLED_TRANSACTIONS_MSG_ID => {
                                match eth::extract_request_id(&payload) {
                                    Ok(rid) => {
                                        debug!(request_id = rid, "responding empty to GetPooledTransactions");
                                        if let Err(e) = eth::send_empty_response(&mut session, eth::POOLED_TRANSACTIONS_MSG_ID, rid).await {
                                            break format!("send empty PooledTransactions failed: {}", e);
                                        }
                                    }
                                    Err(e) => debug!(err = %e, "failed to parse GetPooledTransactions request_id"),
                                }
                            }
                            id if id == eth::ETH_MSG_OFFSET + eth::GET_RECEIPTS_MSG_ID => {
                                match eth::decode_get_receipts(&payload) {
                                    Ok(request) => {
                                        if event_tx
                                            .send(PeerEvent::GetReceiptsRequest {
                                                node_id: remote_pubkey,
                                                request,
                                            })
                                            .await
                                            .is_err()
                                        {
                                            warn!("event channel closed");
                                            break "event channel closed".to_string();
                                        }
                                    }
                                    Err(e) => {
                                        debug!(err = %e, "failed to decode GetReceipts");
                                        if let Ok(rid) = eth::extract_request_id(&payload) {
                                            if let Err(e) = eth::send_empty_response(&mut session, eth::RECEIPTS_MSG_ID, rid).await {
                                                break format!("send empty Receipts failed: {}", e);
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {
                                debug!(msg_id, "unknown eth message, ignoring");
                            }
                        }
                    }
                    Err(e) => {
                        break format!("{}", e);
                    }
                }
            }
        }
    };

    // Cleanup
    {
        let mut peers = active_peers.write().await;
        peers.remove(&remote_pubkey);
    }

    if event_tx
        .send(PeerEvent::Disconnected {
            node_id: remote_pubkey,
            reason: disconnect_reason.clone(),
        })
        .await
        .is_err()
    {
        warn!("event channel closed, cannot send Disconnected event");
    }

    debug!(
        node_id = %hex::encode(&remote_pubkey[..8]),
        reason = disconnect_reason,
        "peer disconnected"
    );
}
