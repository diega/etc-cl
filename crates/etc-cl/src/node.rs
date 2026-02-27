use std::path::Path;
use std::sync::Arc;

use alloy_primitives::Address;
use chain::tracker::ChainTracker;
use chain::types::td_to_rlp_bytes;
use devp2p::constants::{DEFAULT_LISTEN_PORT, MAX_PEERS};
use devp2p::crypto::pubkey_to_node_id;
use devp2p::discovery_manager::DiscoveryManager;
use devp2p::eth::{EthStatus, ForkFilter, ForkId};
use devp2p::peer_manager::{PeerEvent, PeerManager};
use engine_api::auth;
use engine_api::client::EngineClient;
use eth_rpc::EthClient;
use k256::ecdsa::SigningKey;
use mining::MiningCoordinator;
use sync::mess::MessConfig;
use sync::SyncManager;
use tokio::sync::{mpsc, Semaphore};
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

use crate::config::RuntimeConfig;

/// Main node orchestrator. Manages all subsystems and the main event loop.
pub struct Node {
    config: RuntimeConfig,
}

impl Node {
    pub fn new(config: RuntimeConfig) -> Self {
        Self { config }
    }

    /// Run the node: connect to EL, start subsystems, enter main loop.
    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!("starting etc-cl node");

        // Load JWT secret.
        let secret = auth::load_secret(&self.config.jwt_secret_path)?;
        info!(path = %self.config.jwt_secret_path.display(), "loaded JWT secret");

        // Create Engine API client (wrapped in Arc for sharing with mining).
        let engine = Arc::new(EngineClient::new(&self.config.engine_endpoint, secret)?);

        // Exchange capabilities with EL.
        let cl_capabilities = vec![
            "engine_newPayloadV2",
            "engine_forkchoiceUpdatedV2",
            "engine_getPayloadV2",
            "engine_exchangeCapabilities",
            "engine_getStatusInfoV1",
        ];

        match engine.exchange_capabilities(&cl_capabilities).await {
            Ok(caps) => {
                info!(capabilities = ?caps, "connected to execution layer");
                if !caps.iter().any(|c| c == "engine_getStatusInfoV1") {
                    error!("EL does not support engine_getStatusInfoV1 — required for EIP-2124 peer validation");
                    return Err("EL must support engine_getStatusInfoV1".into());
                }
            }
            Err(e) => {
                error!(err = %e, "failed to connect to execution layer");
                return Err(e.into());
            }
        }

        // Fetch EL network identity and fork schedule (required for EIP-2124).
        let status_info = match engine.get_status_info().await {
            Ok(info) => {
                if info.fork_blocks.is_empty() {
                    error!("EL returned empty fork_blocks — cannot validate peers (EIP-2124)");
                    return Err("EL must provide fork_blocks in engine_getStatusInfoV1".into());
                }
                info!(
                    network_id = info.network_id,
                    fork_hash = %hex::encode(&info.hash),
                    fork_next = info.next,
                    fork_blocks = ?info.fork_blocks,
                    "received EL status info"
                );
                info
            }
            Err(e) => {
                error!(err = %e, "failed to get EL status info — cannot start without fork schedule");
                return Err(e.into());
            }
        };

        // Load or generate node key
        let nodekey_path = self.config.datadir.join("nodekey");
        let static_key = load_or_generate_nodekey(&nodekey_path)?;
        let node_id = pubkey_to_node_id(&static_key);
        info!(
            node_id = %hex::encode(&node_id[..8]),
            "node identity loaded"
        );

        // Build EthStatus from EL data
        let eth_status = build_eth_status(&status_info)?;

        let listen_port = self.config.listen_port.unwrap_or(DEFAULT_LISTEN_PORT);

        // Create PeerManager (wrapped in Arc for sharing with spawned tasks)
        let (peer_manager, mut peer_rx) =
            PeerManager::new(static_key.clone(), listen_port, eth_status, MAX_PEERS);
        let peer_manager = Arc::new(peer_manager);

        // Create shared EthClient early so all bootstrap steps reuse it.
        let eth_client = Arc::new(EthClient::new(&self.config.eth_endpoint));

        // Create in-memory ChainTracker and seed from EL head BEFORE starting
        // the TCP listener and connecting to peers, so EthStatus reflects the
        // real head (not genesis/td=1) when peers first connect.
        let mut chain = ChainTracker::new();
        {
            // Seed genesis hash first
            if let Ok(genesis_block) = eth_client.get_block_by_number(0).await {
                let gh: [u8; 32] = *genesis_block.to_block_header().hash().as_ref();
                peer_manager
                    .update_eth_status(gh, vec![1], Some(gh), Some(0))
                    .await;
            }
            // Now seed with actual EL head
            match eth_client.get_block_number().await {
                Ok(el_head) => {
                    match eth_client.get_block_by_number(el_head).await {
                        Ok(block) => {
                            let header = block.to_block_header();
                            let hash = header.hash();
                            let td = block
                                .total_difficulty
                                .unwrap_or(alloy_primitives::U256::ZERO);
                            chain.init_from_el(hash, el_head, td);
                            // Update EthStatus with real head so peers see correct TD/hash
                            let hash_bytes: [u8; 32] = *hash.as_ref();
                            let td_bytes = td_to_rlp_bytes(&td);
                            peer_manager
                                .update_eth_status(hash_bytes, td_bytes, None, Some(el_head))
                                .await;
                            info!(number = el_head, hash = %hash, td = %td, "chain tracker seeded from EL");
                        }
                        Err(e) => {
                            warn!(err = %e, "failed to fetch EL head block, starting empty");
                        }
                    }
                }
                Err(e) => {
                    warn!(err = %e, "failed to get EL block number, starting empty");
                }
            }
        }

        // Start TCP listener AFTER seeding EthStatus so peers see real TD/hash
        peer_manager.start_listener().await?;

        // Build MESS config
        let mess_config = MessConfig {
            activation_block: sync::mess::ECBP1100_ACTIVATION,
            flag: self.config.mess_enabled,
        };

        // Create and start DiscoveryManager
        let (discovery_manager, mut node_rx) =
            DiscoveryManager::new(static_key, listen_port, self.config.dns_discovery.clone());
        discovery_manager.start().await?;

        // Connect to bootnodes
        for enode in &self.config.bootnodes {
            match devp2p::handshake::parse_enode_pubkey(enode) {
                Ok(pubkey) => {
                    let pubkey_bytes = devp2p::crypto::pubkey_to_bytes(&pubkey);
                    let parsed: url::Url = match url::Url::parse(enode) {
                        Ok(u) => u,
                        Err(_) => continue,
                    };
                    let host = parsed.host_str().unwrap_or("127.0.0.1");
                    let port = parsed.port().unwrap_or(DEFAULT_LISTEN_PORT);
                    // Parse ?discport=N query parameter for separate UDP discovery port
                    let udp_port = parsed
                        .query_pairs()
                        .find(|(k, _)| k == "discport")
                        .and_then(|(_, v)| v.parse::<u16>().ok())
                        .unwrap_or(port);
                    let addr = format!("{}:{}", host, port);
                    let node = devp2p::types::NodeInfo {
                        pubkey: pubkey_bytes,
                        addr: addr.parse().unwrap_or_else(|e| {
                            warn!(addr = %addr, err = %e, "failed to parse bootnode address, falling back to 127.0.0.1");
                            std::net::SocketAddr::new(
                                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                                port,
                            )
                        }),
                        tcp_port: port,
                        udp_port,
                    };
                    info!(enode = %&enode[..50.min(enode.len())], "connecting to bootnode");
                    peer_manager.connect_to(&node).await;
                }
                Err(e) => {
                    warn!(enode, err = %e, "invalid bootnode enode URL");
                }
            }
        }

        let eth_endpoint = self.config.eth_endpoint.as_str();
        let mut sync_manager = SyncManager::new(chain, mess_config, Some(eth_endpoint));

        // Set head timestamp from EL head
        if sync_manager.chain().head_hash().is_some() {
            if let Ok(block) = eth_client
                .get_block_by_number(sync_manager.chain().head_number())
                .await
            {
                sync_manager.set_head_timestamp(block.to_block_header().timestamp);
            }
        }

        // Send initial FCU to anchor the EL's head. After a restart, geth needs
        // a forkchoiceUpdated pointing to a block it already has before it will
        // accept new payloads ("forced head needed for startup").
        // Note: we intentionally set safe=finalized=head here (not from ChainTracker's
        // fork_choice_state) because the tracker only has 1 block after init. This is
        // a bootstrap FCU — the EL already validated these blocks, so it's safe.
        {
            let el_head_hash = match eth_client.get_block_number().await {
                Ok(n) => match eth_client.get_block_by_number(n).await {
                    Ok(b) => Some(b.to_block_header().hash()),
                    Err(_) => None,
                },
                Err(_) => None,
            };
            if let Some(hash) = el_head_hash {
                let state = engine_api::types::ForkchoiceState {
                    head_block_hash: hash,
                    safe_block_hash: hash,
                    finalized_block_hash: hash,
                };
                match engine.forkchoice_updated_v2(&state, None).await {
                    Ok(resp) => {
                        info!(
                            status = %resp.payload_status.status,
                            head = %hash,
                            "initial FCU to anchor EL head"
                        );
                    }
                    Err(e) => {
                        // No need to exit early — the periodic catchup FCU (every 10s)
                        // will re-send once the EL is ready, same as Lighthouse's watchdog.
                        warn!(err = %e, "initial FCU failed, will retry via catchup loop");
                    }
                }
            }
        }

        // Initialize mining if enabled.
        let mining_coordinator: Option<Arc<MiningCoordinator>> = if self.config.mining {
            let coinbase_str = self.config.mining_coinbase.as_deref().ok_or_else(|| {
                Box::<dyn std::error::Error>::from(
                    "--mining-coinbase is required when --mining is enabled",
                )
            })?;
            let coinbase_hex = coinbase_str.strip_prefix("0x").unwrap_or(coinbase_str);
            let coinbase_bytes = hex::decode(coinbase_hex).map_err(|e| {
                Box::<dyn std::error::Error>::from(format!("invalid coinbase address: {}", e))
            })?;
            if coinbase_bytes.len() != 20 {
                return Err(
                    format!("coinbase must be 20 bytes, got {}", coinbase_bytes.len()).into(),
                );
            }
            let coinbase = Address::from_slice(&coinbase_bytes);
            let coordinator = Arc::new(MiningCoordinator::new(coinbase));
            info!(coinbase = %coinbase_str, "mining enabled");
            Some(coordinator)
        } else {
            None
        };

        // Spawn mining RPC server if mining is enabled.
        let mut mined_rx: Option<mpsc::Receiver<mining::MinedBlock>> = None;
        let mut new_head_rx: Option<mpsc::Receiver<(alloy_primitives::B256, u64)>> = None;
        if let Some(ref coordinator) = mining_coordinator {
            let (tx, rx) = mpsc::channel(16);
            mined_rx = Some(rx);

            // Channel for SyncManager → mining coordinator new-head notifications
            let (head_tx, head_rx) = mpsc::channel(16);
            sync_manager.set_new_head_notify(head_tx);
            new_head_rx = Some(head_rx);

            let bind_addr = format!("{}:{}", self.config.mining_host, self.config.mining_port);
            let coord = Arc::clone(coordinator);
            let eng = Arc::clone(&engine);
            tokio::spawn(async move {
                if let Err(e) = mining::rpc::start_mining_rpc(coord, eng, tx, &bind_addr).await {
                    error!(err = %e, "mining RPC server failed");
                }
            });
        }

        info!(
            endpoint = %self.config.engine_endpoint,
            datadir = %self.config.datadir.display(),
            listen_port = listen_port,
            mine = self.config.mining,
            "node initialized, entering main loop"
        );

        info!("node is running (Ctrl+C to stop)");

        // Semaphore to limit concurrent serving tasks (GetBlockHeaders/Bodies/Receipts)
        let serve_semaphore = Arc::new(Semaphore::new(32));

        // Track the last head hash we announced in EthStatus, to avoid redundant updates.
        let mut last_status_head: Option<[u8; 32]> = None;

        let mut timeout_timer = interval(Duration::from_secs(5));
        timeout_timer.tick().await; // skip first immediate tick

        let mut catchup_timer = interval(Duration::from_secs(10));
        catchup_timer.tick().await; // skip first immediate tick

        // Main event loop
        loop {
            tokio::select! {
                Some(event) = peer_rx.recv() => {
                    match event {
                        PeerEvent::Connected { node_id, client_id, td, best_hash } => {
                            info!(
                                node_id = %hex::encode(&node_id[..8]),
                                client = client_id,
                                td_len = td.len(),
                                peers = peer_manager.peer_count().await,
                                "peer connected"
                            );
                            sync_manager.on_peer_connected(
                                node_id, &client_id, td, best_hash, peer_manager.as_ref()
                            ).await;
                        }
                        PeerEvent::Disconnected { node_id, reason } => {
                            debug!(
                                node_id = %hex::encode(&node_id[..8]),
                                reason,
                                peers = peer_manager.peer_count().await,
                                "peer disconnected"
                            );
                            sync_manager.on_peer_disconnected(
                                node_id, peer_manager.as_ref()
                            ).await;
                        }
                        PeerEvent::BlockHeaders { node_id, request_id, headers } => {
                            debug!(
                                node_id = %hex::encode(&node_id[..8]),
                                request_id,
                                count = headers.len(),
                                "received block headers"
                            );
                            sync_manager.on_block_headers(
                                node_id, request_id, headers,
                                peer_manager.as_ref(), engine.as_ref(),
                            ).await;
                        }
                        PeerEvent::BlockBodies { node_id, request_id, bodies } => {
                            debug!(
                                node_id = %hex::encode(&node_id[..8]),
                                request_id,
                                count = bodies.len(),
                                "received block bodies"
                            );
                            sync_manager.on_block_bodies(
                                node_id, request_id, bodies,
                                peer_manager.as_ref(), engine.as_ref(),
                            ).await;
                        }
                        PeerEvent::NewBlock { node_id, payload } => {
                            sync_manager.on_new_block(
                                node_id, payload,
                                peer_manager.as_ref(), engine.as_ref(),
                            ).await;
                        }
                        PeerEvent::NewBlockHashes { node_id, payload } => {
                            sync_manager.on_new_block_hashes(
                                node_id, payload,
                                peer_manager.as_ref(),
                            ).await;
                        }
                        PeerEvent::GetBlockHeadersRequest { node_id, request } => {
                            let pm = Arc::clone(&peer_manager);
                            let eth = Arc::clone(&eth_client);
                            let sem = Arc::clone(&serve_semaphore);
                            tokio::spawn(async move {
                                let _permit = match sem.acquire().await {
                                    Ok(p) => p,
                                    Err(_) => return,
                                };
                                crate::server::serve_block_headers(pm, eth, node_id, request).await;
                            });
                        }
                        PeerEvent::GetBlockBodiesRequest { node_id, request } => {
                            let pm = Arc::clone(&peer_manager);
                            let eth = Arc::clone(&eth_client);
                            let sem = Arc::clone(&serve_semaphore);
                            tokio::spawn(async move {
                                let _permit = match sem.acquire().await {
                                    Ok(p) => p,
                                    Err(_) => return,
                                };
                                crate::server::serve_block_bodies(pm, eth, node_id, request).await;
                            });
                        }
                        PeerEvent::GetReceiptsRequest { node_id, request } => {
                            let pm = Arc::clone(&peer_manager);
                            let eth = Arc::clone(&eth_client);
                            let sem = Arc::clone(&serve_semaphore);
                            tokio::spawn(async move {
                                let _permit = match sem.acquire().await {
                                    Ok(p) => p,
                                    Err(_) => return,
                                };
                                crate::server::serve_receipts(pm, eth, node_id, request).await;
                            });
                        }
                    }

                    // Update EthStatus if chain head has changed
                    if let Some(head_hash) = sync_manager.chain().head_hash() {
                        let hash_bytes: [u8; 32] = *head_hash.as_ref();
                        if last_status_head.as_ref() != Some(&hash_bytes) {
                            last_status_head = Some(hash_bytes);
                            let td = sync_manager.chain().head_td();
                            let td_bytes = td_to_rlp_bytes(&td);
                            peer_manager.update_eth_status(hash_bytes, td_bytes, None, Some(sync_manager.chain().head_number())).await;
                        }
                    }
                }
                Some(node) = node_rx.recv() => {
                    debug!(
                        node_id = %hex::encode(&node.pubkey[..8]),
                        addr = %node.addr,
                        "discovered new node, attempting connection"
                    );
                    peer_manager.connect_to(&node).await;
                }
                // Handle mined blocks from the mining RPC.
                Some(mined_block) = async {
                    match mined_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    info!(
                        block = mined_block.number,
                        hash = %mined_block.hash,
                        "processing mined block"
                    );
                    // Fetch real TD from EL (the EL accepted the block via newPayload + FCU)
                    let mined_td = match eth_client.get_block_by_hash(mined_block.hash).await {
                        Ok(block) => block.total_difficulty,
                        Err(e) => {
                            warn!(err = %e, "failed to fetch mined block TD from EL, using fallback");
                            None
                        }
                    };
                    sync_manager.chain_mut().set_head(
                        mined_block.hash, mined_block.number, mined_td
                    );
                    // Broadcast mined block to peers
                    {
                        let td = sync_manager.chain().head_td();
                        let td_bytes = td_to_rlp_bytes(&td);
                        let uncles_rlp: Vec<Vec<u8>> = mined_block.uncles.iter().map(|u| u.rlp_encode()).collect();
                        peer_manager.broadcast_block(&devp2p::peer_manager::BlockBroadcast {
                            header_rlp: &mined_block.header_rlp,
                            block_hash: mined_block.hash.as_ref(),
                            block_number: mined_block.number,
                            transactions_rlp: &mined_block.transactions,
                            uncles_rlp: &uncles_rlp,
                            td_bytes: &td_bytes,
                            exclude: None, // no peer to exclude — we mined it
                        }).await;
                    }
                    // Update EthStatus after mining
                    {
                        let hash_bytes: [u8; 32] = *mined_block.hash.as_ref();
                        last_status_head = Some(hash_bytes);
                        let td = sync_manager.chain().head_td();
                        let td_bytes = td_to_rlp_bytes(&td);
                        peer_manager.update_eth_status(hash_bytes, td_bytes, None, Some(mined_block.number)).await;
                    }
                    // Trigger new work generation with uncle candidates.
                    if let Some(ref coordinator) = mining_coordinator {
                        let uncles = sync_manager.get_uncle_candidates();
                        if let Err(e) = coordinator.on_new_head(
                            engine.as_ref(),
                            mined_block.hash,
                            0, // timestamp will be max(parent+1, now) in on_new_head
                            uncles,
                        ).await {
                            warn!(err = %e, "failed to generate new mining work after mined block");
                        }
                    }
                }
                _ = timeout_timer.tick() => {
                    sync_manager.check_timeouts(peer_manager.as_ref()).await;
                }
                _ = catchup_timer.tick() => {
                    sync_manager.poll_catchup_fcu(
                        engine.as_ref(), peer_manager.as_ref()
                    ).await;
                }
                Some((hash, ts)) = async {
                    match new_head_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(ref coordinator) = mining_coordinator {
                        let uncles = sync_manager.get_uncle_candidates();
                        if let Err(e) = coordinator.on_new_head(
                            engine.as_ref(),
                            hash,
                            ts,
                            uncles,
                        ).await {
                            warn!(err = %e, "failed to generate mining work after new head");
                        }
                    }
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("shutdown signal received");
                    break;
                }
            }
        }

        peer_manager.shutdown().await;
        info!("node stopped");

        Ok(())
    }
}

fn load_or_generate_nodekey(path: &Path) -> Result<SigningKey, Box<dyn std::error::Error>> {
    if path.exists() {
        let hex_str = std::fs::read_to_string(path)?.trim().to_string();
        let bytes = hex::decode(&hex_str)?;
        if bytes.len() != 32 {
            return Err(format!("nodekey must be 32 bytes, got {}", bytes.len()).into());
        }
        let key = SigningKey::from_slice(&bytes)?;
        info!(path = %path.display(), "loaded existing node key");
        Ok(key)
    } else {
        let key = SigningKey::random(&mut rand::thread_rng());
        let bytes = key.to_bytes();
        // Ensure parent dir exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, hex::encode(bytes.as_slice()))?;
        info!(path = %path.display(), "generated new node key");
        Ok(key)
    }
}

fn build_eth_status(
    info: &engine_api::types::StatusInfoResponse,
) -> Result<EthStatus, Box<dyn std::error::Error>> {
    let mut genesis_hash = [0u8; 32];
    genesis_hash.copy_from_slice(info.genesis_hash.as_slice());

    if info.hash.len() != 4 {
        return Err(format!(
            "EL returned fork_hash with {} bytes, expected exactly 4",
            info.hash.len()
        )
        .into());
    }
    let mut fork_hash = [0u8; 4];
    fork_hash.copy_from_slice(&info.hash[..4]);

    let fork_filter = ForkFilter::new(&genesis_hash, &info.fork_blocks);

    Ok(EthStatus {
        protocol_version: 68,
        network_id: info.network_id,
        total_difficulty: vec![1],
        best_hash: genesis_hash,
        genesis_hash,
        fork_id: ForkId {
            fork_hash,
            fork_next: info.next,
        },
        head_number: 0,
        fork_filter: Some(fork_filter),
    })
}
