use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use k256::ecdsa::SigningKey;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::crypto::pubkey_to_node_id;
use crate::discv4::{DiscV4, DiscV4Event, Endpoint, NodeRecord};
use crate::dns_discovery::DnsDiscovery;
use crate::routing_table::RoutingTable;
use crate::types::NodeInfo;

const DISCOVERY_INTERVAL: Duration = Duration::from_secs(30);
const DNS_REFRESH_INTERVAL: Duration = Duration::from_secs(300);

pub struct DiscoveryManager {
    static_key: SigningKey,
    node_id: [u8; 64],
    listen_port: u16,
    dns_url: Option<String>,
    node_tx: mpsc::Sender<NodeInfo>,
}

impl DiscoveryManager {
    pub fn new(
        static_key: SigningKey,
        listen_port: u16,
        dns_url: Option<String>,
    ) -> (Self, mpsc::Receiver<NodeInfo>) {
        let (node_tx, node_rx) = mpsc::channel(256);
        let node_id = pubkey_to_node_id(&static_key);

        let manager = DiscoveryManager {
            static_key,
            node_id,
            listen_port,
            dns_url,
            node_tx,
        };

        (manager, node_rx)
    }

    pub async fn start(&self) -> Result<(), crate::error::Error> {
        let udp_addr = format!("0.0.0.0:{}", self.listen_port);
        let socket = UdpSocket::bind(&udp_addr).await.map_err(|e| {
            crate::error::Error::Io(format!("failed to bind UDP {}: {}", udp_addr, e))
        })?;

        let socket = Arc::new(socket);

        info!(port = self.listen_port, "discv4 UDP listener started");

        let local_endpoint = Endpoint::new(
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            self.listen_port,
            self.listen_port,
        );

        let discv4 = Arc::new(DiscV4::new(
            socket.clone(),
            self.static_key.clone(),
            local_endpoint,
        ));

        // Routing table
        let routing_table = Arc::new(tokio::sync::RwLock::new(RoutingTable::new(&self.node_id)));

        // Seed from DNS
        if let Some(ref url) = self.dns_url {
            let dns_url = url.clone();
            let node_tx = self.node_tx.clone();
            let rt = routing_table.clone();

            tokio::spawn(async move {
                Self::dns_seed_loop(dns_url, node_tx, rt).await;
            });
        }

        // discv4 receive loop
        {
            let discv4 = discv4.clone();
            let rt = routing_table.clone();
            let node_tx = self.node_tx.clone();

            tokio::spawn(async move {
                Self::discv4_recv_loop(discv4, rt, node_tx).await;
            });
        }

        // discv4 find loop
        {
            let discv4 = discv4.clone();
            let rt = routing_table.clone();
            let node_tx = self.node_tx.clone();

            tokio::spawn(async move {
                Self::discv4_find_loop(discv4, rt, node_tx).await;
            });
        }

        Ok(())
    }

    async fn dns_seed_loop(
        dns_url: String,
        node_tx: mpsc::Sender<NodeInfo>,
        routing_table: Arc<tokio::sync::RwLock<RoutingTable>>,
    ) {
        let mut timer = interval(DNS_REFRESH_INTERVAL);

        loop {
            timer.tick().await;

            let discovery = match DnsDiscovery::new(&dns_url) {
                Ok(d) => d,
                Err(e) => {
                    warn!(err = %e, "failed to create DNS discovery");
                    continue;
                }
            };

            match discovery.discover_nodes().await {
                Ok(nodes) => {
                    info!(count = nodes.len(), "DNS discovery found nodes");
                    let mut rt = routing_table.write().await;
                    for node in nodes {
                        rt.insert(node.clone());
                        let _ = node_tx.send(node).await;
                    }
                }
                Err(e) => {
                    warn!(err = %e, "DNS discovery failed");
                }
            }
        }
    }

    async fn discv4_recv_loop(
        discv4: Arc<DiscV4>,
        routing_table: Arc<tokio::sync::RwLock<RoutingTable>>,
        node_tx: mpsc::Sender<NodeInfo>,
    ) {
        loop {
            match discv4.recv().await {
                Ok((src, event)) => match event {
                    DiscV4Event::Ping {
                        hash,
                        sender_pubkey,
                    } => {
                        debug!(src = %src, "received PING, sending PONG");
                        if let Err(e) = discv4.send_pong(src, hash).await {
                            debug!(err = %e, "failed to send PONG");
                        }

                        // Add sender to routing table
                        let node = NodeInfo {
                            pubkey: sender_pubkey,
                            addr: src,
                            tcp_port: src.port(),
                            udp_port: src.port(),
                        };
                        let mut rt = routing_table.write().await;
                        rt.insert(node);
                    }
                    DiscV4Event::Pong { sender_pubkey, .. } => {
                        debug!(src = %src, "received PONG");
                        let node = NodeInfo {
                            pubkey: sender_pubkey,
                            addr: src,
                            tcp_port: src.port(),
                            udp_port: src.port(),
                        };
                        let mut rt = routing_table.write().await;
                        if rt.insert(node.clone()) {
                            let _ = node_tx.send(node).await;
                        }
                    }
                    DiscV4Event::FindNode { target, .. } => {
                        debug!(src = %src, "received FINDNODE");
                        let rt = routing_table.read().await;
                        let closest = rt.closest(&target, 16);
                        let records: Vec<NodeRecord> = closest
                            .into_iter()
                            .map(|n| NodeRecord {
                                ip: n.addr.ip(),
                                udp_port: n.udp_port,
                                tcp_port: n.tcp_port,
                                pubkey: n.pubkey,
                            })
                            .collect();
                        drop(rt);

                        if let Err(e) = discv4.send_neighbors(src, records).await {
                            debug!(err = %e, "failed to send NEIGHBORS");
                        }
                    }
                    DiscV4Event::Neighbors { nodes, .. } => {
                        debug!(src = %src, count = nodes.len(), "received NEIGHBORS");
                        let mut rt = routing_table.write().await;
                        for record in nodes {
                            let node = NodeInfo {
                                pubkey: record.pubkey,
                                addr: SocketAddr::new(record.ip, record.tcp_port),
                                tcp_port: record.tcp_port,
                                udp_port: record.udp_port,
                            };
                            if rt.insert(node.clone()) {
                                let _ = node_tx.send(node).await;
                            }
                        }
                    }
                    DiscV4Event::EnrRequest { request_hash, .. } => {
                        debug!(src = %src, "received ENR_REQUEST, sending ENR_RESPONSE");
                        if let Err(e) = discv4.send_enr_response(src, request_hash).await {
                            debug!(err = %e, "failed to send ENR_RESPONSE");
                        }
                    }
                },
                Err(e) => {
                    debug!(err = %e, "discv4 recv error");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    async fn discv4_find_loop(
        discv4: Arc<DiscV4>,
        routing_table: Arc<tokio::sync::RwLock<RoutingTable>>,
        _node_tx: mpsc::Sender<NodeInfo>,
    ) {
        let mut timer = interval(DISCOVERY_INTERVAL);

        loop {
            timer.tick().await;

            let rt = routing_table.read().await;
            let target = rt.random_target();
            let closest = rt.closest(&target, 3);
            drop(rt);

            for node in closest {
                let udp_addr = SocketAddr::new(node.addr.ip(), node.udp_port);
                if let Err(e) = discv4.send_find_node(udp_addr, target).await {
                    debug!(err = %e, "failed to send FINDNODE");
                }
            }
        }
    }
}
