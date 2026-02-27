use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub pubkey: [u8; 64],
    pub addr: SocketAddr,
    pub tcp_port: u16,
    pub udp_port: u16,
}

impl NodeInfo {
    #[cfg(test)]
    pub fn enode_url(&self) -> String {
        format!(
            "enode://{}@{}:{}",
            hex::encode(self.pubkey),
            self.addr.ip(),
            self.tcp_port
        )
    }
}
