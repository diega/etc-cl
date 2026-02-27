use std::time::Duration;

pub const DEFAULT_LISTEN_PORT: u16 = 30303;
pub const MAX_PEERS: usize = 25;
pub const PING_INTERVAL: Duration = Duration::from_secs(15);
pub const CLIENT_ID: &str = "etc-cl/0.1.0";

pub const STATUS_EXCHANGE_TIMEOUT: Duration = Duration::from_millis(500);
pub const NODE_ID_LEN: usize = 64;
pub const PRIVATE_KEY_LEN: usize = 32;

// RLPx Frame Constants
pub const FRAME_HEADER_SIZE: usize = 16;
pub const FRAME_MAC_SIZE: usize = 16;
pub const FRAME_HEADER_WITH_MAC_SIZE: usize = FRAME_HEADER_SIZE + FRAME_MAC_SIZE;
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const RLP_EMPTY_LIST_2: u8 = 0xc2;
pub const RLP_EMPTY_BYTES: u8 = 0x80;

// ECIES Constants
pub const ECIES_OVERHEAD: usize = 65 + 16 + 32;

// discv4 Protocol Constants
pub const DISCV4_EXPIRATION_SECS: u64 = 60;
pub const DISCV4_MAX_PACKET_SIZE: usize = 1280;
pub const HASH_SIZE: usize = 32;
pub const SIGNATURE_SIZE: usize = 65;
