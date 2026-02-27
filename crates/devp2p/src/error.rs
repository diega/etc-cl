use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("RLP error: {0}")]
    Rlp(String),
    #[error("ECIES error: {0}")]
    Ecies(String),
    #[error("frame error: {0}")]
    Frame(String),
    #[error("handshake error: {0}")]
    Handshake(String),
    #[error("session error: {0}")]
    Session(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("eth error: {0}")]
    Eth(String),
    #[error("discovery error: {0}")]
    Discovery(String),
    #[error("DNS error: {0}")]
    Dns(String),
    #[error("I/O error: {0}")]
    Io(String),
    #[error("connection closed")]
    ConnectionClosed,
    #[error("disconnected: {0}")]
    Disconnected(String),
    #[error("frame too large: {0} bytes")]
    FrameTooLarge(usize),
    #[error("timeout: {0}")]
    Timeout(String),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}
