use std::path::PathBuf;

use clap::Parser;
use serde::Deserialize;
use thiserror::Error;

// ============================================================================
// CLI STRUCTS
// ============================================================================

/// ETC-CL: Proof of Work Consensus Client for Ethereum Classic.
#[derive(Parser, Debug)]
#[command(name = "etc-cl", version = "0.1.0")]
pub struct Cli {
    /// Path to TOML configuration file.
    #[arg(short = 'C', long)]
    pub config: Option<PathBuf>,

    /// Engine API endpoint URL (e.g., http://localhost:8551).
    #[arg(long = "engine-endpoint")]
    pub engine_endpoint: Option<String>,

    /// Eth JSON-RPC endpoint URL (e.g., http://localhost:8545).
    #[arg(long = "eth-endpoint")]
    pub eth_endpoint: Option<String>,

    /// Path to JWT secret file for Engine API authentication.
    #[arg(long = "jwt-secret")]
    pub jwt_secret: Option<PathBuf>,

    /// Path to directory for node key and local data.
    #[arg(long = "datadir")]
    pub datadir: Option<PathBuf>,

    /// Comma-separated enode URLs for P2P discovery bootstrap.
    #[arg(short = 'b', long, value_delimiter = ',')]
    pub bootnodes: Vec<String>,

    /// Listen port for P2P (UDP and TCP).
    #[arg(short = 'l', long = "listen")]
    pub listen: Option<u16>,

    /// Enable mining. Without this flag, all --mining-* options are ignored.
    #[arg(long = "mining")]
    pub mining: bool,

    /// Mining coinbase address (required if --mining).
    #[arg(long = "mining-coinbase")]
    pub mining_coinbase: Option<String>,

    /// Mining RPC server host.
    #[arg(long = "mining-host")]
    pub mining_host: Option<String>,

    /// Mining RPC server port.
    #[arg(long = "mining-port")]
    pub mining_port: Option<u16>,

    /// DNS discovery URL (enrtree://...) for EIP-1459 node discovery.
    #[arg(long = "dns-discovery")]
    pub dns_discovery: Option<String>,

    /// Enable or disable MESS (ECBP-1100) anti-reorg mechanism.
    /// If not specified, uses hardcoded activation block (if any).
    #[arg(long = "mess-enabled")]
    pub mess_enabled: Option<bool>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(long = "log-level")]
    pub log_level: Option<String>,
}

// ============================================================================
// CONFIG FILE STRUCTS
// ============================================================================

/// Configuration loaded from TOML file.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    pub engine_endpoint: Option<String>,
    pub eth_endpoint: Option<String>,
    pub jwt_secret: Option<String>,
    pub datadir: Option<String>,
    #[serde(default)]
    pub bootnodes: Vec<String>,
    pub listen_port: Option<u16>,
    pub dns_discovery: Option<String>,
    pub mining: Option<bool>,
    pub mining_coinbase: Option<String>,
    pub mining_host: Option<String>,
    pub mining_port: Option<u16>,
    pub mess_enabled: Option<bool>,
    pub log_level: Option<String>,
}

// ============================================================================
// RUNTIME CONFIG
// ============================================================================

/// Final merged configuration for runtime.
pub struct RuntimeConfig {
    pub engine_endpoint: String,
    pub eth_endpoint: String,
    pub jwt_secret_path: PathBuf,
    pub datadir: PathBuf,
    pub bootnodes: Vec<String>,
    pub listen_port: Option<u16>,
    pub dns_discovery: Option<String>,
    pub mining: bool,
    pub mining_coinbase: Option<String>,
    pub mining_host: String,
    pub mining_port: u16,
    pub mess_enabled: Option<bool>,
    pub log_level: String,
}

impl RuntimeConfig {
    /// Merge CLI args with config file. Precedence: CLI > config file > defaults.
    pub fn from_cli_and_file(cli: &Cli, file: ConfigFile) -> Result<Self, ConfigError> {
        let engine_endpoint = cli
            .engine_endpoint
            .clone()
            .or(file.engine_endpoint)
            .ok_or(ConfigError::MissingRequired("engine-endpoint"))?;

        let eth_endpoint = cli
            .eth_endpoint
            .clone()
            .or(file.eth_endpoint)
            .unwrap_or_else(|| "http://localhost:8545".to_string());

        let jwt_secret_path = cli
            .jwt_secret
            .clone()
            .or_else(|| file.jwt_secret.map(PathBuf::from))
            .ok_or(ConfigError::MissingRequired("jwt-secret"))?;

        let datadir = cli
            .datadir
            .clone()
            .or_else(|| file.datadir.map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("data"));

        let bootnodes = if !cli.bootnodes.is_empty() {
            cli.bootnodes.clone()
        } else {
            file.bootnodes
        };

        let listen_port = cli.listen.or(file.listen_port);

        let dns_discovery = cli.dns_discovery.clone().or(file.dns_discovery);

        let mining = cli.mining || file.mining.unwrap_or(false);

        let mining_coinbase = cli.mining_coinbase.clone().or(file.mining_coinbase);

        let mining_host = cli
            .mining_host
            .clone()
            .or(file.mining_host)
            .unwrap_or_else(|| "127.0.0.1".to_string());

        let mining_port = cli.mining_port.or(file.mining_port).unwrap_or(8547);

        let mess_enabled = cli.mess_enabled.or(file.mess_enabled);

        let log_level = cli
            .log_level
            .clone()
            .or(file.log_level)
            .unwrap_or_else(|| "info".to_string());

        Ok(RuntimeConfig {
            engine_endpoint,
            eth_endpoint,
            jwt_secret_path,
            datadir,
            bootnodes,
            listen_port,
            dns_discovery,
            mining,
            mining_coinbase,
            mining_host,
            mining_port,
            mess_enabled,
            log_level,
        })
    }
}

// ============================================================================
// ERRORS
// ============================================================================

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("--{0} is required (via CLI or config file)")]
    MissingRequired(&'static str),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("config parse error: {0}")]
    Toml(#[from] toml::de::Error),
}

// ============================================================================
// LOADING FUNCTIONS
// ============================================================================

/// Load TOML config file, returns default if path is None.
pub fn load_config_file(path: Option<&PathBuf>) -> Result<ConfigFile, ConfigError> {
    match path {
        Some(p) => {
            let content = std::fs::read_to_string(p)?;
            toml::from_str(&content).map_err(ConfigError::Toml)
        }
        None => Ok(ConfigFile::default()),
    }
}
