mod config;
mod node;
mod server;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use config::{load_config_file, Cli, RuntimeConfig};
use node::Node;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Load config file if specified.
    let config_file = match load_config_file(cli.config.as_ref()) {
        Ok(cf) => cf,
        Err(e) => {
            eprintln!("error loading config file: {}", e);
            std::process::exit(1);
        }
    };

    // Merge CLI and file config.
    let runtime_config = match RuntimeConfig::from_cli_and_file(&cli, config_file) {
        Ok(rc) => rc,
        Err(e) => {
            eprintln!("configuration error: {}", e);
            std::process::exit(1);
        }
    };

    // Initialize logging (after merge so config file log_level is respected).
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&runtime_config.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    // Create and run the node.
    let mut node = Node::new(runtime_config);
    if let Err(e) = node.run().await {
        eprintln!("node error: {}", e);
        std::process::exit(1);
    }
}
