mod app;
mod carburetor;
mod config;
mod db;
mod ids;
mod ingest;
mod metrics;
mod notice;
mod process;
mod retention;
mod stats;
mod symfetch;
mod web;

use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

use crate::config::Config;

const DEFAULT_CONFIG: &str = "throttle.toml";

#[derive(Parser)]
#[command(
    version,
    about = "Self-hosted crash report server for the Accelerator extension"
)]
struct Cli {
    /// Path to the TOML configuration; it has to exist. Without it,
    /// `throttle.toml` in the current directory is used if there is one,
    /// otherwise the defaults.
    #[arg(long, short, env = "THROTTLE_CONFIG", global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the web server.
    Serve,
    /// Load and validate the configuration, then print it (secrets hidden).
    CheckConfig,
    /// Run one retention pass now (the server also does this periodically).
    Clean,
    /// Write a consistent copy of the database to DEST (safe while the server
    /// runs). The dumps and symbols directories are plain files: copy them
    /// with rsync or similar.
    Backup { dest: PathBuf },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            // minidump-processor warns about every x86 dump ("unsupported CPU architecture":
            // it only disassembles the crashing instruction on amd64). The crash is processed
            // fine; RUST_LOG brings the warnings back.
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,minidump_processor=error")),
        )
        .init();

    let cli = Cli::parse();
    let config = match &cli.config {
        Some(path) => Config::load(path)?,
        None if Path::new(DEFAULT_CONFIG).exists() => Config::load(Path::new(DEFAULT_CONFIG))?,
        None => {
            tracing::info!(
                "no configuration file ({DEFAULT_CONFIG} not found), using the defaults"
            );
            Config::default()
        }
    };

    match cli.command {
        Command::CheckConfig => {
            let mut shown = config;
            for secret in [&mut shown.steam_api_key, &mut shown.metrics_token] {
                if secret.is_some() {
                    *secret = Some("<set>".into());
                }
            }
            println!("{shown:#?}");
            Ok(())
        }
        Command::Serve => app::serve(config).await.context("server failed"),
        Command::Clean => {
            let db = db::open(&config.db_path()).await?;
            let report = retention::run_once(&db, &config, true).await?;
            println!("{report:?}");
            Ok(())
        }
        Command::Backup { dest } => {
            let db = db::open(&config.db_path()).await?;
            db::backup(&db, &dest).await?;
            println!("wrote {}", dest.display());
            Ok(())
        }
    }
}
