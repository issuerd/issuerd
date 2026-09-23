// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// CLI binary entry point for the Issuerd server.

#![forbid(unsafe_code)]

use clap::Parser;
use std::sync::Arc;

mod cli;
mod logging;
mod version;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    #[cfg(windows)]
    {
        let _ = enable_ansi_support::enable_ansi_support();
    }

    let cli = cli::Cli::parse();

    // Prevent multiple daemon instances from running concurrently.
    // The guard is held for the lifetime of the process; dropping it releases
    // the underlying OS lock (named mutex on Windows, flock/socket on Unix).
    let instance = single_instance::SingleInstance::new("issuerd-instance")
        .map_err(|e| anyhow::anyhow!("failed to create single-instance guard: {e}"))?;

    // Load the server configuration before initializing logging so the
    // [logging] section takes effect (RUST_LOG and -v/-q still override it).
    // Commands without a config file (openapi, example, healthcheck) use
    // flag/env logging only.
    let loaded: Option<(std::path::PathBuf, issuerd_server::config::ServerConfig)> =
        match &cli.command {
            cli::Commands::Daemon { config } | cli::Commands::Provision { config, .. } => {
                let path = std::env::current_dir()?.join(config);
                let cfg = issuerd_server::config::ServerConfig::load(Some(path.clone()))?;
                Some((path, cfg))
            }
            _ => None,
        };

    logging::init_logging(&logging::LoggingSettings::resolve(
        cli.verbosity(),
        loaded.as_ref().map(|(_, cfg)| &cfg.logging),
    ))?;

    // rustls 0.23 requires an explicit crypto provider when more than one
    // provider feature is available in the dependency graph (e.g. both ring
    // and aws-lc-rs pulled in transitively). Install ring to match the
    // Issuerd `RingCryptoProvider` used everywhere else.
    let _ = rustls::crypto::ring::default_provider().install_default();

    match cli.command {
        cli::Commands::Daemon { .. } => {
            if !instance.is_single() {
                tracing::error!("Another Issuerd instance is already running");
                std::process::exit(1);
            }
            tracing::info!("{}", version::full_version());
            tracing::info!("Issuerd daemon starting");
            let (config_path, cfg) = loaded.expect("daemon config loaded before init_logging");
            tracing::info!(config_path = %config_path.display(), "loaded configuration");
            let state = Arc::new(issuerd_server::state::ServerState::from_config(&cfg).await?);
            let app = issuerd_server::routes::app_router(state);
            if let Err(e) = issuerd_server::routes::init_metrics() {
                tracing::debug!(error = %e, "metrics recorder already initialized or unavailable");
            }
            issuerd_server::bootstrap::run(&cfg, app, issuerd_server::bootstrap::shutdown_signal())
                .await?;
        }
        cli::Commands::Provision { file, .. } => {
            let (config_path, cfg) = loaded.expect("provision config loaded before init_logging");
            tracing::info!(config_path = %config_path.display(), "loaded configuration");

            let storage: Arc<dyn issuerd_core::Storage> = match &cfg.storage {
                issuerd_server::config::StorageConfig::InMemory => {
                    Arc::new(issuerd_storage::InMemoryStorage::new())
                }
                issuerd_server::config::StorageConfig::Postgres { url } => {
                    let pg = issuerd_storage::PostgresStorage::connect(url).await?;
                    pg.run_migrations().await?;
                    Arc::new(pg)
                }
                issuerd_server::config::StorageConfig::JsonFile { path } => {
                    Arc::new(issuerd_storage::JsonFileStorage::new(path)?)
                }
            };

            let provisioner = issuerd_server::provisioner::Provisioner::from_file(&file)?;
            provisioner.apply_once(storage.as_ref(), &cfg.issuer_url).await?;
            tracing::info!("Provision applied successfully");
        }
        cli::Commands::Openapi { output } => {
            let spec = issuerd_server::openapi::full_openapi();
            let json = serde_json::to_string_pretty(&spec)?;
            std::fs::write(&output, json)?;
            tracing::info!("OpenAPI specification written to {}", output.display());
        }
        cli::Commands::Example { kind, output } => match kind {
            cli::ExampleKind::ServerConfig => {
                let cfg = issuerd_server::config::ServerConfig::generate_example();
                issuerd_server::config::write_example(&cfg, &output)?;
                tracing::info!("Server config example written to {}", output.display());
            }
            cli::ExampleKind::ProvisionConfig => {
                let cfg = issuerd_core::ProvisionConfig::generate_example();
                issuerd_server::config::write_example(&cfg, &output)?;
                tracing::info!("Provision config example written to {}", output.display());
            }
        },
        cli::Commands::Healthcheck {
            url,
            insecure,
            timeout_secs,
        } => {
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(insecure)
                .timeout(std::time::Duration::from_secs(timeout_secs))
                .build()?;
            let response = client.get(&url).send().await?;
            let status = response.status();
            if !status.is_success() {
                anyhow::bail!("health check failed: {status} from {url}");
            }
            tracing::info!(%status, %url, "health check passed");
        }
    }

    Ok(())
}
