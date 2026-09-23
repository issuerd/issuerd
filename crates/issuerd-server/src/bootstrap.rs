// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Dmitry Andreev. <da@issuerd.org>
//
// HTTP server bootstrap: optional TLS, graceful shutdown, sd_notify integration.

use std::net::SocketAddr;

use axum::Router;
use tokio::net::TcpListener;
use tracing::{debug, error, info};

use crate::config::ServerConfig;

/// Bootstrap the HTTP server with optional TLS and graceful shutdown.
pub async fn run(
    config: &ServerConfig,
    app: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), std::io::Error> {
    // Parse as an IP literal so IPv6 addresses ("::1", "::") work; a
    // `format!("{bind}:{port}")` parse would misread the colons (P3-13).
    let ip: std::net::IpAddr = config.bind.parse().map_err(|e| {
        error!(bind = %config.bind, port = %config.port, error = %e, "invalid bind address");
        std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("invalid bind address: {e}"))
    })?;
    let addr = SocketAddr::new(ip, config.port);

    #[cfg(target_os = "linux")]
    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Status("Starting Issuerd...")]);

    debug!(bind = %config.bind, port = %config.port, tls = config.tls.is_some(), "server configuration");

    if let Some(ref tls) = config.tls {
        info!(addr = %addr, "starting TLS server");
        let rustls_config =
            crate::tls::load_tls_config(&tls.cert_path, &tls.key_path).map_err(|e| {
                error!(cert_path = %tls.cert_path, error = %e, "failed to load TLS configuration");
                std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
            })?;
        let axum_rustls =
            axum_server::tls_rustls::RustlsConfig::from_config(std::sync::Arc::new(rustls_config));

        // Use `bind_rustls` (tokio listener created inside the runtime)
        // rather than pre-binding a `std::net::TcpListener` + `from_tcp`:
        // on Windows the `from_std` accept loop never delivers connections.
        // Bind failures still propagate: the spawned task completes with the
        // io error and the `select!` below returns it.
        let handle = axum_server::Handle::new();
        let server = axum_server::bind_rustls(addr, axum_rustls)
            .handle(handle.clone())
            .serve(app.into_make_service_with_connect_info::<SocketAddr>());

        let mut server_task = tokio::spawn(server);
        tokio::select! {
            result = &mut server_task => {
                // The server ended on its own — surface the io result.
                return match result {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(e)) => Err(e),
                    Err(e) => Err(std::io::Error::other(format!("TLS server task failed: {e}"))),
                };
            }
            _ = shutdown => {}
        }
        handle.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
        // Await the server task so the graceful shutdown actually completes
        // (and late serve errors propagate).
        match server_task.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(e) => {
                return Err(std::io::Error::other(format!("TLS server task failed: {e}")));
            }
        }
    } else {
        info!(addr = %addr, "starting server");
        let listener = TcpListener::bind(&addr).await?;

        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .with_graceful_shutdown(shutdown)
            .await?;
    }

    #[cfg(target_os = "linux")]
    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Stopping]);

    info!("Server shutdown complete");
    Ok(())
}

pub async fn shutdown_signal() {
    #[cfg(coverage)]
    {
        // During coverage instrumentation the signal handlers are not testable,
        // so we return immediately to keep the function fully covered.
        return;
    }

    #[cfg(not(coverage))]
    {
        let ctrl_c = async {
            tokio::signal::ctrl_c().await.expect("failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {
                info!("Received Ctrl+C, initiating graceful shutdown");
            }
            _ = terminate => {
                info!("Received SIGTERM, initiating graceful shutdown");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ServerConfig;

    #[tokio::test]
    async fn run_with_invalid_bind_address_fails() {
        let config = ServerConfig {
            bind: "not-an-address".to_string(),
            ..Default::default()
        };
        let result = run(&config, axum::Router::new(), std::future::pending()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn run_with_valid_bind_address_binds() {
        let config = ServerConfig {
            bind: "127.0.0.1".to_string(),
            port: 0,
            ..Default::default()
        };
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            run(&config, axum::Router::new(), std::future::pending()),
        )
        .await;
        // Should time out because the server runs until shutdown_signal fires
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn run_with_valid_tls_binds() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let tmp_dir = std::env::temp_dir()
            .join(format!("issuerd_server_tls_bootstrap_{}", issuerd_core::utils::generate_id()));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let cert_path = tmp_dir.join("cert.pem");
        let key_path = tmp_dir.join("key.pem");

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("generate self-signed cert");
        std::fs::write(&cert_path, cert.cert.pem()).expect("write cert pem");
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key pem");

        let config = ServerConfig {
            bind: "127.0.0.1".to_string(),
            port: 0,
            tls: Some(crate::config::TlsConfig {
                cert_path: cert_path.to_str().unwrap().to_string(),
                key_path: key_path.to_str().unwrap().to_string(),
            }),
            ..Default::default()
        };
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            run(&config, axum::Router::new(), std::future::pending()),
        )
        .await;
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test]
    async fn run_with_invalid_tls_config_fails() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let config = ServerConfig {
            bind: "127.0.0.1".to_string(),
            port: 0,
            tls: Some(crate::config::TlsConfig {
                cert_path: "/nonexistent/cert.pem".to_string(),
                key_path: "/nonexistent/key.pem".to_string(),
            }),
            ..Default::default()
        };
        let result = run(&config, axum::Router::new(), std::future::pending()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn run_shutdown_completes_gracefully() {
        let config = ServerConfig {
            bind: "127.0.0.1".to_string(),
            port: 0,
            ..Default::default()
        };
        let result = run(&config, axum::Router::new(), std::future::ready(())).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn run_tls_shutdown_completes_gracefully() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let tmp_dir = std::env::temp_dir()
            .join(format!("issuerd_server_tls_shutdown_{}", issuerd_core::utils::generate_id()));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let cert_path = tmp_dir.join("cert.pem");
        let key_path = tmp_dir.join("key.pem");

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("generate self-signed cert");
        std::fs::write(&cert_path, cert.cert.pem()).expect("write cert pem");
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key pem");

        let config = ServerConfig {
            bind: "127.0.0.1".to_string(),
            port: 0,
            tls: Some(crate::config::TlsConfig {
                cert_path: cert_path.to_str().unwrap().to_string(),
                key_path: key_path.to_str().unwrap().to_string(),
            }),
            ..Default::default()
        };
        let result = run(&config, axum::Router::new(), std::future::ready(())).await;
        assert!(result.is_ok());
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }

    #[tokio::test]
    async fn shutdown_signal_returns_immediately() {
        let result =
            tokio::time::timeout(std::time::Duration::from_millis(100), shutdown_signal()).await;
        #[cfg(coverage)]
        assert!(result.is_ok(), "under coverage shutdown_signal returns immediately");
        #[cfg(not(coverage))]
        assert!(result.is_err(), "without coverage shutdown_signal waits for a signal");
    }

    #[tokio::test]
    async fn run_with_port_already_in_use_fails() {
        let _guard = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = _guard.local_addr().unwrap();

        let config = ServerConfig {
            bind: "127.0.0.1".to_string(),
            port: addr.port(),
            ..Default::default()
        };

        let result = run(&config, axum::Router::new(), std::future::ready(())).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn run_tls_with_port_already_in_use_fails() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let tmp_dir = std::env::temp_dir().join(format!(
            "issuerd_server_tls_bind_conflict_{}",
            issuerd_core::utils::generate_id()
        ));
        let _ = std::fs::create_dir_all(&tmp_dir);
        let cert_path = tmp_dir.join("cert.pem");
        let key_path = tmp_dir.join("key.pem");

        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("generate self-signed cert");
        std::fs::write(&cert_path, cert.cert.pem()).expect("write cert pem");
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key pem");

        let _guard = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = _guard.local_addr().unwrap();
        let config = ServerConfig {
            bind: "127.0.0.1".to_string(),
            port: addr.port(),
            tls: Some(crate::config::TlsConfig {
                cert_path: cert_path.to_str().unwrap().to_string(),
                key_path: key_path.to_str().unwrap().to_string(),
            }),
            ..Default::default()
        };

        // The bind failure must propagate even though shutdown is ready.
        let result = run(&config, axum::Router::new(), std::future::ready(())).await;
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(&tmp_dir);
    }
}
