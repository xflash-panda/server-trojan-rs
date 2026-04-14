//! Trojan proxy server with layered architecture
//!
//! Architecture:
//! - `core/`: Core proxy logic with hook traits for extensibility
//! - `transport/`: Transport layer abstraction (TCP, WebSocket, gRPC)
//! - `business/`: Business implementations (API, auth, stats)
//! - `handler`: Connection processing logic
//! - `server_runner`: Server startup and accept loop

mod acl;
mod business;
mod config;
mod core;
mod error;
mod handler;
mod logger;
mod server_runner;
mod transport;

// Use jemalloc as the global allocator.
// jemalloc actively returns freed memory to the OS (via muzzy/dirty page decay),
// unlike mimalloc which retains segments at peak capacity permanently.
// This prevents RSS from growing monotonically under high connection churn.
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use logger::log;

use anyhow::Result;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

use crate::business::{
    ApiManager, BackgroundTasks, PanelConfig, PanelStatsCollector, TaskConfig, TrojanAuthenticator,
    TrojanStatsCollector, UserManager,
};
use crate::core::{ConnectionManager, Server};
use panel_core::PanelApi;

#[tokio::main]
async fn main() -> Result<()> {
    // Install aws-lc-rs as the default crypto provider for rustls
    // This must be done before any TLS operations
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Parse CLI arguments
    let cli = config::CliArgs::parse_args();
    cli.validate()?;

    // Initialize logger
    logger::init_logger(&cli.log_mode);

    log::info!(
        api = %cli.api,
        node = cli.node,
        "Starting Trojan server with layered architecture"
    );

    // Create connection manager (shared between core and business layers)
    let conn_manager = ConnectionManager::new();

    // Create panel config
    let panel_config = PanelConfig {
        api: cli.api.clone(),
        token: cli.token.clone(),
        node_id: cli.node,
        node_type: panel_core::NodeType::Trojan,
        state_file_path: cli.data_dir.join(format!("node-{}.state", cli.node)),
        api_timeout: cli.api_timeout.as_secs(),
        debug: cli.log_mode == "debug",
    };

    // Create API manager
    let api_manager = Arc::new(ApiManager::new(panel_config)?);

    // Create user manager
    let user_manager = Arc::new(UserManager::new());

    // Fetch configuration from remote panel (needed for port before registration)
    let node_config = api_manager.fetch_config().await?;
    let remote_config = config::parse_trojan_config(node_config)?;

    // Initialize node with port from config
    api_manager.initialize(remote_config.server_port).await?;
    log::info!("Node initialized");

    // Fetch initial users
    let users = api_manager.fetch_users().await?;
    if let Some(users) = users {
        user_manager.init(&users);
    }

    // Build server config
    let server_config = config::ServerConfig::from_remote(&remote_config, &cli)?;

    // Create authenticator using UserManager
    let authenticator = Arc::new(TrojanAuthenticator(Arc::clone(&user_manager)));

    // Create stats collector
    let stats_collector = Arc::new(PanelStatsCollector::new());

    // Build router from ACL config
    let router = server_runner::build_router(&server_config, cli.refresh_geodata).await?;

    // Build connection config from CLI args
    let conn_config = config::ConnConfig::from_cli(&cli);

    // Clone conn_manager before moving into Server (for graceful shutdown)
    let conn_manager_for_shutdown = conn_manager.clone();

    // Build server using the builder pattern
    let trojan_stats = Arc::new(TrojanStatsCollector(Arc::clone(&stats_collector)));
    let server = Arc::new(
        Server::builder()
            .authenticator(authenticator)
            .stats(trojan_stats as Arc<dyn core::hooks::StatsCollector>)
            .router(router)
            .conn_manager(conn_manager)
            .conn_config(conn_config)
            .build(),
    );

    // Start background tasks with on_user_diff callback for kick
    let task_config = TaskConfig::new(
        cli.fetch_users_interval,
        cli.report_traffics_interval,
        cli.heartbeat_interval,
    );
    let conn_mgr_for_kick = conn_manager_for_shutdown.clone();
    let on_diff = Arc::new(move |diff: panel_core::UserDiff| {
        for uid in diff.removed_ids.iter().chain(diff.uuid_changed_ids.iter()) {
            conn_mgr_for_kick.kick_user(*uid);
        }
    });
    let background_tasks = BackgroundTasks::new(
        task_config,
        Arc::clone(&api_manager),
        Arc::clone(&user_manager),
        Arc::clone(&stats_collector),
    )
    .on_user_diff(on_diff);
    let background_handle = background_tasks.start();

    // Create cancellation token for graceful shutdown
    let cancel_token = CancellationToken::new();
    let cancel_token_clone = cancel_token.clone();

    // Setup shutdown handler
    let api_for_shutdown = Arc::clone(&api_manager);
    let shutdown_handle = tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigint = signal(SignalKind::interrupt()).expect("Failed to setup SIGINT");
            let mut sigterm = signal(SignalKind::terminate()).expect("Failed to setup SIGTERM");

            tokio::select! {
                _ = sigint.recv() => {
                    log::info!("SIGINT received, shutting down...");
                }
                _ = sigterm.recv() => {
                    log::info!("SIGTERM received, shutting down...");
                }
                _ = cancel_token_clone.cancelled() => {}
            }
        }

        #[cfg(not(unix))]
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    log::info!("Shutdown signal received...");
                }
                _ = cancel_token_clone.cancelled() => {}
            }
        }

        cancel_token_clone.cancel();

        // Return the api_manager for shutdown operations
        api_for_shutdown
    });

    // Run server (will run until cancel_token is cancelled or error)
    let server_result = tokio::select! {
        result = server_runner::run_server(server, &server_config) => result,
        _ = cancel_token.cancelled() => Ok(()),
    };

    // Ensure shutdown handler exits if server stopped without a signal
    cancel_token.cancel();

    // Graceful shutdown sequence
    log::info!("Server stopped, performing graceful shutdown...");

    // Cancel all active connections so they send WS Close + TCP FIN to realm,
    // instead of being force-dropped (RST) when the runtime exits.
    // This prevents realm from holding stale connections and reduces thundering
    // herd on restart (realm closes client connections cleanly → clients reconnect
    // more gradually instead of all timing out simultaneously).
    let cancelled = conn_manager_for_shutdown.cancel_all();
    if cancelled > 0 {
        log::info!("Cancelled {cancelled} connections, draining...");
        let drain_deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let remaining = conn_manager_for_shutdown.connection_count();
            if remaining == 0 {
                log::info!("All connections drained");
                break;
            }
            if tokio::time::Instant::now() >= drain_deadline {
                log::warn!("{remaining} connections remaining after drain timeout");
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    // Wait for shutdown handler to complete and get api_manager
    if let Ok(api_for_shutdown) = shutdown_handle.await {
        // Unregister node first — this must complete before supervisor sends SIGKILL.
        // Background tasks shutdown can take up to 15s (3 tasks × 5s timeout each),
        // so unregister before that to stay within supervisor's stopwaitsecs.
        log::info!("Unregistering node...");
        if let Err(e) = api_for_shutdown.unregister().await {
            log::warn!(error = %e, "Failed to unregister node");
        } else {
            log::info!("Node unregistered successfully");
        }

        // Shutdown background tasks last (final traffic report includes drained traffic)
        background_handle.shutdown().await;
    }

    log::info!("Shutdown complete");
    server_result
}
