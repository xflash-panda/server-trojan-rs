//! gRPC API client for remote panel communication (Agent version)

use anyhow::{anyhow, Result};
use connectrpc::client::{ClientConfig, Http2Connection, SharedHttp2Connection};
use connectrpc::Protocol;
use serde::{Deserialize, Serialize};
use server_agent_proto_rs::{
    AgentClient, ConfigRequest, HeartbeatRequest, NodeType as GrpcNodeType,
    RegisterRequest as GrpcRegisterRequest, SubmitRequest, UnregisterRequest, UsersRequest,
    VerifyRequest,
};
use server_client_rs::models::{
    parse_raw_config_response, unmarshal_users, NodeType, TrojanConfig,
};
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::RwLock;

use crate::config::{CliArgs, User};
use crate::logger::log;

/// State file name
const STATE_FILE: &str = "state.json";

/// Persistent state for the panel
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PanelState {
    /// Registration ID obtained from API
    register_id: Option<String>,
    /// Node ID from API config
    node_id: Option<u32>,
    /// Server port from API config
    server_port: Option<u16>,
}

/// User traffic data for submission
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserTraffic {
    pub user_id: i64,
    /// Upload bytes
    pub u: u64,
    /// Download bytes
    pub d: u64,
    /// Count/connections
    #[serde(default)]
    pub n: u64,
}

impl UserTraffic {
    /// Create a new UserTraffic instance with connection count
    pub fn with_count(user_id: i64, upload: u64, download: u64, count: u64) -> Self {
        Self {
            user_id,
            u: upload,
            d: download,
            n: count,
        }
    }
}

/// Aggregated traffic statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TrafficStats {
    /// Total count
    pub count: i64,
    /// Total requests
    pub requests: i64,
    /// User IDs
    pub user_ids: Vec<i64>,
    /// Per-user request counts
    #[serde(default)]
    pub user_requests: std::collections::HashMap<i64, i64>,
}

impl TrafficStats {
    /// Create a new empty TrafficStats instance
    pub fn new() -> Self {
        Self {
            count: 0,
            requests: 0,
            user_ids: Vec::new(),
            user_requests: std::collections::HashMap::new(),
        }
    }

    /// Add a user's request count
    pub fn add_user(&mut self, user_id: i64, requests: i64) {
        self.user_ids.push(user_id);
        self.user_requests.insert(user_id, requests);
        self.requests += requests;
        self.count += 1;
    }
}

/// Configuration for the panel service
#[derive(Debug, Clone)]
pub struct PanelConfig {
    /// gRPC server host (e.g., "127.0.0.1")
    pub server_host: String,
    /// gRPC server port (e.g., 8082)
    pub server_port: u16,
    /// Node ID for this server
    pub node_id: u32,
    /// Data directory for persisting state and other data
    pub data_dir: PathBuf,
    /// API request timeout
    pub api_timeout: Duration,
}

impl PanelConfig {
    /// Create PanelConfig from CLI args
    pub fn from_cli(cli: &CliArgs) -> Self {
        Self {
            server_host: cli.server_host.clone(),
            server_port: cli.port,
            node_id: cli.node,
            data_dir: cli.data_dir.clone(),
            api_timeout: cli.api_timeout,
        }
    }
}

fn get_hostname() -> String {
    hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

/// API manager for handling all remote panel operations via gRPC
pub struct ApiManager {
    client: RwLock<Option<AgentClient<SharedHttp2Connection>>>,
    config: PanelConfig,
    register_id: RwLock<Option<String>>,
}

impl ApiManager {
    /// Create a new API manager
    pub fn new(cli: &CliArgs) -> Result<Self> {
        let config = PanelConfig::from_cli(cli);

        Ok(Self {
            client: RwLock::new(None),
            config,
            register_id: RwLock::new(None),
        })
    }

    /// Connect to the gRPC server
    async fn connect(&self) -> Result<AgentClient<SharedHttp2Connection>> {
        let endpoint = format!(
            "http://{}:{}",
            self.config.server_host, self.config.server_port
        );
        let timeout = self.config.api_timeout;
        log::info!(
            endpoint = %endpoint,
            timeout_secs = timeout.as_secs(),
            "Connecting to gRPC server"
        );

        let uri: http::Uri = endpoint
            .parse()
            .map_err(|e| anyhow!("Invalid endpoint URI: {}", e))?;

        let conn = Http2Connection::connect_plaintext(uri.clone())
            .await
            .map_err(|e| anyhow!("Failed to connect to gRPC server {}: {}", endpoint, e))?;

        let shared = conn.shared(1024);

        let config = ClientConfig::new(uri)
            .protocol(Protocol::Grpc)
            .default_timeout(timeout);

        let client = AgentClient::new(shared, config);
        log::info!("Connected to gRPC server");
        Ok(client)
    }

    /// Get or create gRPC client
    async fn get_client(&self) -> Result<AgentClient<SharedHttp2Connection>> {
        let client_guard = self.client.read().await;
        if let Some(client) = client_guard.clone() {
            return Ok(client);
        }
        drop(client_guard);

        let client = self.connect().await?;
        *self.client.write().await = Some(client.clone());
        Ok(client)
    }

    /// Reset cached gRPC client, forcing a fresh connection on next request.
    /// Called when a gRPC request fails to ensure stale connections are discarded.
    pub async fn reset_client(&self) {
        let mut client_guard = self.client.write().await;
        if client_guard.is_some() {
            *client_guard = None;
            log::warn!("gRPC client reset, will reconnect on next request");
        }
    }

    /// Get the state file path
    fn state_file_path(&self) -> PathBuf {
        self.config.data_dir.join(STATE_FILE)
    }

    /// Load state from file
    fn load_state(&self) -> Option<PanelState> {
        let path = self.state_file_path();
        if !path.exists() {
            return None;
        }

        match std::fs::read_to_string(&path) {
            Ok(content) => match serde_json::from_str(&content) {
                Ok(state) => {
                    log::info!(path = %path.display(), "Loaded state from file");
                    Some(state)
                }
                Err(e) => {
                    log::warn!(error = %e, "Failed to parse state file");
                    None
                }
            },
            Err(e) => {
                log::warn!(error = %e, "Failed to read state file");
                None
            }
        }
    }

    /// Save state to file
    fn save_state(&self, state: &PanelState) -> Result<()> {
        let path = self.state_file_path();
        let content = serde_json::to_string_pretty(state)
            .map_err(|e| anyhow!("Failed to serialize state: {}", e))?;

        std::fs::write(&path, content)
            .map_err(|e| anyhow!("Failed to write state file {:?}: {}", path, e))?;

        log::info!(path = %path.display(), "Saved state to file");
        Ok(())
    }

    /// Delete state file
    fn delete_state(&self) {
        let path = self.state_file_path();
        if path.exists() {
            if let Err(e) = std::fs::remove_file(&path) {
                log::warn!(error = %e, path = %path.display(), "Failed to delete state file");
            } else {
                log::info!(path = %path.display(), "Deleted state file");
            }
        }
    }

    /// Get the current register_id
    #[allow(dead_code)]
    pub async fn get_register_id(&self) -> Option<String> {
        self.register_id.read().await.clone()
    }

    /// Verify register_id with gRPC server
    async fn verify_register_id(&self, register_id: &str) -> Result<bool> {
        let client = self.get_client().await?;

        let response = client
            .verify(VerifyRequest {
                node_type: GrpcNodeType::TROJAN.into(),
                register_id: register_id.to_string(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow!("gRPC verify request failed: {}", e))?;

        Ok(response.into_owned().result)
    }

    /// Fetch config from gRPC server
    pub async fn fetch_config(&self) -> Result<TrojanConfig> {
        let client = self.get_client().await?;

        let config_response = client
            .config(ConfigRequest {
                node_id: self.config.node_id as i32,
                node_type: GrpcNodeType::TROJAN.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow!("gRPC config request failed: {}", e))?
            .into_owned();

        if !config_response.result {
            return Err(anyhow!("Server returned failure for config request"));
        }

        let raw_data_str = String::from_utf8_lossy(&config_response.raw_data);
        log::debug!(raw_data = %raw_data_str, "Raw config data from server");

        let node_config = parse_raw_config_response(NodeType::Trojan, &config_response.raw_data)
            .map_err(|e| anyhow!("Failed to parse config: {} - raw_data: {}", e, raw_data_str))?;

        let trojan_config = node_config
            .as_trojan()
            .map_err(|e| anyhow!("Failed to get TrojanConfig: {}", e))?
            .clone();

        log::info!(
            node_id = self.config.node_id,
            port = trojan_config.server_port,
            network = ?trojan_config.network,
            "Configuration fetched"
        );

        Ok(trojan_config)
    }

    /// Register node with gRPC server
    async fn register_node(&self, hostname: String, port: u16) -> Result<String> {
        let client = self.get_client().await?;

        let response = client
            .register(GrpcRegisterRequest {
                node_id: self.config.node_id as i32,
                node_type: GrpcNodeType::TROJAN.into(),
                host_name: hostname,
                port: port.to_string(),
                ip: String::new(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow!("gRPC register request failed: {}", e))?;

        Ok(response.into_owned().register_id)
    }

    /// Initialize node - try to verify existing registration or register new
    ///
    /// Returns (register_id, TrojanConfig)
    pub async fn initialize(&self, port: u16) -> Result<String> {
        log::info!("Panel service initializing...");

        // Ensure data directory exists
        if !self.config.data_dir.exists() {
            log::info!(path = %self.config.data_dir.display(), "Creating data directory");
            std::fs::create_dir_all(&self.config.data_dir).map_err(|e| {
                anyhow!(
                    "Failed to create data directory {:?}: {}",
                    self.config.data_dir,
                    e
                )
            })?;
        }

        // Try to load existing state and verify register_id
        let mut need_register = true;

        if let Some(state) = self.load_state() {
            if let Some(saved_register_id) = &state.register_id {
                log::info!(register_id = %saved_register_id, "Found saved register_id, verifying...");
                match self.verify_register_id(saved_register_id).await {
                    Ok(true) => {
                        log::info!(register_id = %saved_register_id, "Saved register_id is valid");
                        *self.register_id.write().await = Some(saved_register_id.clone());
                        need_register = false;
                    }
                    Ok(false) => {
                        log::warn!("Saved register_id is invalid, will re-register");
                        self.delete_state();
                    }
                    Err(e) => {
                        // Network error - don't delete state, exit and retry on next startup
                        return Err(anyhow!("Failed to verify register_id: {}", e));
                    }
                }
            }
        }

        if need_register {
            // Get hostname and register node
            let hostname = get_hostname();

            log::info!(
                node_id = self.config.node_id,
                hostname = %hostname,
                port = port,
                "Registering node"
            );

            let register_id = self
                .register_node(hostname, port)
                .await
                .map_err(|e| anyhow!("Failed to register node, cannot continue: {}", e))?;

            log::info!(register_id = %register_id, "Node registered successfully");

            // Save register_id for later use
            *self.register_id.write().await = Some(register_id.clone());

            // Persist state to file
            let state = PanelState {
                register_id: Some(register_id.clone()),
                node_id: Some(self.config.node_id),
                server_port: Some(port),
            };
            self.save_state(&state)?;

            return Ok(register_id);
        }

        // Return existing register_id
        let register_id = self.register_id.read().await.clone();
        Ok(register_id.expect("register_id should be set"))
    }

    /// Unregister the node from the panel
    pub async fn unregister(&self) -> Result<()> {
        let register_id = self.register_id.read().await.clone();

        if let Some(id) = register_id {
            log::info!(register_id = %id, "Unregistering node");

            let client = self.get_client().await?;

            let response = client
                .unregister(UnregisterRequest {
                    node_type: GrpcNodeType::TROJAN.into(),
                    register_id: id.clone(),
                    ..Default::default()
                })
                .await
                .map_err(|e| anyhow!("gRPC unregister request failed: {}", e))?;

            if response.into_owned().result {
                log::info!("Node unregistered successfully");
                self.delete_state();
                *self.register_id.write().await = None;
            } else {
                log::warn!("Unregister failed: server returned false");
            }
        }

        Ok(())
    }

    /// Fetch users from gRPC server
    pub async fn fetch_users(&self) -> Result<Vec<User>> {
        let client = self.get_client().await?;

        let users_response = client
            .users(UsersRequest {
                node_type: GrpcNodeType::TROJAN.into(),
                node_id: self.config.node_id as i32,
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow!("gRPC users request failed: {}", e))?
            .into_owned();

        let raw_data_str = String::from_utf8_lossy(&users_response.raw_data);
        log::debug!(raw_data = %raw_data_str, "Raw users data from server");

        let parsed_users = unmarshal_users(&users_response.raw_data).map_err(|e| {
            anyhow!(
                "Failed to parse users response: {} - raw_data: {}",
                e,
                raw_data_str
            )
        })?;

        let users: Vec<User> = parsed_users
            .into_iter()
            .map(|u| User {
                id: u.id,
                uuid: u.uuid,
            })
            .collect();

        log::debug!(count = users.len(), "Users fetched");
        Ok(users)
    }

    /// Submit traffic data to panel
    pub async fn submit_traffic(&self, data: Vec<UserTraffic>) -> Result<()> {
        if data.is_empty() {
            log::debug!("No traffic to submit");
            return Ok(());
        }

        let register_id = self
            .register_id
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("Not registered"))?;

        let count = data.len();

        // Build TrafficStats for raw_stats
        let mut stats = TrafficStats::new();
        for traffic in &data {
            stats.add_user(traffic.user_id, traffic.n as i64);
        }

        let raw_data = serde_json::to_vec(&data)
            .map_err(|e| anyhow!("Failed to serialize traffic data: {}", e))?;
        let raw_stats = serde_json::to_vec(&stats)
            .map_err(|e| anyhow!("Failed to serialize traffic stats: {}", e))?;

        let client = self.get_client().await?;

        let response = client
            .submit(SubmitRequest {
                node_type: GrpcNodeType::TROJAN.into(),
                register_id,
                raw_data,
                raw_stats,
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow!("gRPC submit request failed: {}", e))?;

        if response.into_owned().result {
            log::debug!(count = count, "Traffic submitted successfully");
            Ok(())
        } else {
            Err(anyhow!("Failed to submit traffic: server returned false"))
        }
    }

    /// Send heartbeat to panel
    pub async fn heartbeat(&self) -> Result<()> {
        let register_id = self
            .register_id
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("Not registered"))?;

        let client = self.get_client().await?;

        let response = client
            .heartbeat(HeartbeatRequest {
                node_type: GrpcNodeType::TROJAN.into(),
                register_id,
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow!("gRPC heartbeat request failed: {}", e))?;

        if response.into_owned().result {
            log::debug!("Heartbeat sent successfully");
            Ok(())
        } else {
            Err(anyhow!("Heartbeat failed: server returned false"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_traffic_with_count() {
        let traffic = UserTraffic::with_count(1, 100, 200, 5);
        assert_eq!(traffic.user_id, 1);
        assert_eq!(traffic.u, 100);
        assert_eq!(traffic.d, 200);
        assert_eq!(traffic.n, 5);
    }

    #[test]
    fn test_traffic_stats_add_user() {
        let mut stats = TrafficStats::new();
        stats.add_user(1, 10);
        stats.add_user(2, 20);

        assert_eq!(stats.count, 2);
        assert_eq!(stats.requests, 30);
        assert_eq!(stats.user_ids, vec![1, 2]);
        assert_eq!(stats.user_requests.get(&1), Some(&10));
        assert_eq!(stats.user_requests.get(&2), Some(&20));
    }

    #[test]
    fn test_panel_state_serialization() {
        let state = PanelState {
            register_id: Some("test-id".to_string()),
            node_id: Some(1),
            server_port: Some(443),
        };

        let json = serde_json::to_string(&state).unwrap();
        let parsed: PanelState = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.register_id, Some("test-id".to_string()));
        assert_eq!(parsed.node_id, Some(1));
        assert_eq!(parsed.server_port, Some(443));
    }
}
