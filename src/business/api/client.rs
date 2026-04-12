//! API client for remote panel communication

use anyhow::{anyhow, Result};
use server_client_rs::{
    ApiClient, ApiError, Config as ApiConfig, NodeType, RegisterRequest, TrojanConfig, UserTraffic,
};
use std::path::PathBuf;
use tokio::sync::RwLock;

use crate::config::{CliArgs, User};
use crate::logger::log;

/// State file content for persistence
#[derive(Debug, Clone)]
struct PersistentState {
    register_id: String,
    node_id: i64,
}

impl PersistentState {
    fn serialize(&self) -> String {
        format!("{}:{}", self.node_id, self.register_id)
    }

    fn deserialize(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.splitn(2, ':').collect();
        if parts.len() == 2 {
            let node_id = parts[0].parse().ok()?;
            let register_id = parts[1].to_string();
            Some(Self {
                register_id,
                node_id,
            })
        } else {
            None
        }
    }
}

/// API manager for handling all remote panel operations
pub struct ApiManager {
    client: ApiClient,
    node_id: i64,
    register_id: RwLock<Option<String>>,
    state_file_path: PathBuf,
}

impl ApiManager {
    /// Create a new API manager
    pub fn new(cli: &CliArgs) -> Result<Self> {
        let config = ApiConfig::new(&cli.api, &cli.token)
            .with_timeout(cli.api_timeout)
            .with_debug(cli.log_mode == "debug");

        let client = ApiClient::new(config)?;

        Ok(Self {
            client,
            node_id: cli.node,
            register_id: RwLock::new(None),
            state_file_path: cli.get_state_file_path(),
        })
    }

    /// Load persisted state from disk
    fn load_state(&self) -> Option<PersistentState> {
        if self.state_file_path.exists() {
            match std::fs::read_to_string(&self.state_file_path) {
                Ok(content) => {
                    let state = PersistentState::deserialize(content.trim())?;
                    if state.node_id == self.node_id {
                        return Some(state);
                    }
                }
                Err(e) => {
                    log::warn!(error = %e, "Failed to read state file");
                }
            }
        }
        None
    }

    /// Save state to disk
    fn save_state(&self, register_id: &str) -> Result<()> {
        let state = PersistentState {
            register_id: register_id.to_string(),
            node_id: self.node_id,
        };

        if let Some(parent) = self.state_file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(&self.state_file_path, state.serialize())?;
        log::debug!(path = %self.state_file_path.display(), "State saved");
        Ok(())
    }

    /// Clear persisted state
    fn clear_state(&self) {
        if self.state_file_path.exists() {
            if let Err(e) = std::fs::remove_file(&self.state_file_path) {
                log::warn!(error = %e, "Failed to remove state file");
            }
        }
    }

    /// Get the current register_id
    #[allow(dead_code)]
    pub async fn get_register_id(&self) -> Option<String> {
        self.register_id.read().await.clone()
    }

    /// Fetch node configuration from remote panel
    pub async fn fetch_config(&self) -> Result<TrojanConfig> {
        log::info!(node_id = self.node_id, "Fetching node configuration");

        let config_enum = self.client.config(NodeType::Trojan, self.node_id).await?;
        let config = config_enum.as_trojan()?;

        log::info!(
            node_id = self.node_id,
            port = config.server_port,
            network = ?config.network,
            "Configuration fetched"
        );

        Ok(config.clone())
    }

    /// Initialize node - try to verify existing registration or register new
    ///
    /// `port` is the server port from remote config, used for registration
    pub async fn initialize(&self, port: u16) -> Result<String> {
        if let Some(state) = self.load_state() {
            log::info!(
                register_id = %state.register_id,
                "Found existing registration, verifying"
            );

            match self
                .client
                .verify(NodeType::Trojan, &state.register_id)
                .await
            {
                Ok(true) => {
                    log::info!(register_id = %state.register_id, "Registration verified");
                    *self.register_id.write().await = Some(state.register_id.clone());
                    return Ok(state.register_id);
                }
                Ok(false) => {
                    log::warn!("Existing registration is invalid, re-registering");
                    self.clear_state();
                }
                Err(e) => {
                    log::warn!(error = %e, "Failed to verify registration, re-registering");
                    self.clear_state();
                }
            }
        }

        self.register(port).await
    }

    /// Register the node with the panel
    async fn register(&self, port: u16) -> Result<String> {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        log::info!(
            node_id = self.node_id,
            hostname = %hostname,
            port = port,
            "Registering node"
        );

        let request = RegisterRequest::new(hostname, port);

        let register_id = self
            .client
            .register(NodeType::Trojan, self.node_id, request)
            .await?;

        log::info!(register_id = %register_id, "Node registered successfully");

        if let Err(e) = self.save_state(&register_id) {
            log::warn!(error = %e, "Failed to save state");
        }

        *self.register_id.write().await = Some(register_id.clone());
        Ok(register_id)
    }

    /// Unregister the node from the panel
    pub async fn unregister(&self) -> Result<()> {
        let register_id = self.register_id.read().await.clone();

        if let Some(id) = register_id {
            log::info!(register_id = %id, "Unregistering node");

            if let Err(e) = self.client.unregister(NodeType::Trojan, &id).await {
                log::warn!(error = %e, "Failed to unregister node");
            }

            self.clear_state();
            *self.register_id.write().await = None;
        }

        Ok(())
    }

    /// Fetch users from remote panel
    pub async fn fetch_users(&self) -> Result<Vec<User>> {
        let register_id = self
            .register_id
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("Not registered"))?;

        match self.client.users(NodeType::Trojan, &register_id).await {
            Ok(users) => {
                log::debug!(count = users.len(), "Users fetched");
                Ok(users.into_iter().map(User::from).collect())
            }
            Err(ApiError::NotModified { .. }) => {
                log::debug!("Users not modified (ETag match)");
                Err(anyhow!("Not modified"))
            }
            Err(e) => {
                log::error!(error = %e, "Failed to fetch users");
                Err(e.into())
            }
        }
    }

    /// Submit traffic data to panel
    pub async fn submit_traffic(&self, data: Vec<UserTraffic>) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }

        let register_id = self
            .register_id
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("Not registered"))?;

        log::debug!(count = data.len(), "Submitting traffic data");

        self.client
            .submit(NodeType::Trojan, &register_id, data)
            .await?;

        log::debug!("Traffic data submitted");
        Ok(())
    }

    /// Send heartbeat to panel
    pub async fn heartbeat(&self) -> Result<()> {
        let register_id = self
            .register_id
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow!("Not registered"))?;

        self.client
            .heartbeat(NodeType::Trojan, &register_id)
            .await?;

        log::debug!("Heartbeat sent");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistent_state_serialization() {
        let state = PersistentState {
            register_id: "abc-123".to_string(),
            node_id: 42,
        };

        let s = state.serialize();
        assert_eq!(s, "42:abc-123");

        let parsed = PersistentState::deserialize(&s).unwrap();
        assert_eq!(parsed.node_id, 42);
        assert_eq!(parsed.register_id, "abc-123");
    }

    #[test]
    fn test_persistent_state_with_colon_in_id() {
        let state = PersistentState {
            register_id: "abc:123:xyz".to_string(),
            node_id: 1,
        };

        let s = state.serialize();
        let parsed = PersistentState::deserialize(&s).unwrap();
        assert_eq!(parsed.register_id, "abc:123:xyz");
    }

    #[test]
    fn test_persistent_state_deserialize_invalid() {
        assert!(PersistentState::deserialize("invalid").is_none());
        assert!(PersistentState::deserialize("").is_none());
        assert!(PersistentState::deserialize("notanumber:id").is_none());
    }
}
