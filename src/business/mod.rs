//! Business logic — thin wrappers bridging server-panel-rs to core traits

use std::sync::Arc;

use crate::core::hooks::{Authenticator, StatsCollector};
use crate::core::UserId;

// Re-export panel types used by main.rs
pub use server_panel_rs::{
    ApiManager, BackgroundTasks, PanelConfig, StatsCollector as PanelStatsCollector, TaskConfig,
    UserManager,
};

/// Newtype bridging panel::StatsCollector to core::hooks::StatsCollector trait
pub struct TrojanStatsCollector(pub Arc<PanelStatsCollector>);

impl StatsCollector for TrojanStatsCollector {
    fn record_request(&self, user_id: UserId) {
        self.0.record_request(user_id);
    }

    fn record_upload(&self, user_id: UserId, bytes: u64) {
        self.0.record_upload(user_id, bytes);
    }

    fn record_download(&self, user_id: UserId, bytes: u64) {
        self.0.record_download(user_id, bytes);
    }
}

/// Newtype bridging UserManager::authenticate() to core::hooks::Authenticator trait
pub struct TrojanAuthenticator(pub Arc<UserManager>);

impl Authenticator for TrojanAuthenticator {
    fn authenticate(&self, password: &[u8; 56]) -> Option<UserId> {
        self.0.authenticate(password)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use server_panel_rs::{password_to_hex, User};

    // --- TrojanAuthenticator tests ---

    fn create_user(id: i64, uuid: &str) -> User {
        User {
            id,
            uuid: uuid.to_string(),
        }
    }

    fn make_authenticator(entries: &[(&str, i64)]) -> TrojanAuthenticator {
        let um = UserManager::new();
        let users: Vec<User> = entries
            .iter()
            .map(|(uuid, id)| create_user(*id, uuid))
            .collect();
        um.init(&users);
        TrojanAuthenticator(Arc::new(um))
    }

    #[test]
    fn test_authenticate_valid_password() {
        let auth = make_authenticator(&[("uuid-1", 1), ("uuid-2", 2)]);
        let hex = password_to_hex("uuid-1");
        assert_eq!(auth.authenticate(&hex), Some(1));
    }

    #[test]
    fn test_authenticate_invalid_password() {
        let auth = make_authenticator(&[("uuid-1", 1)]);
        let hex = password_to_hex("wrong-uuid");
        assert_eq!(auth.authenticate(&hex), None);
    }

    #[test]
    fn test_authenticate_empty_map() {
        let auth = make_authenticator(&[]);
        let hex = password_to_hex("any-uuid");
        assert_eq!(auth.authenticate(&hex), None);
    }

    #[test]
    fn test_authenticate_hot_reload() {
        let um = Arc::new(UserManager::new());
        um.init(&[create_user(1, "uuid-1")]);
        let auth = TrojanAuthenticator(Arc::clone(&um));

        // Verify initial state
        assert_eq!(auth.authenticate(&password_to_hex("uuid-1")), Some(1));
        assert_eq!(auth.authenticate(&password_to_hex("uuid-2")), None);

        // Simulate hot-reload via UserManager::update
        um.update(&[create_user(2, "uuid-2")]);

        // Old password gone, new password works
        assert_eq!(auth.authenticate(&password_to_hex("uuid-1")), None);
        assert_eq!(auth.authenticate(&password_to_hex("uuid-2")), Some(2));
    }

    // --- TrojanStatsCollector tests ---

    #[test]
    fn test_stats_record_request() {
        let panel = Arc::new(PanelStatsCollector::new());
        let stats = TrojanStatsCollector(Arc::clone(&panel));

        stats.record_request(1);
        stats.record_request(1);
        stats.record_request(2);

        let snap = panel.get_stats(1).unwrap();
        assert_eq!(snap.request_count, 2);
        let snap = panel.get_stats(2).unwrap();
        assert_eq!(snap.request_count, 1);
    }

    #[test]
    fn test_stats_record_upload_download() {
        let panel = Arc::new(PanelStatsCollector::new());
        let stats = TrojanStatsCollector(Arc::clone(&panel));

        stats.record_upload(1, 100);
        stats.record_upload(1, 50);
        stats.record_download(1, 200);

        let snap = panel.get_stats(1).unwrap();
        assert_eq!(snap.upload_bytes, 150);
        assert_eq!(snap.download_bytes, 200);
    }

    #[test]
    fn test_stats_bridge_shares_underlying_collector() {
        let panel = Arc::new(PanelStatsCollector::new());
        let stats = TrojanStatsCollector(Arc::clone(&panel));

        // Write via bridge
        stats.record_upload(1, 100);

        // Read via panel directly — should see the same data
        let snap = panel.get_stats(1).unwrap();
        assert_eq!(snap.upload_bytes, 100);

        // Reset via panel, bridge writes accumulate fresh
        let snapshots = panel.reset_all();
        assert_eq!(snapshots.len(), 1);

        stats.record_download(1, 50);
        let snap = panel.get_stats(1).unwrap();
        assert_eq!(snap.download_bytes, 50);
        assert_eq!(snap.upload_bytes, 0); // was reset
    }
}
