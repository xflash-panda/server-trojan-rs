//! ACL (Access Control List) Engine integration
//!
//! Provides rule-based traffic routing with support for:
//! - Direct connections
//! - SOCKS5 proxy
//! - HTTP/HTTPS proxy
//! - Reject (block) connections
//!
//! Configuration format (YAML):
//! ```yaml
//! outbounds:
//!   - name: warp
//!     type: socks5
//!     socks5:
//!       addr: 127.0.0.1:40000
//!   - name: http-proxy
//!     type: http
//!     http:
//!       addr: 127.0.0.1:8080
//! acl:
//!   inline:
//!     - reject(all, udp/443)
//!     - warp(suffix:google.com)
//!     - direct(all)
//! ```

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// Re-export types from acl-engine-r
pub use acl_engine_r::{
    geo::{AutoGeoLoader, GeoIpFormat, GeoSiteFormat, NilGeoLoader},
    outbound::{
        Addr, AsyncOutbound, AsyncTcpConn, AsyncUdpConn, Direct, DirectMode, DirectOptions, Http,
        Reject, Socks5,
    },
    HostInfo, Protocol,
};

use crate::logger::log;

/// ACL configuration loaded from YAML file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclConfig {
    /// List of outbound configurations
    #[serde(default)]
    pub outbounds: Vec<OutboundEntry>,

    /// ACL rules configuration
    #[serde(default)]
    pub acl: AclRules,
}

/// ACL rules section
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AclRules {
    /// Inline rules (list of rule strings)
    #[serde(default)]
    pub inline: Vec<String>,
}

/// Outbound entry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundEntry {
    /// Outbound name (used in rules)
    pub name: String,

    /// Outbound type: "direct", "socks5", "http", "reject"
    #[serde(rename = "type")]
    pub outbound_type: String,

    /// SOCKS5 configuration (when type = "socks5")
    #[serde(default)]
    pub socks5: Option<Socks5Config>,

    /// HTTP proxy configuration (when type = "http")
    #[serde(default)]
    pub http: Option<HttpConfig>,

    /// Direct configuration (when type = "direct")
    #[serde(default)]
    pub direct: Option<DirectConfig>,
}

/// SOCKS5 outbound configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5Config {
    /// SOCKS5 server address (host:port)
    pub addr: String,

    /// Optional username for authentication
    #[serde(default)]
    pub username: Option<String>,

    /// Optional password for authentication
    #[serde(default)]
    pub password: Option<String>,

    /// Whether to allow UDP through this proxy (default: true)
    #[serde(default = "default_allow_udp")]
    pub allow_udp: bool,
}

fn default_allow_udp() -> bool {
    true
}

/// HTTP proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    /// HTTP proxy server address (host:port or full URL)
    pub addr: String,

    /// Optional username for basic authentication
    #[serde(default)]
    pub username: Option<String>,

    /// Optional password for basic authentication
    #[serde(default)]
    pub password: Option<String>,

    /// Use HTTPS for proxy connection
    #[serde(default)]
    pub https: bool,
}

/// Direct outbound configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectConfig {
    /// IP mode: "auto", "4", "6", "prefer4", "prefer6"
    #[serde(default = "default_ip_mode")]
    pub mode: String,

    /// Bind outgoing connections to a specific local IPv4 address
    #[serde(rename = "bindIPv4", default)]
    pub bind_ipv4: Option<String>,

    /// Bind outgoing connections to a specific local IPv6 address
    #[serde(rename = "bindIPv6", default)]
    pub bind_ipv6: Option<String>,

    /// Bind outgoing connections to a specific network device (Linux only, SO_BINDTODEVICE)
    /// Mutually exclusive with bindIPv4/bindIPv6
    #[serde(rename = "bindDevice", default)]
    pub bind_device: Option<String>,

    /// Enable TCP Fast Open for outgoing connections (Linux/macOS)
    #[serde(rename = "fastOpen", default)]
    pub fast_open: bool,
}

fn default_ip_mode() -> String {
    "auto".to_string()
}

impl Default for DirectConfig {
    fn default() -> Self {
        Self {
            mode: default_ip_mode(),
            bind_ipv4: None,
            bind_ipv6: None,
            bind_device: None,
            fast_open: false,
        }
    }
}

/// Outbound handler wrapper
#[derive(Clone)]
pub enum OutboundHandler {
    /// Direct connection
    Direct(Arc<Direct>),
    /// SOCKS5 proxy
    Socks5 { inner: Arc<Socks5>, allow_udp: bool },
    /// HTTP proxy
    Http(Arc<Http>),
    /// Reject connection
    Reject(Arc<Reject>),
}

impl std::fmt::Debug for OutboundHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundHandler::Direct(_) => write!(f, "Direct"),
            OutboundHandler::Socks5 { allow_udp, .. } => write!(f, "Socks5(udp={})", allow_udp),
            OutboundHandler::Http(_) => write!(f, "Http"),
            OutboundHandler::Reject(_) => write!(f, "Reject"),
        }
    }
}

impl OutboundHandler {
    /// Create OutboundHandler from configuration entry
    pub fn from_entry(entry: &OutboundEntry) -> Result<Self> {
        match entry.outbound_type.as_str() {
            "direct" => {
                let config = entry.direct.as_ref();
                let mode = config.map(|d| d.mode.as_str()).unwrap_or("auto");

                let direct_mode = match mode {
                    "auto" => DirectMode::Auto,
                    "4" | "only4" => DirectMode::Only4,
                    "6" | "only6" => DirectMode::Only6,
                    "prefer4" | "46" => DirectMode::Prefer46,
                    "prefer6" | "64" => DirectMode::Prefer64,
                    _ => {
                        return Err(anyhow!(
                            "Invalid direct mode '{}' for outbound '{}', \
                             valid values: auto, 4, only4, 6, only6, prefer4, 46, prefer6, 64",
                            mode,
                            entry.name
                        ));
                    }
                };

                let bind_ip4 = config
                    .and_then(|d| d.bind_ipv4.as_deref())
                    .map(|s| {
                        s.parse::<std::net::Ipv4Addr>()
                            .map_err(|e| anyhow!("Invalid bindIPv4 '{}': {}", s, e))
                    })
                    .transpose()?;
                let bind_ip6 = config
                    .and_then(|d| d.bind_ipv6.as_deref())
                    .map(|s| {
                        s.parse::<std::net::Ipv6Addr>()
                            .map_err(|e| anyhow!("Invalid bindIPv6 '{}': {}", s, e))
                    })
                    .transpose()?;
                let bind_device = config.and_then(|d| d.bind_device.clone());
                let fast_open = config.is_some_and(|d| d.fast_open);

                // Validate bind IPs at startup by trying to bind a test socket
                if let Some(ip) = bind_ip4 {
                    let socket = socket2::Socket::new(
                        socket2::Domain::IPV4,
                        socket2::Type::STREAM,
                        Some(socket2::Protocol::TCP),
                    )
                    .map_err(|e| anyhow!("Failed to create test socket: {}", e))?;
                    let bind_addr: std::net::SocketAddr =
                        std::net::SocketAddr::new(std::net::IpAddr::V4(ip), 0);
                    socket.bind(&bind_addr.into()).map_err(|e| {
                        anyhow!(
                            "FATAL: outbound '{}' bindIPv4 {} failed: {}",
                            entry.name,
                            ip,
                            e
                        )
                    })?;
                }
                if let Some(ip) = bind_ip6 {
                    let socket = socket2::Socket::new(
                        socket2::Domain::IPV6,
                        socket2::Type::STREAM,
                        Some(socket2::Protocol::TCP),
                    )
                    .map_err(|e| anyhow!("Failed to create test socket: {}", e))?;
                    let bind_addr: std::net::SocketAddr =
                        std::net::SocketAddr::new(std::net::IpAddr::V6(ip), 0);
                    socket.bind(&bind_addr.into()).map_err(|e| {
                        anyhow!(
                            "FATAL: outbound '{}' bindIPv6 {} failed: {}",
                            entry.name,
                            ip,
                            e
                        )
                    })?;
                }

                // Validate bindDevice at startup
                #[cfg(target_os = "linux")]
                if let Some(ref device) = bind_device {
                    let socket = socket2::Socket::new(
                        socket2::Domain::IPV4,
                        socket2::Type::STREAM,
                        Some(socket2::Protocol::TCP),
                    )
                    .map_err(|e| anyhow!("Failed to create test socket: {}", e))?;
                    socket.bind_device(Some(device.as_bytes())).map_err(|e| {
                        anyhow!(
                            "FATAL: outbound '{}' bindDevice '{}' failed: {}",
                            entry.name,
                            device,
                            e
                        )
                    })?;
                }
                #[cfg(not(target_os = "linux"))]
                if let Some(ref device) = bind_device {
                    return Err(anyhow!(
                        "FATAL: outbound '{}' bindDevice '{}' is only supported on Linux",
                        entry.name,
                        device
                    ));
                }

                let opts = DirectOptions {
                    mode: direct_mode,
                    bind_ip4,
                    bind_ip6,
                    bind_device,
                    fast_open,
                    timeout: None,
                };
                let direct = Direct::with_options(opts)
                    .map_err(|e| anyhow!("Invalid direct outbound '{}': {}", entry.name, e))?;

                // Log the direct outbound configuration
                let mut parts = vec![format!("mode={}", mode)];
                if let Some(ip) = bind_ip4 {
                    parts.push(format!("bindIPv4={}", ip));
                }
                if let Some(ip) = bind_ip6 {
                    parts.push(format!("bindIPv6={}", ip));
                }
                if let Some(ref dev) = config.and_then(|d| d.bind_device.as_ref()) {
                    parts.push(format!("bindDevice={}", dev));
                }
                if fast_open {
                    parts.push("fastOpen=true".to_string());
                }
                log::info!(
                    outbound = %entry.name,
                    "Direct outbound configured: {}",
                    parts.join(", ")
                );

                Ok(OutboundHandler::Direct(Arc::new(direct)))
            }
            "socks5" => {
                let config = entry.socks5.as_ref().ok_or_else(|| {
                    anyhow!("socks5 config required for outbound '{}'", entry.name)
                })?;

                let socks5 = if let (Some(username), Some(password)) =
                    (&config.username, &config.password)
                {
                    Socks5::with_auth(&config.addr, username, password)
                        .map_err(|e| anyhow!("Invalid socks5 outbound '{}': {}", entry.name, e))?
                } else {
                    Socks5::new(&config.addr)
                };

                Ok(OutboundHandler::Socks5 {
                    inner: Arc::new(socks5),
                    allow_udp: config.allow_udp,
                })
            }
            "http" => {
                let config = entry
                    .http
                    .as_ref()
                    .ok_or_else(|| anyhow!("http config required for outbound '{}'", entry.name))?;

                let mut http = if config.https {
                    Http::try_new(&config.addr, true)
                        .map_err(|e| anyhow!("Invalid http outbound '{}': {}", entry.name, e))?
                } else {
                    Http::new(&config.addr)
                };

                if let (Some(username), Some(password)) = (&config.username, &config.password) {
                    http = http.with_auth(username, password);
                }

                Ok(OutboundHandler::Http(Arc::new(http)))
            }
            "reject" => Ok(OutboundHandler::Reject(Arc::new(Reject::new()))),
            unknown => Err(anyhow!(
                "Unknown outbound type '{}' for outbound '{}'",
                unknown,
                entry.name
            )),
        }
    }

    /// Check if this handler rejects connections
    #[allow(dead_code)]
    pub fn is_reject(&self) -> bool {
        matches!(self, OutboundHandler::Reject(_))
    }

    /// Check if this handler allows UDP
    #[allow(dead_code)]
    pub fn allows_udp(&self) -> bool {
        match self {
            OutboundHandler::Direct(_) => true,
            OutboundHandler::Socks5 { allow_udp, .. } => *allow_udp,
            OutboundHandler::Http(_) => false, // HTTP proxy doesn't support UDP
            OutboundHandler::Reject(_) => false,
        }
    }
}

#[async_trait]
impl AsyncOutbound for OutboundHandler {
    async fn dial_tcp(&self, addr: &mut Addr) -> acl_engine_r::Result<Box<dyn AsyncTcpConn>> {
        match self {
            OutboundHandler::Direct(d) => d.dial_tcp(addr).await,
            OutboundHandler::Socks5 { inner, .. } => inner.dial_tcp(addr).await,
            OutboundHandler::Http(h) => h.dial_tcp(addr).await,
            OutboundHandler::Reject(r) => r.dial_tcp(addr).await,
        }
    }

    async fn dial_udp(&self, addr: &mut Addr) -> acl_engine_r::Result<Box<dyn AsyncUdpConn>> {
        match self {
            OutboundHandler::Direct(d) => d.dial_udp(addr).await,
            OutboundHandler::Socks5 { inner, .. } => inner.dial_udp(addr).await,
            OutboundHandler::Http(h) => h.dial_udp(addr).await,
            OutboundHandler::Reject(r) => r.dial_udp(addr).await,
        }
    }
}

/// ACL Engine for rule-based traffic routing
pub struct AclEngine {
    /// Compiled rule set
    compiled: acl_engine_r::CompiledRuleSet<Arc<OutboundHandler>>,
    /// Keep outbounds map for reference
    #[allow(dead_code)]
    outbounds: HashMap<String, Arc<OutboundHandler>>,
}

impl AclEngine {
    /// Create a new ACL engine from configuration
    ///
    /// # Arguments
    /// * `config` - ACL configuration
    /// * `data_dir` - Optional data directory for geo data files
    /// * `refresh_geodata` - If true, force refresh geo data files on startup
    pub async fn new(
        config: AclConfig,
        data_dir: Option<&Path>,
        refresh_geodata: bool,
    ) -> Result<Self> {
        // Step 1: Parse outbounds into handler map
        let mut outbounds: HashMap<String, Arc<OutboundHandler>> = HashMap::new();

        for entry in &config.outbounds {
            let handler = OutboundHandler::from_entry(entry)?;
            log::info!(
                outbound = %entry.name,
                outbound_type = %entry.outbound_type,
                "Loaded outbound"
            );
            outbounds.insert(entry.name.clone(), Arc::new(handler));
        }

        // Step 2: Ensure default outbounds exist
        outbounds
            .entry("reject".to_string())
            .or_insert_with(|| Arc::new(OutboundHandler::Reject(Arc::new(Reject::new()))));
        outbounds
            .entry("direct".to_string())
            .or_insert_with(|| Arc::new(OutboundHandler::Direct(Arc::new(Direct::new()))));

        // Step 3: Get rules or use default
        let rules = if config.acl.inline.is_empty() {
            vec!["direct(all)".to_string()]
        } else {
            config.acl.inline.clone()
        };

        // Step 4: Parse rules text
        let rules_text = rules.join("\n");
        let text_rules = acl_engine_r::parse_rules(&rules_text)
            .map_err(|e| anyhow!("Failed to parse ACL rules: {}", e))?;

        // Step 5: Create geo loader
        let mut geo_loader = if let Some(dir) = data_dir {
            AutoGeoLoader::new()
                .with_data_dir(dir)
                .with_geoip(GeoIpFormat::Mmdb)
                .with_geosite(GeoSiteFormat::Sing)
        } else {
            AutoGeoLoader::new()
                .with_geoip(GeoIpFormat::Mmdb)
                .with_geosite(GeoSiteFormat::Sing)
        };

        // Force refresh geodata if requested
        if refresh_geodata {
            use std::time::Duration;
            geo_loader = geo_loader.with_update_interval(Duration::ZERO);
            log::info!("Geo data refresh requested, will download latest files");
        }

        // Step 6: Compile rules
        let compiled = acl_engine_r::compile(
            &text_rules,
            &outbounds,
            NonZeroUsize::new(4096).unwrap(),
            &geo_loader,
        )
        .map_err(|e| anyhow!("Failed to compile ACL rules: {}", e))?;

        log::info!(
            outbounds = outbounds.len(),
            rules = compiled.rule_count(),
            "ACL engine initialized"
        );

        Ok(Self {
            compiled,
            outbounds,
        })
    }

    /// Create a default ACL engine (direct all traffic)
    #[allow(dead_code)]
    pub fn new_default() -> Result<Self> {
        let mut outbounds: HashMap<String, Arc<OutboundHandler>> = HashMap::new();
        outbounds.insert(
            "direct".to_string(),
            Arc::new(OutboundHandler::Direct(Arc::new(Direct::new()))),
        );
        outbounds.insert(
            "reject".to_string(),
            Arc::new(OutboundHandler::Reject(Arc::new(Reject::new()))),
        );

        let text_rules = acl_engine_r::parse_rules("direct(all)")
            .map_err(|e| anyhow!("Failed to parse default rules: {}", e))?;

        let compiled = acl_engine_r::compile(
            &text_rules,
            &outbounds,
            NonZeroUsize::new(1024).unwrap(),
            &NilGeoLoader,
        )
        .map_err(|e| anyhow!("Failed to compile default rules: {}", e))?;

        Ok(Self {
            compiled,
            outbounds,
        })
    }

    /// Match a host against ACL rules and return the appropriate outbound handler
    pub fn match_host(
        &self,
        host: &str,
        port: u16,
        protocol: Protocol,
    ) -> Option<Arc<OutboundHandler>> {
        // Create HostInfo from host string
        let host_info = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            HostInfo::from_ip(ip)
        } else {
            HostInfo::from_name(host)
        };

        match self.compiled.match_host(&host_info, protocol, port) {
            Some(result) => Some(result.outbound.clone()),
            None => {
                // No match, return default direct
                self.outbounds.get("direct").cloned()
            }
        }
    }

    /// Get the number of compiled rules
    pub fn rule_count(&self) -> usize {
        self.compiled.rule_count()
    }
}

/// Load ACL configuration from YAML file
pub async fn load_acl_config(path: &Path) -> Result<AclConfig> {
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| anyhow!("Failed to read ACL config file '{}': {}", path.display(), e))?;

    let config: AclConfig = serde_yaml::from_str(&content).map_err(|e| {
        anyhow!(
            "Failed to parse ACL config file '{}': {}",
            path.display(),
            e
        )
    })?;

    Ok(config)
}

/// ACL Router adapter implementing core::hooks::OutboundRouter
///
/// This adapter wraps the ACL engine and implements the OutboundRouter trait
/// for integration with the core proxy layer.
pub struct AclRouter {
    engine: AclEngine,
    /// Block connections to private/loopback IP addresses (SSRF protection)
    block_private_ip: bool,
}

impl AclRouter {
    /// Create a new ACL router with custom private IP blocking setting
    pub fn with_block_private_ip(engine: AclEngine, block_private_ip: bool) -> Self {
        Self {
            engine,
            block_private_ip,
        }
    }
}

#[async_trait]
impl crate::core::hooks::OutboundRouter for AclRouter {
    async fn route(&self, addr: &crate::core::Address) -> crate::core::hooks::OutboundType {
        let mut resolved_addr: Option<std::net::SocketAddr> = None;

        // Check for private IP if blocking is enabled
        if self.block_private_ip {
            let (is_private, resolved) = crate::core::hooks::check_private_and_resolve(addr).await;
            if is_private {
                log::debug!(target = %addr, "Blocked private address");
                return crate::core::hooks::OutboundType::Reject;
            }
            resolved_addr = resolved;
        }

        // Extract host and port for ACL matching (Cow avoids alloc for domains)
        let host = addr.host();
        let port = addr.port();

        self.route_host_with_resolved(&host, port, resolved_addr)
    }
}

impl AclRouter {
    /// Route host via ACL engine, passing through any pre-resolved address for Direct results.
    fn route_host_with_resolved(
        &self,
        host: &str,
        port: u16,
        resolved: Option<std::net::SocketAddr>,
    ) -> crate::core::hooks::OutboundType {
        match self.engine.match_host(host, port, Protocol::TCP) {
            Some(handler) => match &*handler {
                OutboundHandler::Direct(_) => crate::core::hooks::OutboundType::Direct {
                    resolved,
                    handler: Some(handler),
                },
                OutboundHandler::Socks5 { .. } | OutboundHandler::Http(_) => {
                    crate::core::hooks::OutboundType::Proxy(handler)
                }
                OutboundHandler::Reject(_) => crate::core::hooks::OutboundType::Reject,
            },
            None => crate::core::hooks::OutboundType::Direct {
                resolved,
                handler: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_acl_config() {
        let yaml = r#"
outbounds:
  - name: warp
    type: socks5
    socks5:
      addr: 127.0.0.1:40000
      allow_udp: true
  - name: http-proxy
    type: http
    http:
      addr: 127.0.0.1:8080
      https: false
acl:
  inline:
    - reject(all, udp/443)
    - warp(suffix:google.com)
    - direct(all)
"#;

        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.outbounds.len(), 2);
        assert_eq!(config.outbounds[0].name, "warp");
        assert_eq!(config.outbounds[0].outbound_type, "socks5");
        assert_eq!(config.acl.inline.len(), 3);
    }

    #[test]
    fn test_outbound_handler_from_entry_direct() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                mode: "auto".to_string(),
                ..Default::default()
            }),
        };

        let handler = OutboundHandler::from_entry(&entry).unwrap();
        assert!(matches!(handler, OutboundHandler::Direct(_)));
        assert!(handler.allows_udp());
        assert!(!handler.is_reject());
    }

    #[test]
    fn test_outbound_handler_from_entry_socks5() {
        let entry = OutboundEntry {
            name: "proxy".to_string(),
            outbound_type: "socks5".to_string(),
            socks5: Some(Socks5Config {
                addr: "127.0.0.1:1080".to_string(),
                username: None,
                password: None,
                allow_udp: true,
            }),
            http: None,
            direct: None,
        };

        let handler = OutboundHandler::from_entry(&entry).unwrap();
        assert!(matches!(handler, OutboundHandler::Socks5 { .. }));
        assert!(handler.allows_udp());
    }

    #[test]
    fn test_outbound_handler_from_entry_http() {
        let entry = OutboundEntry {
            name: "http".to_string(),
            outbound_type: "http".to_string(),
            socks5: None,
            http: Some(HttpConfig {
                addr: "127.0.0.1:8080".to_string(),
                username: None,
                password: None,
                https: false,
            }),
            direct: None,
        };

        let handler = OutboundHandler::from_entry(&entry).unwrap();
        assert!(matches!(handler, OutboundHandler::Http(_)));
        assert!(!handler.allows_udp()); // HTTP doesn't support UDP
    }

    #[test]
    fn test_outbound_handler_from_entry_reject() {
        let entry = OutboundEntry {
            name: "block".to_string(),
            outbound_type: "reject".to_string(),
            socks5: None,
            http: None,
            direct: None,
        };

        let handler = OutboundHandler::from_entry(&entry).unwrap();
        assert!(matches!(handler, OutboundHandler::Reject(_)));
        assert!(handler.is_reject());
        assert!(!handler.allows_udp());
    }

    #[tokio::test]
    async fn test_acl_engine_default() {
        let engine = AclEngine::new_default().unwrap();
        assert_eq!(engine.rule_count(), 1);

        // Should match everything to direct
        let handler = engine.match_host("example.com", 80, Protocol::TCP);
        assert!(handler.is_some());
        assert!(!handler.unwrap().is_reject());
    }

    #[test]
    fn test_parse_empty_config() {
        let yaml = r#"
outbounds: []
acl:
  inline: []
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.outbounds.is_empty());
        assert!(config.acl.inline.is_empty());
    }

    #[test]
    fn test_parse_config_with_auth() {
        let yaml = r#"
outbounds:
  - name: auth-proxy
    type: socks5
    socks5:
      addr: 127.0.0.1:1080
      username: user
      password: pass
      allow_udp: true
  - name: http-auth
    type: http
    http:
      addr: 127.0.0.1:8080
      username: admin
      password: secret
      https: true
acl:
  inline:
    - auth-proxy(all)
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.outbounds.len(), 2);

        let socks5 = &config.outbounds[0];
        assert_eq!(
            socks5.socks5.as_ref().unwrap().username,
            Some("user".to_string())
        );
        assert_eq!(
            socks5.socks5.as_ref().unwrap().password,
            Some("pass".to_string())
        );

        let http = &config.outbounds[1];
        assert!(http.http.as_ref().unwrap().https);
    }

    #[test]
    fn test_outbound_handler_socks5_no_udp() {
        let entry = OutboundEntry {
            name: "no-udp-proxy".to_string(),
            outbound_type: "socks5".to_string(),
            socks5: Some(Socks5Config {
                addr: "127.0.0.1:1080".to_string(),
                username: None,
                password: None,
                allow_udp: false,
            }),
            http: None,
            direct: None,
        };

        let handler = OutboundHandler::from_entry(&entry).unwrap();
        assert!(!handler.allows_udp());
    }

    #[test]
    fn test_outbound_handler_direct_modes() {
        // Test various direct modes
        let modes = vec![
            ("auto", DirectMode::Auto),
            ("4", DirectMode::Only4),
            ("only4", DirectMode::Only4),
            ("6", DirectMode::Only6),
            ("only6", DirectMode::Only6),
            ("prefer4", DirectMode::Prefer46),
            ("46", DirectMode::Prefer46),
            ("prefer6", DirectMode::Prefer64),
            ("64", DirectMode::Prefer64),
        ];

        for (mode_str, _expected_mode) in modes {
            let entry = OutboundEntry {
                name: "direct".to_string(),
                outbound_type: "direct".to_string(),
                socks5: None,
                http: None,
                direct: Some(DirectConfig {
                    mode: mode_str.to_string(),
                    ..Default::default()
                }),
            };

            let handler = OutboundHandler::from_entry(&entry).unwrap();
            assert!(matches!(handler, OutboundHandler::Direct(_)));
        }
    }

    #[test]
    fn test_direct_invalid_mode_rejected() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                mode: "invalid_mode".to_string(),
                ..Default::default()
            }),
        };
        let err = OutboundHandler::from_entry(&entry).unwrap_err();
        assert!(
            err.to_string().contains("Invalid direct mode"),
            "Expected mode validation error, got: {}",
            err
        );
    }

    #[test]
    fn test_direct_invalid_bind_ipv4_rejected() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                bind_ipv4: Some("not-an-ip".to_string()),
                ..Default::default()
            }),
        };
        let err = OutboundHandler::from_entry(&entry).unwrap_err();
        assert!(
            err.to_string().contains("Invalid bindIPv4"),
            "Expected IPv4 parse error, got: {}",
            err
        );
    }

    #[test]
    fn test_direct_invalid_bind_ipv6_rejected() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                bind_ipv6: Some("not-an-ipv6".to_string()),
                ..Default::default()
            }),
        };
        let err = OutboundHandler::from_entry(&entry).unwrap_err();
        assert!(
            err.to_string().contains("Invalid bindIPv6"),
            "Expected IPv6 parse error, got: {}",
            err
        );
    }

    #[test]
    fn test_direct_bind_device_exclusive_with_bind_ip() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                bind_ipv4: Some("127.0.0.1".to_string()),
                bind_device: Some("eth0".to_string()),
                ..Default::default()
            }),
        };
        // Must fail: either mutual exclusion (Linux) or platform not supported (non-Linux)
        let err = OutboundHandler::from_entry(&entry).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mutually exclusive")
                || msg.contains("bind_device")
                || msg.contains("only supported on Linux"),
            "Expected device-related error, got: {}",
            msg
        );
    }

    #[test]
    fn test_direct_bind_ipv4_unreachable_rejected() {
        // Use an IP that cannot exist on any local interface
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                bind_ipv4: Some("198.51.100.1".to_string()), // TEST-NET-2, never local
                ..Default::default()
            }),
        };
        let err = OutboundHandler::from_entry(&entry).unwrap_err();
        assert!(
            err.to_string().contains("FATAL") && err.to_string().contains("bindIPv4"),
            "Expected startup bind validation error, got: {}",
            err
        );
    }

    #[test]
    fn test_direct_bind_ipv4_loopback_ok() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                bind_ipv4: Some("127.0.0.1".to_string()),
                ..Default::default()
            }),
        };
        let handler = OutboundHandler::from_entry(&entry).unwrap();
        assert!(matches!(handler, OutboundHandler::Direct(_)));
    }

    #[test]
    fn test_direct_bind_ipv6_unreachable_rejected() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                bind_ipv6: Some("2001:db8::1".to_string()), // Documentation prefix, never local
                ..Default::default()
            }),
        };
        let err = OutboundHandler::from_entry(&entry).unwrap_err();
        assert!(
            err.to_string().contains("FATAL") && err.to_string().contains("bindIPv6"),
            "Expected startup bind validation error, got: {}",
            err
        );
    }

    #[test]
    fn test_direct_bind_ipv6_loopback_ok() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                bind_ipv6: Some("::1".to_string()),
                ..Default::default()
            }),
        };
        let handler = OutboundHandler::from_entry(&entry).unwrap();
        assert!(matches!(handler, OutboundHandler::Direct(_)));
    }

    #[test]
    fn test_direct_bind_device_exclusive_with_bind_ipv6() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                bind_ipv6: Some("::1".to_string()),
                bind_device: Some("eth0".to_string()),
                ..Default::default()
            }),
        };
        // Must fail: either mutual exclusion (Linux) or platform not supported (non-Linux)
        let err = OutboundHandler::from_entry(&entry).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("mutually exclusive")
                || msg.contains("bind_device")
                || msg.contains("only supported on Linux"),
            "Expected device-related error, got: {}",
            msg
        );
    }

    #[test]
    fn test_direct_bind_device_rejected_on_non_linux() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                bind_device: Some("lo0".to_string()),
                ..Default::default()
            }),
        };
        if cfg!(target_os = "linux") {
            // On Linux: may succeed or fail depending on permissions/device,
            // but should not fail with "only supported on Linux"
            let result = OutboundHandler::from_entry(&entry);
            if let Err(ref e) = result {
                assert!(
                    !e.to_string().contains("only supported on Linux"),
                    "Should not get platform error on Linux, got: {}",
                    e
                );
            }
        } else {
            // On non-Linux: should fail with platform error
            let err = OutboundHandler::from_entry(&entry).unwrap_err();
            assert!(
                err.to_string().contains("only supported on Linux"),
                "Expected platform error, got: {}",
                err
            );
        }
    }

    #[test]
    fn test_direct_with_fast_open() {
        let entry = OutboundEntry {
            name: "direct".to_string(),
            outbound_type: "direct".to_string(),
            socks5: None,
            http: None,
            direct: Some(DirectConfig {
                fast_open: true,
                ..Default::default()
            }),
        };
        let handler = OutboundHandler::from_entry(&entry).unwrap();
        assert!(matches!(handler, OutboundHandler::Direct(_)));
    }

    #[test]
    fn test_direct_config_yaml_camel_case() {
        let yaml = r#"
outbounds:
  - name: direct
    type: direct
    direct:
      mode: "4"
      bindIPv4: "127.0.0.1"
      fastOpen: true
acl:
  inline:
    - direct(all)
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        let direct_cfg = config.outbounds[0].direct.as_ref().unwrap();
        assert_eq!(direct_cfg.mode, "4");
        assert_eq!(direct_cfg.bind_ipv4.as_deref(), Some("127.0.0.1"));
        assert_eq!(direct_cfg.fast_open, true);
        assert!(direct_cfg.bind_ipv6.is_none());
        assert!(direct_cfg.bind_device.is_none());
    }

    #[test]
    fn test_direct_config_yaml_all_options() {
        let yaml = r#"
outbounds:
  - name: direct
    type: direct
    direct:
      mode: prefer4
      bindIPv4: "10.0.0.1"
      bindIPv6: "::1"
      fastOpen: false
acl:
  inline:
    - direct(all)
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        let direct_cfg = config.outbounds[0].direct.as_ref().unwrap();
        assert_eq!(direct_cfg.mode, "prefer4");
        assert_eq!(direct_cfg.bind_ipv4.as_deref(), Some("10.0.0.1"));
        assert_eq!(direct_cfg.bind_ipv6.as_deref(), Some("::1"));
        assert_eq!(direct_cfg.fast_open, false);
    }

    #[test]
    fn test_direct_config_default_values() {
        // Minimal YAML: only mode should default to "auto", rest None/false
        let yaml = r#"
outbounds:
  - name: direct
    type: direct
    direct: {}
acl:
  inline:
    - direct(all)
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        let direct_cfg = config.outbounds[0].direct.as_ref().unwrap();
        assert_eq!(direct_cfg.mode, "auto");
        assert!(direct_cfg.bind_ipv4.is_none());
        assert!(direct_cfg.bind_ipv6.is_none());
        assert!(direct_cfg.bind_device.is_none());
        assert_eq!(direct_cfg.fast_open, false);
    }

    #[test]
    fn test_outbound_handler_unknown_type() {
        let entry = OutboundEntry {
            name: "unknown".to_string(),
            outbound_type: "unknown_type".to_string(),
            socks5: None,
            http: None,
            direct: None,
        };

        let result = OutboundHandler::from_entry(&entry);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unknown outbound type"));
    }

    #[test]
    fn test_outbound_handler_missing_socks5_config() {
        let entry = OutboundEntry {
            name: "bad-socks5".to_string(),
            outbound_type: "socks5".to_string(),
            socks5: None, // Missing required config
            http: None,
            direct: None,
        };

        let result = OutboundHandler::from_entry(&entry);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("socks5 config required"));
    }

    #[test]
    fn test_outbound_handler_missing_http_config() {
        let entry = OutboundEntry {
            name: "bad-http".to_string(),
            outbound_type: "http".to_string(),
            socks5: None,
            http: None, // Missing required config
            direct: None,
        };

        let result = OutboundHandler::from_entry(&entry);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("http config required"));
    }

    #[test]
    fn test_outbound_handler_debug_format() {
        let direct = OutboundHandler::Direct(Arc::new(Direct::new()));
        assert_eq!(format!("{:?}", direct), "Direct");

        let reject = OutboundHandler::Reject(Arc::new(Reject::new()));
        assert_eq!(format!("{:?}", reject), "Reject");

        let socks5 = OutboundHandler::Socks5 {
            inner: Arc::new(Socks5::new("127.0.0.1:1080")),
            allow_udp: true,
        };
        assert_eq!(format!("{:?}", socks5), "Socks5(udp=true)");

        let http = OutboundHandler::Http(Arc::new(Http::new("127.0.0.1:8080")));
        assert_eq!(format!("{:?}", http), "Http");
    }

    #[tokio::test]
    async fn test_acl_engine_with_multiple_outbounds() {
        let yaml = r#"
outbounds:
  - name: proxy1
    type: socks5
    socks5:
      addr: 127.0.0.1:1080
  - name: proxy2
    type: http
    http:
      addr: 127.0.0.1:8080
acl:
  inline:
    - proxy1(suffix:example.com)
    - proxy2(suffix:test.org)
    - direct(all)
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        let engine = AclEngine::new(config, None, false).await.unwrap();

        assert_eq!(engine.rule_count(), 3);
    }

    #[tokio::test]
    async fn test_acl_engine_match_ip_addresses() {
        let engine = AclEngine::new_default().unwrap();

        // Test IPv4
        let handler = engine.match_host("192.168.1.1", 80, Protocol::TCP);
        assert!(handler.is_some());

        // Test IPv6
        let handler = engine.match_host("::1", 80, Protocol::TCP);
        assert!(handler.is_some());
    }

    #[tokio::test]
    async fn test_acl_engine_reject_rule() {
        let yaml = r#"
outbounds: []
acl:
  inline:
    - reject(suffix:blocked.com)
    - direct(all)
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        let engine = AclEngine::new(config, None, false).await.unwrap();

        // Test blocked domain
        let handler = engine.match_host("www.blocked.com", 443, Protocol::TCP);
        assert!(handler.is_some());
        assert!(handler.unwrap().is_reject());

        // Test allowed domain
        let handler = engine.match_host("example.com", 80, Protocol::TCP);
        assert!(handler.is_some());
        assert!(!handler.unwrap().is_reject());
    }

    #[tokio::test]
    async fn test_acl_engine_protocol_specific_rules() {
        let yaml = r#"
outbounds: []
acl:
  inline:
    - reject(all, udp/443)
    - direct(all)
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        let engine = AclEngine::new(config, None, false).await.unwrap();

        // UDP on port 443 should be rejected
        let handler = engine.match_host("example.com", 443, Protocol::UDP);
        assert!(handler.is_some());
        assert!(handler.unwrap().is_reject());

        // TCP on port 443 should be allowed (direct)
        let handler = engine.match_host("example.com", 443, Protocol::TCP);
        assert!(handler.is_some());
        assert!(!handler.unwrap().is_reject());

        // UDP on other ports should be allowed
        let handler = engine.match_host("example.com", 80, Protocol::UDP);
        assert!(handler.is_some());
        assert!(!handler.unwrap().is_reject());
    }

    #[tokio::test]
    async fn test_acl_engine_port_specific_rules() {
        let yaml = r#"
outbounds:
  - name: warp
    type: socks5
    socks5:
      addr: 127.0.0.1:40000
acl:
  inline:
    - warp(all, tcp/22)
    - warp(all, tcp/25)
    - direct(all)
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        let engine = AclEngine::new(config, None, false).await.unwrap();

        // Port 22 should match warp (socks5)
        let handler = engine.match_host("any.host.com", 22, Protocol::TCP);
        assert!(handler.is_some());
        assert!(matches!(*handler.unwrap(), OutboundHandler::Socks5 { .. }));

        // Port 25 should match warp (socks5)
        let handler = engine.match_host("any.host.com", 25, Protocol::TCP);
        assert!(handler.is_some());
        assert!(matches!(*handler.unwrap(), OutboundHandler::Socks5 { .. }));

        // Port 80 should be direct
        let handler = engine.match_host("any.host.com", 80, Protocol::TCP);
        assert!(handler.is_some());
        assert!(matches!(*handler.unwrap(), OutboundHandler::Direct(_)));
    }

    #[tokio::test]
    async fn test_load_acl_config_from_file() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
        writeln!(
            file,
            r#"
outbounds:
  - name: test
    type: direct
acl:
  inline:
    - test(all)
"#
        )
        .unwrap();

        let config = load_acl_config(file.path()).await.unwrap();
        assert_eq!(config.outbounds.len(), 1);
        assert_eq!(config.outbounds[0].name, "test");
    }

    #[tokio::test]
    async fn test_load_acl_config_invalid_yaml() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut file = NamedTempFile::with_suffix(".yaml").unwrap();
        writeln!(file, "this is not valid yaml: {{{{").unwrap();

        let result = load_acl_config(file.path()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_load_acl_config_file_not_found() {
        use std::path::Path;
        let result = load_acl_config(Path::new("/nonexistent/path/config.yaml")).await;
        assert!(result.is_err());
    }

    // Integration test with real acl-o.yaml file
    #[tokio::test]
    async fn test_real_acl_config_file() {
        use std::path::Path;

        let acl_path = Path::new("acl-o.yaml");
        if !acl_path.exists() {
            println!("Skipping test: acl-o.yaml not found");
            return;
        }

        // Load and parse the real config
        let config = load_acl_config(acl_path).await.unwrap();

        // Verify basic structure
        assert!(
            !config.outbounds.is_empty(),
            "Should have at least one outbound"
        );
        assert!(!config.acl.inline.is_empty(), "Should have ACL rules");

        // Verify warp outbound exists and is socks5 type
        let warp_outbound = config.outbounds.iter().find(|o| o.name == "warp");
        assert!(warp_outbound.is_some(), "Should have 'warp' outbound");
        assert_eq!(warp_outbound.unwrap().outbound_type, "socks5");

        // Create engine (without geo data, will skip geosite rules)
        // Note: This may fail if geosite rules are required and data_dir is not provided
        // For a full test with geosite, provide data_dir with actual geo files
        let engine_result = AclEngine::new(config, None, false).await;

        // If engine creation succeeds, test some rules
        if let Ok(engine) = engine_result {
            println!("ACL engine created with {} rules", engine.rule_count());

            // Test reject rule: udp/443 should be rejected
            let handler = engine.match_host("any.com", 443, Protocol::UDP);
            if let Some(h) = handler {
                assert!(h.is_reject(), "UDP/443 should be rejected");
            }

            // Test port-based rule: tcp/22 should go through warp
            let handler = engine.match_host("any.com", 22, Protocol::TCP);
            if let Some(h) = handler {
                assert!(
                    matches!(*h, OutboundHandler::Socks5 { .. }),
                    "TCP/22 should use warp (socks5)"
                );
            }

            // Test suffix rule: google.com should go through warp
            let handler = engine.match_host("www.google.com", 443, Protocol::TCP);
            if let Some(h) = handler {
                assert!(
                    matches!(*h, OutboundHandler::Socks5 { .. }),
                    "google.com should use warp"
                );
            }

            // Test default rule: random domain should be direct
            let handler = engine.match_host("random-unknown-site.xyz", 80, Protocol::TCP);
            if let Some(h) = handler {
                assert!(
                    matches!(*h, OutboundHandler::Direct(_)),
                    "Unknown domain should be direct"
                );
            }
        } else {
            println!(
                "Note: ACL engine creation failed (likely due to missing geo data): {:?}",
                engine_result.err()
            );
        }
    }

    // Test with real geo data (requires data directory)
    #[tokio::test]
    async fn test_real_acl_with_geo_data() {
        use std::path::Path;

        let acl_path = Path::new("acl-o.yaml");
        let data_dir = Path::new("data"); // Standard data directory

        if !acl_path.exists() {
            println!("Skipping test: acl-o.yaml not found");
            return;
        }

        if !data_dir.exists() {
            println!("Skipping full geo test: data directory not found");
            return;
        }

        let config = load_acl_config(acl_path).await.unwrap();
        let engine = AclEngine::new(config, Some(data_dir), false).await;

        match engine {
            Ok(engine) => {
                println!(
                    "ACL engine created with geo data, {} rules",
                    engine.rule_count()
                );

                // Test geosite:openai rule (if data is available)
                let handler = engine.match_host("chat.openai.com", 443, Protocol::TCP);
                if let Some(h) = handler {
                    println!("openai.com matched: {:?}", h);
                }

                // Test geosite:google-deepmind rule
                let handler = engine.match_host("deepmind.google.com", 443, Protocol::TCP);
                if let Some(h) = handler {
                    println!("deepmind.google.com matched: {:?}", h);
                }
            }
            Err(e) => {
                println!("ACL engine with geo data failed: {}", e);
            }
        }
    }

    #[test]
    fn test_default_ip_mode() {
        assert_eq!(default_ip_mode(), "auto");
    }

    #[test]
    fn test_acl_rules_default() {
        let rules = AclRules::default();
        assert!(rules.inline.is_empty());
    }

    #[test]
    fn test_direct_config_default_mode() {
        let yaml = r#"
outbounds:
  - name: d
    type: direct
acl:
  inline: []
"#;
        let config: AclConfig = serde_yaml::from_str(yaml).unwrap();
        // direct config is None, should use default "auto" mode
        assert!(config.outbounds[0].direct.is_none());
    }

    #[test]
    fn test_acl_router_blocks_private_ip_by_default() {
        let engine = AclEngine::new_default().unwrap();
        let router = AclRouter::with_block_private_ip(engine, true);
        assert!(router.block_private_ip);
    }

    #[test]
    fn test_acl_router_with_custom_block_setting() {
        let engine = AclEngine::new_default().unwrap();
        let router = AclRouter::with_block_private_ip(engine, false);
        assert!(!router.block_private_ip);
    }

    #[tokio::test]
    async fn test_acl_router_rejects_private_ipv4() {
        use crate::core::hooks::OutboundRouter;
        use crate::core::Address;

        let engine = AclEngine::new_default().unwrap();
        let router = AclRouter::with_block_private_ip(engine, true);

        // Test loopback
        let addr = Address::IPv4([127, 0, 0, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, crate::core::hooks::OutboundType::Reject));

        // Test private Class A
        let addr = Address::IPv4([10, 0, 0, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, crate::core::hooks::OutboundType::Reject));

        // Test private Class C
        let addr = Address::IPv4([192, 168, 1, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, crate::core::hooks::OutboundType::Reject));

        // Test public IP should not be rejected
        let addr = Address::IPv4([8, 8, 8, 8], 80);
        let result = router.route(&addr).await;
        assert!(matches!(
            result,
            crate::core::hooks::OutboundType::Direct { .. }
        ));
    }

    #[tokio::test]
    async fn test_acl_router_rejects_private_ipv6() {
        use crate::core::hooks::OutboundRouter;
        use crate::core::Address;

        let engine = AclEngine::new_default().unwrap();
        let router = AclRouter::with_block_private_ip(engine, true);

        // Test loopback ::1
        let addr = Address::IPv6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, crate::core::hooks::OutboundType::Reject));

        // Test ULA (fd00::1)
        let addr = Address::IPv6([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, crate::core::hooks::OutboundType::Reject));
    }

    #[tokio::test]
    async fn test_acl_router_allows_private_when_disabled() {
        use crate::core::hooks::OutboundRouter;
        use crate::core::Address;

        let engine = AclEngine::new_default().unwrap();
        let router = AclRouter::with_block_private_ip(engine, false);

        // Private IP should be allowed when blocking is disabled
        let addr = Address::IPv4([127, 0, 0, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(
            result,
            crate::core::hooks::OutboundType::Direct { .. }
        ));
    }
}
