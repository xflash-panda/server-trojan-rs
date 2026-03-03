//! Hook traits for extensibility
//!
//! Defines the extension points that allow business logic to be injected into the core proxy.

use crate::core::Address;
use async_trait::async_trait;
use std::net::SocketAddr;

/// User ID type used throughout the system.
/// Using i64 for consistency with database and API layer.
pub type UserId = i64;

/// Authenticator trait for user authentication
///
/// Synchronous by design: authentication is a hash-table lookup (ArcSwap),
/// not an I/O operation. Eliminating `async_trait` avoids one `Box<dyn Future>`
/// heap allocation per connection on the hot path.
pub trait Authenticator: Send + Sync {
    /// Authenticate user by password hash, returns user_id if successful
    fn authenticate(&self, password: &[u8; 56]) -> Option<UserId>;
}

/// Statistics collector trait for traffic tracking
pub trait StatsCollector: Send + Sync {
    /// Record a proxy request
    fn record_request(&self, user_id: UserId);
    /// Record upload bytes (client -> remote)
    fn record_upload(&self, user_id: UserId, bytes: u64);
    /// Record download bytes (remote -> client)
    fn record_download(&self, user_id: UserId, bytes: u64);
}

/// Outbound router trait for routing decisions
#[async_trait]
pub trait OutboundRouter: Send + Sync {
    /// Route based on target address, returns the outbound handler
    async fn route(&self, addr: &Address) -> OutboundType;
}

/// Outbound type for routing decisions
#[derive(Clone)]
pub enum OutboundType {
    /// Direct connection, optionally with a pre-resolved address to skip redundant DNS.
    /// When the router already resolved the domain (e.g. for SSRF checking), it passes
    /// the result here so the handler can reuse it instead of resolving again.
    /// The handler is passed when ACL is configured so bind/fastOpen options are respected.
    Direct {
        resolved: Option<SocketAddr>,
        handler: Option<std::sync::Arc<crate::acl::OutboundHandler>>,
    },
    /// Reject connection
    Reject,
    /// Proxy connection via ACL engine outbound handler
    Proxy(std::sync::Arc<crate::acl::OutboundHandler>),
}

impl std::fmt::Debug for OutboundType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutboundType::Direct {
                resolved: None,
                handler: None,
            } => write!(f, "Direct"),
            OutboundType::Direct {
                resolved: Some(addr),
                ..
            } => write!(f, "Direct({})", addr),
            OutboundType::Direct {
                handler: Some(h), ..
            } => write!(f, "Direct({:?})", h),
            OutboundType::Reject => write!(f, "Reject"),
            OutboundType::Proxy(handler) => write!(f, "Proxy({:?})", handler),
        }
    }
}

/// Direct router - routes all traffic directly with optional private IP blocking
pub struct DirectRouter {
    /// Block connections to private/loopback IP addresses
    block_private_ip: bool,
}

impl DirectRouter {
    /// Create a new DirectRouter with private IP blocking enabled (default)
    pub fn new() -> Self {
        Self {
            block_private_ip: true,
        }
    }

    /// Create a new DirectRouter with custom private IP blocking setting
    pub fn with_block_private_ip(block_private_ip: bool) -> Self {
        Self { block_private_ip }
    }
}

impl Default for DirectRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl OutboundRouter for DirectRouter {
    async fn route(&self, addr: &Address) -> OutboundType {
        if self.block_private_ip {
            let (is_private, resolved) = check_private_and_resolve(addr).await;
            if is_private {
                return OutboundType::Reject;
            }
            return OutboundType::Direct {
                resolved,
                handler: None,
            };
        }
        OutboundType::Direct {
            resolved: None,
            handler: None,
        }
    }
}

/// Check if an address is private/loopback/link-local.
/// For domain addresses, also returns the first non-private resolved SocketAddr
/// so callers can reuse it without a second DNS lookup.
pub(crate) async fn check_private_and_resolve(addr: &Address) -> (bool, Option<SocketAddr>) {
    use super::ip_filter::{is_private_ipv4, is_private_ipv6};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    match addr {
        Address::IPv4(ip, _) => {
            let ipv4 = Ipv4Addr::from(*ip);
            (is_private_ipv4(&ipv4), None)
        }
        Address::IPv6(ip, _) => {
            let ipv6 = Ipv6Addr::from(*ip);
            (is_private_ipv6(&ipv6), None)
        }
        Address::Domain(domain, port) => {
            use tokio::net::lookup_host;
            let lookup = format!("{}:{}", domain, port);
            let resolved: Vec<SocketAddr> = match lookup_host(&lookup).await {
                Ok(addrs) => addrs.collect(),
                Err(_) => return (false, None),
            };
            let mut first_public: Option<SocketAddr> = None;
            for addr in resolved {
                match addr.ip() {
                    IpAddr::V4(ipv4) if is_private_ipv4(&ipv4) => {
                        return (true, None);
                    }
                    IpAddr::V6(ipv6) if is_private_ipv6(&ipv6) => {
                        return (true, None);
                    }
                    _ => {
                        if first_public.is_none() {
                            first_public = Some(addr);
                        }
                    }
                }
            }
            (false, first_public)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_direct_router_public_domain() {
        let router = DirectRouter::new();
        let addr = Address::Domain("example.com".to_string(), 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Direct { .. }));
    }

    #[tokio::test]
    async fn test_direct_router_blocks_loopback() {
        let router = DirectRouter::new();
        let addr = Address::IPv4([127, 0, 0, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Reject));
    }

    #[tokio::test]
    async fn test_direct_router_blocks_private_ip() {
        let router = DirectRouter::new();

        // 10.0.0.0/8
        let addr = Address::IPv4([10, 0, 0, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Reject));

        // 192.168.0.0/16
        let addr = Address::IPv4([192, 168, 1, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Reject));
    }

    #[tokio::test]
    async fn test_direct_router_allows_public_ip() {
        let router = DirectRouter::new();
        let addr = Address::IPv4([8, 8, 8, 8], 80);
        let result = router.route(&addr).await;
        assert!(matches!(
            result,
            OutboundType::Direct {
                resolved: None,
                handler: None
            }
        ));
    }

    #[tokio::test]
    async fn test_direct_router_allows_private_when_disabled() {
        let router = DirectRouter::with_block_private_ip(false);
        let addr = Address::IPv4([127, 0, 0, 1], 80);
        let result = router.route(&addr).await;
        assert!(matches!(
            result,
            OutboundType::Direct {
                resolved: None,
                handler: None
            }
        ));
    }

    #[tokio::test]
    async fn test_direct_router_domain_returns_resolved_addr() {
        let router = DirectRouter::new();
        // localhost resolves to 127.0.0.1 which is private → Reject
        let addr = Address::Domain("localhost".to_string(), 80);
        let result = router.route(&addr).await;
        assert!(matches!(result, OutboundType::Reject));
    }

    #[tokio::test]
    async fn test_check_private_and_resolve_ipv4_private() {
        let addr = Address::IPv4([10, 0, 0, 1], 80);
        let (is_private, resolved) = check_private_and_resolve(&addr).await;
        assert!(is_private);
        assert!(resolved.is_none());
    }

    #[tokio::test]
    async fn test_check_private_and_resolve_ipv4_public() {
        let addr = Address::IPv4([8, 8, 8, 8], 53);
        let (is_private, resolved) = check_private_and_resolve(&addr).await;
        assert!(!is_private);
        // IP addresses don't need DNS, resolved is None
        assert!(resolved.is_none());
    }

    #[tokio::test]
    async fn test_check_private_and_resolve_domain_private() {
        let addr = Address::Domain("localhost".to_string(), 80);
        let (is_private, resolved) = check_private_and_resolve(&addr).await;
        assert!(is_private);
        assert!(resolved.is_none());
    }

    #[tokio::test]
    async fn test_check_private_and_resolve_domain_public() {
        // example.com should resolve to a public IP
        let addr = Address::Domain("example.com".to_string(), 80);
        let (is_private, resolved) = check_private_and_resolve(&addr).await;
        assert!(!is_private);
        // Should have a resolved address from the DNS lookup
        assert!(
            resolved.is_some(),
            "public domain should return resolved addr"
        );
        let socket_addr = resolved.unwrap();
        assert_eq!(socket_addr.port(), 80);
    }
}
