//! Connection handling logic
//!
//! This module contains the request processing and connection relay logic.

use crate::acl;
use crate::core::{
    copy_bidirectional_with_stats, hooks, Address, DecodeResult, Server, TrojanCmd, TrojanRequest,
    TrojanUdpPacket, UserId,
};
use crate::logger::log;
use crate::transport::TransportStream;

use anyhow::{anyhow, Result};
use bytes::BytesMut;
use socket2::{SockRef, TcpKeepalive};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::transport::ConnectionMeta;

/// Maximum entries in per-session UDP route cache
const UDP_MAX_ROUTE_CACHE_ENTRIES: usize = 256;

/// TCP keepalive interval for outbound connections (matches Go default)
const TCP_KEEPALIVE_SECS: u64 = 15;

/// Shutdown timeout — prevents infinite hang when peer is unresponsive
const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Read and decode a complete Trojan request from the stream
///
/// This function handles partial reads by continuing to read until
/// a complete request is received or an error occurs.
pub async fn read_trojan_request(
    stream: &mut TransportStream,
    buf: &mut BytesMut,
    buffer_size: usize,
) -> Result<TrojanRequest> {
    loop {
        // Try to decode with current buffer (check completeness first to avoid clone)
        if buf.len() >= TrojanRequest::MIN_SIZE {
            match TrojanRequest::check_complete(buf) {
                Ok(_header_len) => {
                    // Buffer contains complete request, now decode it
                    match TrojanRequest::decode_zerocopy(buf) {
                        DecodeResult::Ok(req, _) => {
                            return Ok(req);
                        }
                        DecodeResult::Invalid(e) => {
                            return Err(anyhow!("Invalid request: {}", e));
                        }
                        DecodeResult::NeedMoreData => {
                            // Should not happen after check_complete succeeds
                            unreachable!("check_complete succeeded but decode failed");
                        }
                    }
                }
                Err(None) => {
                    // Need more data, continue reading
                }
                Err(Some(e)) => {
                    return Err(anyhow!("Invalid request: {}", e));
                }
            }
        }

        // Read directly into BytesMut spare capacity (avoids separate heap allocation)
        buf.reserve(buffer_size);
        let n = stream.read_buf(buf).await?;
        if n == 0 {
            if buf.is_empty() {
                return Err(anyhow!("Connection closed before receiving request"));
            } else {
                return Err(anyhow!("Connection closed with incomplete request"));
            }
        }

        // Prevent buffer from growing too large (protection against malicious clients)
        if buf.len() > buffer_size * 2 {
            return Err(anyhow!("Request too large"));
        }
    }
}

/// Process a single connection
pub async fn process_connection(
    server: &Server,
    mut stream: TransportStream,
    meta: ConnectionMeta,
) -> Result<()> {
    // Read Trojan request with timeout and retry for incomplete data
    let buffer_size = server.conn_config.buffer_size;
    let mut buf = BytesMut::with_capacity(buffer_size);

    let request = tokio::time::timeout(
        server.conn_config.request_timeout,
        read_trojan_request(&mut stream, &mut buf, buffer_size),
    )
    .await
    .map_err(|_| anyhow!("Request read timeout"))??;

    // Free request parsing buffer immediately — payload is an independent Bytes.
    // Saves 32KB per connection during the relay phase.
    drop(buf);

    let peer_addr = meta.peer_addr;

    // Authenticate user
    let user_id = match server.authenticator.authenticate(&request.password) {
        Some(id) => id,
        None => {
            log::authentication(peer_addr, false);
            log::debug!(
                peer = %peer_addr,
                transport = %meta.transport_type,
                "Invalid user credentials"
            );
            return Err(anyhow!("Invalid user credentials"));
        }
    };

    log::authentication(peer_addr, true);
    log::debug!(peer = %peer_addr, user_id = user_id, "User authenticated");

    // Register connection for tracking and kick-off capability
    let (conn_id, cancel_token) = server.conn_manager.register(user_id, peer_addr);
    log::debug!(peer = %peer_addr, user_id = user_id, conn_id = conn_id, "Connection registered");

    // Ensure connection is unregistered when done
    let _guard = scopeguard::guard((), |_| {
        server.conn_manager.unregister(conn_id);
        log::debug!(conn_id = conn_id, "Connection unregistered");
    });

    // Record proxy request
    server.stats.record_request(user_id);

    match request.cmd {
        TrojanCmd::Connect => {
            handle_connect(
                server,
                stream,
                request.addr,
                request.payload,
                peer_addr,
                user_id,
                cancel_token,
            )
            .await
        }
        TrojanCmd::UdpAssociate => {
            handle_udp_associate(
                server,
                stream,
                request.addr,
                request.payload,
                peer_addr,
                user_id,
                cancel_token,
            )
            .await
        }
    }
}

/// Handle TCP CONNECT command
async fn handle_connect(
    server: &Server,
    client_stream: TransportStream,
    target: Address,
    initial_payload: bytes::Bytes,
    peer_addr: SocketAddr,
    user_id: UserId,
    cancel_token: CancellationToken,
) -> Result<()> {
    // Route the connection (passing Address directly avoids string allocation)
    let outbound_type = server.router.route(&target).await;

    // Check if connection should be rejected
    if matches!(outbound_type, hooks::OutboundType::Reject) {
        log::debug!(peer = %peer_addr, target = %target, "Connection rejected by router");
        return Ok(());
    }

    log::debug!(peer = %peer_addr, target = %target, outbound = ?outbound_type, "Connecting to target");

    // Build connect context
    let ctx = ConnectContext {
        server,
        client_stream,
        target: &target,
        initial_payload,
        peer_addr,
        user_id,
        cancel_token,
    };

    // Connect based on outbound type
    match outbound_type {
        hooks::OutboundType::Direct { resolved, handler } => {
            handle_direct_connect(ctx, resolved, handler).await
        }
        hooks::OutboundType::Proxy(handler) => handle_proxy_connect(ctx, handler).await,
        hooks::OutboundType::Reject => Ok(()), // Already handled above
    }
}

/// Context for handling outbound connections
struct ConnectContext<'a> {
    server: &'a Server,
    client_stream: TransportStream,
    target: &'a Address,
    initial_payload: bytes::Bytes,
    peer_addr: SocketAddr,
    user_id: UserId,
    cancel_token: CancellationToken,
}

impl<'a> ConnectContext<'a> {
    /// Relay data between client and remote with stats tracking
    async fn relay<S>(self, mut remote_stream: S) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        // Keep ownership of client_stream so we can shutdown after cancel
        let mut client_stream = self.client_stream;

        // Write initial payload if any
        if !self.initial_payload.is_empty() {
            self.server
                .stats
                .record_upload(self.user_id, self.initial_payload.len() as u64);
            remote_stream.write_all(&self.initial_payload).await?;
        }

        // Relay data with stats tracking and cancellation support.
        // Pass &mut so streams aren't moved into the future — this allows
        // graceful shutdown even when cancel_token drops the relay future.
        let stats = Arc::clone(&self.server.stats);
        let relay_fut = copy_bidirectional_with_stats(
            &mut client_stream,
            &mut remote_stream,
            self.server.conn_config.idle_timeout_secs(),
            self.server.conn_config.uplink_only_timeout_secs(),
            self.server.conn_config.downlink_only_timeout_secs(),
            self.server.conn_config.buffer_size,
            Some((self.user_id, stats)),
        );

        let cancelled = tokio::select! {
            result = relay_fut => {
                match result {
                    Ok(r) if r.completed => {
                        log::trace!(peer = %self.peer_addr, up = r.a_to_b, down = r.b_to_a, "Relay completed");
                    }
                    Ok(r) => {
                        log::debug!(peer = %self.peer_addr, up = r.a_to_b, down = r.b_to_a, "Connection timeout");
                    }
                    Err(e) => {
                        log::debug!(peer = %self.peer_addr, error = %e, "Relay error");
                    }
                }
                false
            }
            _ = self.cancel_token.cancelled() => {
                log::debug!(peer = %self.peer_addr, "Connection kicked");
                true
            }
        };

        // Only shutdown on cancel — relay already handles shutdown on completion/timeout/error.
        if cancelled {
            let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, client_stream.shutdown()).await;
            let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, remote_stream.shutdown()).await;
        }

        Ok(())
    }
}

/// Handle direct connection
async fn handle_direct_connect(
    ctx: ConnectContext<'_>,
    resolved: Option<std::net::SocketAddr>,
    handler: Option<Arc<acl::OutboundHandler>>,
) -> Result<()> {
    // When handler is present (ACL configured), use it for bind/fastOpen support
    if let Some(handler) = handler {
        use acl::{Addr as AclAddr, AsyncOutbound};

        let mut acl_addr = if let Some(addr) = resolved {
            // Pass pre-resolved address to avoid redundant DNS
            AclAddr::from_socket_addr(addr)
        } else {
            AclAddr::new(ctx.target.host().into_owned(), ctx.target.port())
        };

        // Connect via handler (respects bind/fastOpen options)
        let remote_stream = match tokio::time::timeout(
            ctx.server.conn_config.connect_timeout,
            handler.dial_tcp(&mut acl_addr),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                log::debug!(peer = %ctx.peer_addr, target = %ctx.target, error = %e, "Direct connect failed");
                return Err(anyhow!("Direct connect failed: {}", e));
            }
            Err(_) => {
                log::debug!(peer = %ctx.peer_addr, target = %ctx.target, "Direct connect timeout");
                return Err(anyhow!("Direct connect timeout"));
            }
        };

        log::debug!(peer = %ctx.peer_addr, target = %ctx.target, handler = ?handler, "Connected to remote (direct)");
        return ctx.relay(remote_stream).await;
    }

    // Fast path: no ACL handler, use simple TcpStream::connect with keepalive/nodelay
    let remote_addr = match resolved {
        Some(addr) => addr,
        None => ctx.target.to_socket_addr().await?,
    };

    let remote_stream = match tokio::time::timeout(
        ctx.server.conn_config.connect_timeout,
        TcpStream::connect(remote_addr),
    )
    .await
    {
        Ok(Ok(stream)) => {
            if ctx.server.conn_config.tcp_nodelay {
                let _ = stream.set_nodelay(true);
            }
            let keepalive = TcpKeepalive::new()
                .with_time(std::time::Duration::from_secs(TCP_KEEPALIVE_SECS))
                .with_interval(std::time::Duration::from_secs(TCP_KEEPALIVE_SECS));
            let _ = SockRef::from(&stream).set_tcp_keepalive(&keepalive);
            stream
        }
        Ok(Err(e)) => {
            log::debug!(peer = %ctx.peer_addr, error = %e, "TCP connect failed");
            return Err(e.into());
        }
        Err(_) => {
            log::debug!(peer = %ctx.peer_addr, "TCP connect timeout");
            return Err(anyhow!("TCP connect timeout"));
        }
    };

    log::debug!(peer = %ctx.peer_addr, remote = %remote_addr, "Connected to remote (direct)");
    ctx.relay(remote_stream).await
}

/// Handle proxy connection via ACL engine outbound handler
async fn handle_proxy_connect(
    ctx: ConnectContext<'_>,
    handler: Arc<acl::OutboundHandler>,
) -> Result<()> {
    use acl::{Addr as AclAddr, AsyncOutbound};

    // Convert Address to ACL Addr (Cow avoids clone for domains)
    let mut acl_addr = AclAddr::new(ctx.target.host().into_owned(), ctx.target.port());

    // Connect via proxy with timeout
    let remote_stream = match tokio::time::timeout(
        ctx.server.conn_config.connect_timeout,
        handler.dial_tcp(&mut acl_addr),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            log::debug!(peer = %ctx.peer_addr, target = %ctx.target, error = %e, "Proxy connect failed");
            return Err(anyhow!("Proxy connect failed: {}", e));
        }
        Err(_) => {
            log::debug!(peer = %ctx.peer_addr, target = %ctx.target, "Proxy connect timeout");
            return Err(anyhow!("Proxy connect timeout"));
        }
    };

    log::debug!(peer = %ctx.peer_addr, target = %ctx.target, handler = ?handler, "Connected to remote (proxy)");
    ctx.relay(remote_stream).await
}

/// Maximum UDP read buffer size to prevent memory exhaustion
const UDP_MAX_READ_BUFFER_SIZE: usize = 64 * 1024; // 64KB

/// Handle UDP ASSOCIATE command
async fn handle_udp_associate(
    server: &Server,
    mut client_stream: TransportStream,
    _initial_target: Address,
    initial_payload: bytes::Bytes,
    peer_addr: SocketAddr,
    user_id: UserId,
    cancel_token: CancellationToken,
) -> Result<()> {
    use acl::{Addr as AclAddr, AsyncOutbound, AsyncUdpConn};
    use std::collections::HashMap;

    // Buffer for reading UDP packets from TCP stream (with size limit)
    let mut read_buf = BytesMut::with_capacity(8 * 1024); // Start with 8KB
    if !initial_payload.is_empty() {
        read_buf.extend_from_slice(&initial_payload);
    }

    // Per-session route cache: avoids repeated router.route() + DNS for the same target.
    // Also caches the AclAddr for write_to() to avoid per-packet String allocation.
    let mut route_cache: HashMap<Address, (hooks::OutboundType, AclAddr)> = HashMap::new();

    // UDP relay loop
    let mut udp_recv_buf = vec![0u8; 65536];
    let mut udp_conn: Option<Box<dyn AsyncUdpConn>> = None;
    let mut current_handler: Option<Arc<acl::OutboundHandler>> = None;

    // Idle timeout tracking (same mechanism as TCP relay)
    let idle_timeout_secs = server.conn_config.idle_timeout_secs();
    let start_time = std::time::Instant::now();
    let mut last_activity_secs: u64 = 0;
    let mut idle_interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

    loop {
        tokio::select! {
            // Read from client TCP stream directly into BytesMut (avoids temp buffer)
            result = async {
                // Check buffer size limit before reading
                if read_buf.len() >= UDP_MAX_READ_BUFFER_SIZE {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::OutOfMemory,
                        "UDP read buffer exceeded limit",
                    ));
                }
                read_buf.reserve(8 * 1024);
                client_stream.read_buf(&mut read_buf).await
            } => {
                let n = match result {
                    Ok(0) => {
                        log::debug!(peer = %peer_addr, "UDP client disconnected");
                        break;
                    }
                    Ok(n) => n,
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::OutOfMemory {
                            log::warn!(
                                peer = %peer_addr,
                                buffer_size = read_buf.len(),
                                "UDP read buffer exceeded limit, closing connection"
                            );
                        } else {
                            log::debug!(peer = %peer_addr, error = %e, "UDP read error");
                        }
                        break;
                    }
                };
                let _ = n;
                last_activity_secs = start_time.elapsed().as_secs();

                // Process all complete UDP packets in buffer (zero-copy)
                while !read_buf.is_empty() {
                    match TrojanUdpPacket::decode_zerocopy(&mut read_buf) {
                        DecodeResult::Ok(packet, _consumed) => {

                            // Route the packet (use cache to avoid repeated DNS lookups and String allocs)
                            let (outbound_type, send_addr) = match route_cache.get(&packet.addr) {
                                Some(cached) => (cached.0.clone(), &cached.1),
                                None => {
                                    let result = server.router.route(&packet.addr).await;
                                    // Pre-compute the AclAddr for write_to() once per unique target
                                    let acl_addr = match &result {
                                        hooks::OutboundType::Direct { resolved: Some(addr), .. } => {
                                            AclAddr::new(addr.ip().to_string(), addr.port())
                                        }
                                        _ => AclAddr::new(packet.addr.host().into_owned(), packet.addr.port()),
                                    };
                                    // Evict all entries when cache is full to bound memory
                                    if route_cache.len() >= UDP_MAX_ROUTE_CACHE_ENTRIES {
                                        route_cache.clear();
                                    }
                                    route_cache.insert(packet.addr.clone(), (result.clone(), acl_addr));
                                    let cached = route_cache.get(&packet.addr).unwrap();
                                    (cached.0.clone(), &cached.1)
                                }
                            };

                            match &outbound_type {
                                hooks::OutboundType::Reject => {
                                    log::debug!(peer = %peer_addr, target = %packet.addr, "UDP packet rejected by router");
                                    continue;
                                }
                                hooks::OutboundType::Direct { handler, .. } => {
                                    // For direct, we need to create a UDP connection if not exists
                                    if udp_conn.is_none() || current_handler.is_some() {
                                        // Explicitly drop old connection to release resources
                                        if let Some(old_conn) = udp_conn.take() {
                                            drop(old_conn);
                                        }
                                        current_handler = None;

                                        // Use ACL handler if available (respects bind options),
                                        // otherwise fall back to default Direct
                                        let dial_handler: Arc<acl::OutboundHandler> = handler
                                            .clone()
                                            .unwrap_or_else(|| {
                                                Arc::new(acl::OutboundHandler::Direct(
                                                    Arc::new(acl::Direct::new()),
                                                ))
                                            });
                                        // Reuse cached AclAddr (avoids per-packet String allocation)
                                        let mut dial_addr = send_addr.clone();
                                        match dial_handler.dial_udp(&mut dial_addr).await {
                                            Ok(conn) => {
                                                udp_conn = Some(conn);
                                            }
                                            Err(e) => {
                                                log::debug!(peer = %peer_addr, target = %packet.addr, error = %e, "Failed to create direct UDP connection");
                                                continue;
                                            }
                                        }
                                    }
                                }
                                hooks::OutboundType::Proxy(handler) => {
                                    // Check if handler supports UDP
                                    if !handler.allows_udp() {
                                        log::debug!(peer = %peer_addr, target = %packet.addr, "UDP not allowed by outbound handler");
                                        continue;
                                    }

                                    // Create new UDP connection if handler changed or not exists
                                    let need_new_conn = match &current_handler {
                                        None => true,
                                        Some(h) => !Arc::ptr_eq(h, handler),
                                    };

                                    if need_new_conn {
                                        // Explicitly drop old connection to release resources
                                        if let Some(old_conn) = udp_conn.take() {
                                            drop(old_conn);
                                        }

                                        // Reuse cached AclAddr (avoids per-packet String allocation)
                                        let mut dial_addr = send_addr.clone();
                                        match handler.dial_udp(&mut dial_addr).await {
                                            Ok(conn) => {
                                                udp_conn = Some(conn);
                                                current_handler = Some(handler.clone());
                                            }
                                            Err(e) => {
                                                log::debug!(peer = %peer_addr, target = %packet.addr, error = %e, "Failed to create proxy UDP connection");
                                                continue;
                                            }
                                        }
                                    }
                                }
                            }

                            // Send UDP packet using cached AclAddr (zero per-packet String allocation)
                            if let Some(ref conn) = udp_conn {
                                match conn.write_to(&packet.payload, send_addr).await {
                                    Ok(n) => {
                                        server.stats.record_upload(user_id, n as u64);
                                        log::trace!(peer = %peer_addr, target = %packet.addr, bytes = n, "UDP packet sent");
                                    }
                                    Err(e) => {
                                        log::debug!(peer = %peer_addr, target = %packet.addr, error = %e, "UDP send error");
                                    }
                                }
                            }
                        }
                        DecodeResult::NeedMoreData => break,
                        DecodeResult::Invalid(msg) => {
                            log::debug!(peer = %peer_addr, error = %msg, "Invalid UDP packet");
                            read_buf.clear();
                            break;
                        }
                    }
                }
            }

            // Read from UDP connection (if exists), reusing pre-allocated buffer
            result = async {
                if let Some(ref conn) = udp_conn {
                    conn.read_from(&mut udp_recv_buf).await
                } else {
                    // No UDP connection, wait forever
                    std::future::pending::<acl_engine_r::Result<(usize, AclAddr)>>().await
                }
            } => {
                match result {
                    Ok((n, from_addr)) => {
                        last_activity_secs = start_time.elapsed().as_secs();

                        // Convert AclAddr back to Address
                        let addr = acl_addr_to_address(&from_addr);

                        // Encode and send back to client
                        let response = TrojanUdpPacket::encode(&addr, &udp_recv_buf[..n]);
                        if let Err(e) = client_stream.write_all(&response).await {
                            log::debug!(peer = %peer_addr, error = %e, "Failed to write UDP response");
                            break;
                        }
                        server.stats.record_download(user_id, n as u64);
                        log::trace!(peer = %peer_addr, from = %from_addr, bytes = n, "UDP packet received");
                    }
                    Err(e) => {
                        log::debug!(peer = %peer_addr, error = %e, "UDP recv error");
                    }
                }
            }

            // Idle timeout check (every 30s)
            _ = idle_interval.tick() => {
                let idle_secs = start_time.elapsed().as_secs().saturating_sub(last_activity_secs);
                if idle_secs >= idle_timeout_secs {
                    log::debug!(peer = %peer_addr, idle_secs = idle_secs, "UDP connection idle timeout");
                    break;
                }
            }

            // Handle cancellation
            _ = cancel_token.cancelled() => {
                log::debug!(peer = %peer_addr, "UDP connection kicked by admin");
                break;
            }
        }
    }

    // Graceful shutdown of the client TCP stream carrying UDP packets
    let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, client_stream.shutdown()).await;

    Ok(())
}

/// Convert AclAddr to Address
fn acl_addr_to_address(addr: &acl::Addr) -> Address {
    use std::net::{Ipv4Addr, Ipv6Addr};

    // Try to parse as IP address first
    if let Ok(ipv4) = addr.host().parse::<Ipv4Addr>() {
        return Address::IPv4(ipv4.octets(), addr.port());
    }
    if let Ok(ipv6) = addr.host().parse::<Ipv6Addr>() {
        return Address::IPv6(ipv6.octets(), addr.port());
    }
    // Otherwise treat as domain
    Address::Domain(addr.host().to_string(), addr.port())
}

#[cfg(test)]
mod tests {
    use super::*;
    use acl::Addr as AclAddr;

    #[test]
    fn test_acl_addr_to_address_ipv4() {
        let acl_addr = AclAddr::new("192.168.1.1", 8080);
        let addr = acl_addr_to_address(&acl_addr);
        assert!(matches!(addr, Address::IPv4([192, 168, 1, 1], 8080)));
    }

    #[test]
    fn test_acl_addr_to_address_ipv6() {
        let acl_addr = AclAddr::new("::1", 443);
        let addr = acl_addr_to_address(&acl_addr);
        match addr {
            Address::IPv6(ip, port) => {
                assert_eq!(port, 443);
                assert_eq!(ip, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            }
            _ => panic!("Expected IPv6 address"),
        }
    }

    #[test]
    fn test_acl_addr_to_address_ipv6_full() {
        let acl_addr = AclAddr::new("2001:db8::1", 80);
        let addr = acl_addr_to_address(&acl_addr);
        assert!(matches!(addr, Address::IPv6(_, 80)));
    }

    #[test]
    fn test_acl_addr_to_address_domain() {
        let acl_addr = AclAddr::new("example.com", 80);
        let addr = acl_addr_to_address(&acl_addr);
        assert!(matches!(addr, Address::Domain(ref d, 80) if d == "example.com"));
    }

    #[test]
    fn test_keepalive_and_shutdown_constants() {
        assert_eq!(TCP_KEEPALIVE_SECS, 15);
        assert_eq!(SHUTDOWN_TIMEOUT, std::time::Duration::from_secs(5));
    }

    #[test]
    fn test_acl_addr_to_address_domain_with_subdomain() {
        let acl_addr = AclAddr::new("sub.example.com", 443);
        let addr = acl_addr_to_address(&acl_addr);
        assert!(matches!(addr, Address::Domain(ref d, 443) if d == "sub.example.com"));
    }

    /// Build a valid Trojan CONNECT request as raw bytes
    fn build_trojan_request(password: &[u8; 56], addr: &Address, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(password);
        buf.extend_from_slice(b"\r\n");
        buf.push(1); // CONNECT
        addr.encode(&mut buf);
        buf.extend_from_slice(b"\r\n");
        buf.extend_from_slice(payload);
        buf
    }

    #[tokio::test]
    async fn test_read_trojan_request_complete_in_one_read() {
        let password = [b'a'; 56];
        let addr = Address::IPv4([127, 0, 0, 1], 8080);
        let raw = build_trojan_request(&password, &addr, b"hello");

        let mut stream: TransportStream = Box::pin(std::io::Cursor::new(raw));
        let mut buf = BytesMut::with_capacity(1024);

        let req = read_trojan_request(&mut stream, &mut buf, 1024)
            .await
            .unwrap();
        assert_eq!(req.password, password);
        assert_eq!(req.cmd, TrojanCmd::Connect);
        assert!(matches!(req.addr, Address::IPv4([127, 0, 0, 1], 8080)));
        assert_eq!(req.payload.as_ref(), b"hello");
    }

    #[tokio::test]
    async fn test_read_trojan_request_empty_connection() {
        let mut stream: TransportStream = Box::pin(std::io::Cursor::new(Vec::new()));
        let mut buf = BytesMut::with_capacity(1024);

        let err = read_trojan_request(&mut stream, &mut buf, 1024)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("closed before receiving"),
            "Expected 'closed before receiving' error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_read_trojan_request_incomplete_connection() {
        // Send partial password then EOF
        let mut stream: TransportStream = Box::pin(std::io::Cursor::new(vec![b'a'; 30]));
        let mut buf = BytesMut::with_capacity(1024);

        let err = read_trojan_request(&mut stream, &mut buf, 1024)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("incomplete request"),
            "Expected 'incomplete request' error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_read_trojan_request_too_large() {
        // Craft a request that looks like it needs more data (valid password + CRLF
        // + valid command + domain ATYP with large length), so the parser keeps
        // reading until the buffer exceeds the size limit.
        let buffer_size = 128;
        let mut data = Vec::new();
        data.extend_from_slice(&[b'a'; 56]); // valid password
        data.extend_from_slice(b"\r\n"); // valid first CRLF
        data.push(1); // CONNECT
        data.push(3); // ATYP_DOMAIN
        data.push(255); // domain length = 255 (will need more data to complete)
                        // Feed enough to exceed buffer_size * 2 without ever completing the domain
        data.extend_from_slice(&vec![b'x'; buffer_size * 2]);

        let mut stream: TransportStream = Box::pin(std::io::Cursor::new(data));
        let mut buf = BytesMut::with_capacity(buffer_size);

        let err = read_trojan_request(&mut stream, &mut buf, buffer_size)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("too large"),
            "Expected 'too large' error, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_read_trojan_request_no_payload() {
        let password = [b'z'; 56];
        let addr = Address::Domain("example.com".to_string(), 443);
        let raw = build_trojan_request(&password, &addr, b"");

        let mut stream: TransportStream = Box::pin(std::io::Cursor::new(raw));
        let mut buf = BytesMut::with_capacity(1024);

        let req = read_trojan_request(&mut stream, &mut buf, 1024)
            .await
            .unwrap();
        assert_eq!(req.password, password);
        assert!(matches!(
            req.addr,
            Address::Domain(ref d, 443) if d == "example.com"
        ));
        assert!(req.payload.is_empty());
    }

    /// Verify that reusing a pre-allocated buffer for UDP recv produces correct
    /// TrojanUdpPacket encoding — stale data beyond `n` bytes must not leak
    /// into the encoded packet.
    #[test]
    fn test_udp_recv_buf_reuse_no_stale_data() {
        // Simulate a reused 64KB buffer (like udp_recv_buf in handle_udp_associate)
        let mut recv_buf = vec![0xFFu8; 65536]; // filled with 0xFF "stale" data

        // --- First "read": 5 bytes ---
        let data1 = b"hello";
        recv_buf[..data1.len()].copy_from_slice(data1);
        let n1 = data1.len();

        let addr1 = Address::IPv4([8, 8, 8, 8], 53);
        let encoded1 = TrojanUdpPacket::encode(&addr1, &recv_buf[..n1]);

        // Decode and verify only "hello" is in the payload, no stale 0xFF
        match TrojanUdpPacket::decode(&encoded1) {
            DecodeResult::Ok(pkt, _) => {
                assert_eq!(pkt.payload.as_ref(), b"hello");
                assert_eq!(pkt.payload.len(), 5);
            }
            _ => panic!("Failed to decode first packet"),
        }

        // --- Second "read": 3 bytes (shorter than first) ---
        // Bytes 3..5 still contain 'l','o' from the first read — stale data
        let data2 = b"bye";
        recv_buf[..data2.len()].copy_from_slice(data2);
        let n2 = data2.len();

        let addr2 = Address::Domain("dns.example.com".to_string(), 53);
        let encoded2 = TrojanUdpPacket::encode(&addr2, &recv_buf[..n2]);

        match TrojanUdpPacket::decode(&encoded2) {
            DecodeResult::Ok(pkt, _) => {
                // Must be "bye" only, NOT "byelo" or anything longer
                assert_eq!(pkt.payload.as_ref(), b"bye");
                assert_eq!(pkt.payload.len(), 3);
            }
            _ => panic!("Failed to decode second packet"),
        }

        // --- Third "read": large payload ---
        let data3 = vec![0xABu8; 1024];
        recv_buf[..data3.len()].copy_from_slice(&data3);
        let n3 = data3.len();

        let addr3 = Address::IPv4([1, 1, 1, 1], 443);
        let encoded3 = TrojanUdpPacket::encode(&addr3, &recv_buf[..n3]);

        match TrojanUdpPacket::decode(&encoded3) {
            DecodeResult::Ok(pkt, _) => {
                assert_eq!(pkt.payload.len(), 1024);
                assert!(pkt.payload.iter().all(|&b| b == 0xAB));
            }
            _ => panic!("Failed to decode third packet"),
        }
    }
}
