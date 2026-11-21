//! Reede egress proxy — the single, allowlist-gated next-hop for a sandbox.
//!
//! # Where this sits in the S10 enforcement model
//!
//! The isolation floor ([`crate::isolation::GvisorBackend`] in `ProxyGated`
//! mode) puts each task sandbox on a **`--internal` docker network**. An
//! internal network has no default route to the outside world, so at the
//! **namespace layer** the sandbox physically cannot reach any external IP: a
//! raw socket or a direct-IP connect has nowhere to go. The *only* host the
//! sandbox can reach is this proxy, which is bound to that network's gateway
//! address (the host side of the docker bridge).
//!
//! This module is what makes that single reachable next-hop *selective*:
//!
//! * [`EgressProxy::serve_connect`] terminates HTTP `CONNECT` and lets a stream
//!   through only when its destination host is on the allowlist.
//! * [`EgressProxy::serve_dns`] answers the sandbox's DNS (the sandbox is
//!   launched with `--dns <gateway>`), forwarding only allowlisted names to a
//!   real upstream resolver and returning `REFUSED` for everything else.
//!
//! Every denial — CONNECT, DNS, or a raw non-CONNECT stream — fires the
//! [`FlagToHuman`] hook so the block is never silent.
//!
//! The proxy runs as part of the reede host process (no custom container image
//! is required); it is host-independent (std/tokio only), preserving the one-way
//! dependency.

use crate::egress::{DeniedEgress, EgressAttemptKind, EgressPolicy, FlagToHuman};
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream, UdpSocket};
use uuid::Uuid;

/// Default TCP port the proxy listens on (for HTTP_PROXY / CONNECT).
pub const DEFAULT_PROXY_PORT: u16 = 13128;
/// DNS is always served on the well-known port so `--dns <gateway>` just works.
pub const DNS_PORT: u16 = 53;
/// Default upstream resolver used to answer *allowlisted* names.
pub const DEFAULT_DNS_UPSTREAM: &str = "1.1.1.1:53";

/// Per-proxy resource bounds. Each sandbox owns a proxy, so these limits also
/// bound one sandbox's connection footprint in the shared host process.
#[derive(Clone, Debug)]
pub struct ProxyLimits {
    pub max_connections: usize,
    pub max_header_bytes: usize,
    pub header_timeout: Duration,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
}

impl Default for ProxyLimits {
    fn default() -> Self {
        Self {
            max_connections: 128,
            max_header_bytes: 4096,
            header_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(60),
        }
    }
}

impl ProxyLimits {
    fn validate(&self) -> Result<(), String> {
        if self.max_connections == 0
            || self.max_connections > tokio::sync::Semaphore::MAX_PERMITS
            || !(32..=65536).contains(&self.max_header_bytes)
            || self.header_timeout.is_zero()
            || self.connect_timeout.is_zero()
            || self.idle_timeout.is_zero()
        {
            return Err("proxy limits must have positive capacity/deadlines and a 32..65536 byte header limit".into());
        }
        Ok(())
    }
}

/// CIDR range used to reject unsafe proxy destinations.
#[derive(Clone, Debug)]
struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

impl IpCidr {
    fn parse(raw: &str) -> Result<Self, String> {
        let (address, prefix) = raw
            .trim()
            .split_once('/')
            .ok_or_else(|| format!("CIDR must include a prefix length: {raw}"))?;
        let network = address
            .parse::<IpAddr>()
            .map_err(|_| format!("invalid CIDR address: {raw}"))?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| format!("invalid CIDR prefix: {raw}"))?;
        let max = if network.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(format!("CIDR prefix out of range: {raw}"));
        }
        Ok(Self { network, prefix })
    }

    fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }
}

const SPECIAL_DENY_CIDRS: &[&str] = &[
    "0.0.0.0/32",
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "224.0.0.0/4",
    "255.255.255.255/32",
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

#[async_trait]
pub trait HostResolver: Send + Sync {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>>;
}

struct TokioHostResolver;

#[async_trait]
impl HostResolver for TokioHostResolver {
    async fn resolve(&self, host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok(lookup_host((host, port)).await?.collect())
    }
}

/// The allowlist-gated egress proxy. Cheap to clone (all fields are `Arc`).
pub struct EgressProxy {
    policy: Arc<dyn EgressPolicy>,
    hook: Arc<dyn FlagToHuman>,
    /// Upstream resolver (`ip:port`) allowlisted DNS queries are forwarded to.
    dns_upstream: String,
    task_id: Option<Uuid>,
    deny_cidrs: Vec<IpCidr>,
    resolver: Arc<dyn HostResolver>,
    limits: ProxyLimits,
}

impl EgressProxy {
    pub fn new(
        policy: Arc<dyn EgressPolicy>,
        hook: Arc<dyn FlagToHuman>,
        dns_upstream: impl Into<String>,
    ) -> Self {
        Self::with_resolver(
            policy,
            hook,
            dns_upstream,
            None,
            &[],
            Arc::new(TokioHostResolver),
        )
        .expect("built-in deny CIDRs are valid")
    }

    pub fn for_task(
        policy: Arc<dyn EgressPolicy>,
        hook: Arc<dyn FlagToHuman>,
        dns_upstream: impl Into<String>,
        task_id: Uuid,
        custom_deny_cidrs: &[String],
    ) -> Result<Self, String> {
        Self::with_resolver(
            policy,
            hook,
            dns_upstream,
            Some(task_id),
            custom_deny_cidrs,
            Arc::new(TokioHostResolver),
        )
    }

    /// Construct with an explicit host resolver. The default constructors use Tokio's
    /// system resolver; this seam lets callers that control resolution preserve the same
    /// post-resolution address checks.
    pub fn for_task_with_resolver(
        policy: Arc<dyn EgressPolicy>,
        hook: Arc<dyn FlagToHuman>,
        dns_upstream: impl Into<String>,
        task_id: Uuid,
        custom_deny_cidrs: &[String],
        resolver: Arc<dyn HostResolver>,
    ) -> Result<Self, String> {
        Self::with_resolver(
            policy,
            hook,
            dns_upstream,
            Some(task_id),
            custom_deny_cidrs,
            resolver,
        )
    }

    fn with_resolver(
        policy: Arc<dyn EgressPolicy>,
        hook: Arc<dyn FlagToHuman>,
        dns_upstream: impl Into<String>,
        task_id: Option<Uuid>,
        custom_deny_cidrs: &[String],
        resolver: Arc<dyn HostResolver>,
    ) -> Result<Self, String> {
        let mut deny_cidrs = SPECIAL_DENY_CIDRS
            .iter()
            .map(|cidr| IpCidr::parse(cidr))
            .collect::<Result<Vec<_>, _>>()?;
        for cidr in custom_deny_cidrs {
            deny_cidrs.push(IpCidr::parse(cidr)?);
        }
        Ok(Self {
            policy,
            hook,
            dns_upstream: dns_upstream.into(),
            task_id,
            deny_cidrs,
            resolver,
            limits: ProxyLimits::default(),
        })
    }

    pub fn with_limits(mut self, limits: ProxyLimits) -> Result<Self, String> {
        limits.validate()?;
        self.limits = limits;
        Ok(self)
    }

    fn denied(&self, kind: EgressAttemptKind, destination: String, reason: &str) {
        self.hook.on_denied(&DeniedEgress {
            task_id: self.task_id,
            kind,
            destination,
            reason: reason.to_string(),
        });
    }

    fn address_is_denied(&self, address: IpAddr) -> bool {
        self.deny_cidrs.iter().any(|cidr| cidr.contains(address))
    }

    fn parse_connect_target(target: &str) -> Result<(String, u16), &'static str> {
        if let Some(rest) = target.strip_prefix('[') {
            let (address, suffix) = rest.split_once(']').ok_or("malformed bracketed host")?;
            address
                .parse::<IpAddr>()
                .map_err(|_| "invalid IP literal")?;
            let port = match suffix.strip_prefix(':') {
                Some(raw) => raw.parse::<u16>().map_err(|_| "invalid port")?,
                None if suffix.is_empty() => 443,
                _ => return Err("malformed bracketed host port"),
            };
            return Ok((address.to_string(), port));
        }
        match target.rsplit_once(':') {
            Some((host, raw_port)) if !host.contains(':') => {
                let port = raw_port.parse::<u16>().map_err(|_| "invalid port")?;
                Ok((host.to_string(), port))
            }
            Some(_) => Err("IPv6 literal must be bracketed"),
            None => Ok((target.to_string(), 443)),
        }
    }

    /// Bind the CONNECT proxy on `addr:port` and the DNS filter on `addr:53`,
    /// spawn both accept loops, and return a handle that aborts them together.
    ///
    /// `addr` is the docker network's gateway IP, i.e. the one address the
    /// `--internal` sandbox can reach. Binding there (not `0.0.0.0`) keeps the
    /// proxy off every other interface.
    pub async fn start_on_gateway(
        self: Arc<Self>,
        addr: IpAddr,
        port: u16,
    ) -> std::io::Result<tokio::task::JoinHandle<()>> {
        let tcp = TcpListener::bind(SocketAddr::new(addr, port)).await?;
        let udp = UdpSocket::bind(SocketAddr::new(addr, DNS_PORT)).await?;

        Ok(Self::spawn_on_sockets(self, tcp, udp))
    }

    fn spawn_on_sockets(
        self: Arc<Self>,
        tcp: TcpListener,
        udp: UdpSocket,
    ) -> tokio::task::JoinHandle<()> {
        let connect_proxy = self.clone();
        let dns_proxy = self;
        tokio::spawn(async move {
            // Poll the owned loops directly so cancelling this task drops both
            // listeners. Each loop also owns its accepted connection tasks.
            tokio::select! {
                _ = connect_proxy.serve_connect(tcp) => {}
                _ = dns_proxy.serve_dns(udp) => {}
            }
        })
    }

    /// Accept loop for the HTTP `CONNECT` proxy.
    pub async fn serve_connect(self: Arc<Self>, listener: TcpListener) {
        let mut connections = tokio::task::JoinSet::new();
        let capacity = Arc::new(tokio::sync::Semaphore::new(self.limits.max_connections));
        loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((stream, _peer)) => {
                        let Ok(permit) = capacity.clone().try_acquire_owned() else {
                            self.denied(EgressAttemptKind::Connect, "proxy".into(), "connection limit exceeded");
                            drop(stream);
                            continue;
                        };
                        let me = self.clone();
                        connections.spawn(async move {
                            let _permit = permit;
                            if let Err(e) = me.handle_connect(stream).await {
                                tracing::debug!("egress proxy connect handling error: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::debug!("egress proxy accept error: {e}");
                        break;
                    }
                },
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    }

    /// Accept loop for the filtering DNS resolver (UDP).
    pub async fn serve_dns(self: Arc<Self>, sock: UdpSocket) {
        let mut buf = [0u8; 1500];
        loop {
            let (n, peer) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    tracing::debug!("egress DNS recv error: {e}");
                    break;
                }
            };
            if let Some(reply) = self.answer_dns(&buf[..n]).await {
                let _ = sock.send_to(&reply, peer).await;
            }
        }
    }

    /// Handle one CONNECT request: allow only validated addresses and ports.
    async fn handle_connect(&self, mut client: TcpStream) -> std::io::Result<()> {
        let (header, header_end) = tokio::time::timeout(self.limits.header_timeout, async {
            let mut bytes = Vec::new();
            loop {
                let remaining = self.limits.max_header_bytes.saturating_sub(bytes.len());
                if remaining == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "CONNECT header too large",
                    ));
                }
                let mut chunk = [0u8; 1024];
                let size = remaining.min(chunk.len());
                let n = client.read(&mut chunk[..size]).await?;
                if n == 0 {
                    return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
                }
                let search_from = bytes.len().saturating_sub(3);
                bytes.extend_from_slice(&chunk[..n]);
                if let Some(at) = bytes[search_from..]
                    .windows(4)
                    .position(|part| part == b"\r\n\r\n")
                {
                    return Ok((bytes, search_from + at + 4));
                }
            }
        })
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "CONNECT header deadline")
        })??;

        let req = String::from_utf8_lossy(&header[..header_end]);
        let first_line = req.lines().next().unwrap_or("");
        let parts: Vec<&str> = first_line.split_whitespace().collect();
        if parts.len() < 2 || parts[0] != "CONNECT" {
            self.denied(
                EgressAttemptKind::RawSocket,
                first_line.chars().take(64).collect(),
                "non-CONNECT stream at egress proxy",
            );
            client
                .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                .await?;
            return Ok(());
        }

        let target = parts[1];
        let (host, port) = match Self::parse_connect_target(target) {
            Ok((host, port)) if port != 0 => (host, port),
            _ => {
                self.denied(
                    EgressAttemptKind::Connect,
                    target.to_string(),
                    "invalid CONNECT target or port",
                );
                client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
                return Ok(());
            }
        };
        if !self.policy.is_allowed_connect(&host, port) {
            self.denied(
                EgressAttemptKind::Connect,
                target.to_string(),
                "destination not on egress allowlist",
            );
            client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
            return Ok(());
        }

        let addresses = match tokio::time::timeout(
            self.limits.connect_timeout,
            self.resolver.resolve(&host, port),
        )
        .await
        {
            Ok(Ok(addresses)) if !addresses.is_empty() => addresses,
            _ => {
                client
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    .await?;
                return Ok(());
            }
        };
        if addresses
            .iter()
            .any(|address| self.address_is_denied(address.ip()))
        {
            self.denied(
                EgressAttemptKind::Connect,
                target.to_string(),
                "resolved to a denied address",
            );
            client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
            return Ok(());
        }

        let upstream = tokio::time::timeout(self.limits.connect_timeout, async {
            for address in addresses {
                if let Ok(stream) = TcpStream::connect(address).await {
                    return Some(stream);
                }
            }
            None
        })
        .await
        .ok()
        .flatten();
        let Some(mut upstream) = upstream else {
            client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await?;
            return Ok(());
        };

        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        if header_end < header.len() {
            tokio::time::timeout(
                self.limits.idle_timeout,
                upstream.write_all(&header[header_end..]),
            )
            .await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
        }
        relay_with_idle_deadline(&mut client, &mut upstream, self.limits.idle_timeout).await?;
        Ok(())
    }

    /// Produce a DNS reply for one query: forward allowlisted names upstream,
    /// return `REFUSED` (and flag) for anything else.
    async fn answer_dns(&self, query: &[u8]) -> Option<Vec<u8>> {
        let qname = parse_qname(query)?;

        if !self.policy.is_allowed(&qname) {
            self.denied(
                EgressAttemptKind::Dns,
                qname.clone(),
                "DNS name not on egress allowlist",
            );
            tracing::warn!(qname = %qname, "egress DNS DENIED (REFUSED)");
            return Some(build_refused(query));
        }

        // Allowlisted: forward to the upstream resolver and relay the answer.
        match self.forward_dns(query).await {
            Ok(resp) => Some(resp),
            Err(e) => {
                tracing::warn!(qname = %qname, "egress DNS upstream forward failed: {e}");
                Some(build_servfail(query))
            }
        }
    }

    async fn forward_dns(&self, query: &[u8]) -> std::io::Result<Vec<u8>> {
        // Bind an ephemeral local socket; the proxy host (not the sandbox) has a
        // real route to the upstream resolver.
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(&self.dns_upstream).await?;
        sock.send(query).await?;
        let mut buf = vec![0u8; 1500];
        let n = tokio::time::timeout(std::time::Duration::from_secs(3), sock.recv(&mut buf))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream DNS timeout")
            })??;
        buf.truncate(n);
        Ok(buf)
    }
}

// ---------------------------------------------------------------------------
// Minimal DNS wire helpers (no external DNS crate; keeps the one-way rule intact).
// ---------------------------------------------------------------------------

/// A shared activity deadline allows one-way traffic while bounding idle tunnels.
async fn relay_with_idle_deadline(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    idle: Duration,
) -> std::io::Result<()> {
    let (mut cr, mut cw) = client.split();
    let (mut ur, mut uw) = upstream.split();
    let (mut cb, mut ub) = ([0u8; 16384], [0u8; 16384]);
    let (mut co, mut uo) = (true, true);
    while co || uo {
        let (from_client, count) = tokio::time::timeout(idle, async {
            tokio::select! {
                n = cr.read(&mut cb), if co => n.map(|n| (true, n)),
                n = ur.read(&mut ub), if uo => n.map(|n| (false, n)),
            }
        })
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "tunnel idle deadline"))??;
        tokio::time::timeout(idle, async {
            if from_client {
                if count == 0 {
                    co = false;
                    uw.shutdown().await
                } else {
                    uw.write_all(&cb[..count]).await
                }
            } else if count == 0 {
                uo = false;
                cw.shutdown().await
            } else {
                cw.write_all(&ub[..count]).await
            }
        })
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "tunnel write deadline")
        })??;
    }
    Ok(())
}

/// Validate a single-question standard DNS query and extract its dotted name.
///
/// The entire forwarded message must fit the authorization decision: additional
/// questions, response/update opcodes and ambiguous labels are rejected. One
/// EDNS OPT record is supported; arbitrary additional records are not forwarded.
pub fn parse_qname(pkt: &[u8]) -> Option<String> {
    if pkt.len() < 12
        || pkt[2] & 0xfe != 0 // only RD is meaningful in the first query flag byte
        || pkt[3] & 0xcf != 0 // allow AD/CD, reject RA/reserved/RCODE
        || pkt[4..6] != [0, 1]
        || pkt[6..10] != [0, 0, 0, 0]
        || pkt[10] != 0
        || pkt[11] > 1
    {
        return None;
    }
    let mut pos = 12usize;
    let mut labels: Vec<&str> = Vec::new();
    loop {
        let len = *pkt.get(pos)? as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None; // compression and extended labels are unsupported
        }
        let end = pos.checked_add(len)?;
        let label = pkt.get(pos..end)?;
        if !label
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        {
            return None; // literal dots/escapes must not collapse into another name
        }
        labels.push(std::str::from_utf8(label).ok()?);
        pos = end;
    }
    if labels.is_empty() || pos - 12 > 255 {
        return None;
    }
    let question = pkt.get(pos..pos.checked_add(4)?)?;
    if question[..2] == [0, 0] || question[2..] != [0, 1] {
        return None; // nonzero QTYPE, Internet class only
    }
    pos += 4;
    if pkt[11] == 1 {
        // OPT: root owner, type 41, UDP size, extended flags, bounded RDATA.
        let opt = pkt.get(pos..pos.checked_add(11)?)?;
        if opt[..3] != [0, 0, 41] {
            return None;
        }
        let data_len = u16::from_be_bytes([opt[9], opt[10]]) as usize;
        pos = pos.checked_add(11)?.checked_add(data_len)?;
    }
    if pos != pkt.len() {
        return None;
    }
    Some(labels.join(".").to_ascii_lowercase())
}

/// Echo the query's header+question with QR=1 and RCODE set, ANCOUNT/NS/AR = 0.
fn build_error_reply(query: &[u8], rcode: u8) -> Vec<u8> {
    // Length of header + question (up to and including the null label + QTYPE +
    // QCLASS). Fall back to the raw header if we cannot find the question end.
    let q_end = question_end(query).unwrap_or(query.len().min(12));
    let mut resp = query[..q_end].to_vec();
    if resp.len() < 12 {
        resp.resize(12, 0);
    }
    resp[2] |= 0x80; // QR = 1 (response)
    resp[3] = (resp[3] & 0xF0) | (rcode & 0x0F); // set RCODE
                                                 // ANCOUNT, NSCOUNT, ARCOUNT = 0
    for byte in resp.iter_mut().take(12).skip(6) {
        *byte = 0;
    }
    resp
}

/// RCODE 5 = REFUSED (policy denial).
pub fn build_refused(query: &[u8]) -> Vec<u8> {
    build_error_reply(query, 5)
}

/// RCODE 2 = SERVFAIL (upstream failure on an otherwise-allowed name).
pub fn build_servfail(query: &[u8]) -> Vec<u8> {
    build_error_reply(query, 2)
}

/// Byte offset just past the question section (QNAME + QTYPE + QCLASS).
fn question_end(pkt: &[u8]) -> Option<usize> {
    if pkt.len() < 12 {
        return None;
    }
    let mut pos = 12usize;
    loop {
        let len = *pkt.get(pos)? as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        pos += 1 + len;
    }
    // + QTYPE (2) + QCLASS (2)
    let end = pos + 4;
    if end <= pkt.len() {
        Some(end)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::egress::AllowlistEgress;
    use std::sync::Mutex;

    struct RecordingHook(Mutex<Vec<DeniedEgress>>);
    impl RecordingHook {
        fn new() -> Arc<Self> {
            Arc::new(Self(Mutex::new(Vec::new())))
        }
        fn events(&self) -> Vec<DeniedEgress> {
            self.0.lock().unwrap().clone()
        }
    }
    impl FlagToHuman for RecordingHook {
        fn on_denied(&self, event: &DeniedEgress) {
            self.0.lock().unwrap().push(event.clone());
        }
    }

    struct PendingResolver {
        entered: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl HostResolver for PendingResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
            self.entered.notify_one();
            std::future::pending::<std::io::Result<Vec<SocketAddr>>>().await
        }
    }

    struct FixedResolver {
        addresses: Vec<SocketAddr>,
        calls: Mutex<usize>,
    }

    #[async_trait]
    impl HostResolver for FixedResolver {
        async fn resolve(&self, _host: &str, _port: u16) -> std::io::Result<Vec<SocketAddr>> {
            *self.calls.lock().unwrap() += 1;
            Ok(self.addresses.clone())
        }
    }

    async fn send_connect(proxy: Arc<EgressProxy>, target: &str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            proxy.handle_connect(stream).await.unwrap();
        });
        let mut client = TcpStream::connect(address).await.unwrap();
        client
            .write_all(format!("CONNECT {target} HTTP/1.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = [0u8; 128];
        let n = client.read(&mut response).await.unwrap();
        server.await.unwrap();
        String::from_utf8_lossy(&response[..n]).into_owned()
    }

    #[test]
    fn proxy_limits_reject_zero_or_unbounded_configuration() {
        let mut limits = ProxyLimits::default();
        assert!(limits.validate().is_ok());
        limits.max_connections = 0;
        assert!(limits.validate().is_err());
        limits.max_connections = 1;
        limits.header_timeout = Duration::ZERO;
        assert!(limits.validate().is_err());
    }

    #[tokio::test]
    async fn fragmented_headers_are_parsed_and_slow_headers_expire() {
        let limits = ProxyLimits {
            header_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let proxy = Arc::new(
            EgressProxy::new(
                Arc::new(AllowlistEgress::new(vec![])),
                RecordingHook::new(),
                DEFAULT_DNS_UPSTREAM,
            )
            .with_limits(limits)
            .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn({
            let proxy = proxy.clone();
            async move {
                let (stream, _) = listener.accept().await.unwrap();
                proxy.handle_connect(stream).await
            }
        });
        let mut client = TcpStream::connect(addr).await.unwrap();
        for fragment in [
            b"CON".as_slice(),
            b"NECT blocked.example:443 HTTP/1.1\r\n",
            b"\r\n",
        ] {
            client.write_all(fragment).await.unwrap();
        }
        let mut response = [0u8; 128];
        let n = client.read(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response[..n]).contains("403"));
        assert!(server.await.unwrap().is_ok());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            proxy.handle_connect(stream).await
        });
        let _client = TcpStream::connect(addr).await.unwrap();
        let error = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn saturated_proxy_refuses_more_connections_and_reclaims_slots() {
        let hook = RecordingHook::new();
        let limits = ProxyLimits {
            max_connections: 1,
            header_timeout: Duration::from_millis(100),
            ..Default::default()
        };
        let proxy = Arc::new(
            EgressProxy::new(
                Arc::new(AllowlistEgress::new(vec![])),
                hook.clone(),
                DEFAULT_DNS_UPSTREAM,
            )
            .with_limits(limits)
            .unwrap(),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(proxy.serve_connect(listener));
        let mut first = TcpStream::connect(addr).await.unwrap();
        first.write_all(b"C").await.unwrap();
        // Wait for admission without depending on scheduler ordering.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let mut second = TcpStream::connect(addr).await.unwrap();
        let mut byte = [0];
        let result = tokio::time::timeout(Duration::from_secs(1), second.read(&mut byte))
            .await
            .unwrap();
        assert!(matches!(result, Ok(0) | Err(_)));
        assert!(hook
            .events()
            .iter()
            .any(|event| event.reason == "connection limit exceeded"));
        let _ = tokio::time::timeout(Duration::from_secs(1), first.read(&mut byte))
            .await
            .unwrap();
        let mut third = TcpStream::connect(addr).await.unwrap();
        third
            .write_all(b"CONNECT blocked.example:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut response = [0; 128];
        let n = third.read(&mut response).await.unwrap();
        assert!(String::from_utf8_lossy(&response[..n]).contains("403"));
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn adversarial_f_refuses_any_resolved_address_in_custom_denied_cidr_and_records_task() {
        let hook = RecordingHook::new();
        let resolver = Arc::new(FixedResolver {
            addresses: vec![
                "203.0.113.7:443".parse().unwrap(),
                "203.0.114.9:443".parse().unwrap(),
            ],
            calls: Mutex::new(0),
        });
        let proxy = Arc::new(
            EgressProxy::with_resolver(
                Arc::new(AllowlistEgress::new(vec!["api.example.eu".to_string()])),
                hook.clone(),
                DEFAULT_DNS_UPSTREAM,
                Some(Uuid::from_u128(42)),
                &["203.0.113.0/24".to_string()],
                resolver.clone(),
            )
            .unwrap(),
        );
        let response = send_connect(proxy, "api.example.eu:443").await;
        assert!(response.contains("403"));
        let events = hook.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].task_id, Some(Uuid::from_u128(42)));
        assert_eq!(events[0].reason, "resolved to a denied address");
        assert_eq!(*resolver.calls.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn connect_denies_unspecified_addresses_and_records_task() {
        for raw_address in ["0.0.0.0:443", "[::]:443"] {
            let hook = RecordingHook::new();
            let resolver = Arc::new(FixedResolver {
                addresses: vec![raw_address.parse().unwrap()],
                calls: Mutex::new(0),
            });
            let task_id = Uuid::from_u128(43);
            let proxy = Arc::new(
                EgressProxy::for_task_with_resolver(
                    Arc::new(AllowlistEgress::new(vec!["api.example.eu".to_string()])),
                    hook.clone(),
                    DEFAULT_DNS_UPSTREAM,
                    task_id,
                    &[],
                    resolver,
                )
                .unwrap(),
            );
            let response = send_connect(proxy, "api.example.eu:443").await;
            assert!(
                response.contains("403 Forbidden"),
                "{raw_address}: {response}"
            );
            let events = hook.events();
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].task_id, Some(task_id));
            assert_eq!(events[0].reason, "resolved to a denied address");
        }
    }

    #[test]
    fn mandatory_special_ranges_and_custom_cidrs_are_combined() {
        let proxy = EgressProxy::with_resolver(
            Arc::new(AllowlistEgress::new(vec![])),
            RecordingHook::new(),
            DEFAULT_DNS_UPSTREAM,
            None,
            &["203.0.113.0/24".to_string()],
            Arc::new(FixedResolver {
                addresses: vec![],
                calls: Mutex::new(0),
            }),
        )
        .unwrap();
        assert!(proxy.address_is_denied("0.0.0.0".parse().unwrap()));
        assert!(proxy.address_is_denied("255.255.255.255".parse().unwrap()));
        assert!(proxy.address_is_denied("224.0.0.1".parse().unwrap()));
        assert!(proxy.address_is_denied("::".parse().unwrap()));
        assert!(proxy.address_is_denied("ff02::1".parse().unwrap()));
        assert!(proxy.address_is_denied("127.0.0.1".parse().unwrap()));
        assert!(proxy.address_is_denied("10.2.3.4".parse().unwrap()));
        assert!(proxy.address_is_denied("100.64.0.1".parse().unwrap()));
        assert!(proxy.address_is_denied("fc00::1".parse().unwrap()));
        assert!(proxy.address_is_denied("203.0.113.9".parse().unwrap()));
        assert!(!proxy.address_is_denied("203.0.114.9".parse().unwrap()));
    }

    #[test]
    fn malformed_custom_cidr_fails_proxy_construction() {
        let result = EgressProxy::for_task(
            Arc::new(AllowlistEgress::new(vec![])),
            RecordingHook::new(),
            DEFAULT_DNS_UPSTREAM,
            Uuid::from_u128(42),
            &["not-a-cidr".to_string()],
        );
        assert!(result.err().unwrap().contains("CIDR"));
    }

    #[tokio::test]
    async fn malformed_and_out_of_range_ports_are_refused() {
        for target in [
            "api.example.eu:0",
            "api.example.eu:65536",
            "api.example.eu:notaport",
        ] {
            let hook = RecordingHook::new();
            let resolver = Arc::new(FixedResolver {
                addresses: vec![],
                calls: Mutex::new(0),
            });
            let proxy = Arc::new(
                EgressProxy::with_resolver(
                    Arc::new(AllowlistEgress::new(vec!["api.example.eu".to_string()])),
                    hook.clone(),
                    DEFAULT_DNS_UPSTREAM,
                    None,
                    &[],
                    resolver.clone(),
                )
                .unwrap(),
            );
            let response = send_connect(proxy, target).await;
            assert!(
                response.contains("403"),
                "invalid target must be refused: {target}"
            );
            assert_eq!(*resolver.calls.lock().unwrap(), 0);
            assert_eq!(hook.events()[0].reason, "invalid CONNECT target or port");
        }
    }

    #[tokio::test]
    async fn host_only_allowlist_refuses_port_22_before_resolving() {
        let hook = RecordingHook::new();
        let resolver = Arc::new(FixedResolver {
            addresses: vec!["203.0.113.7:22".parse().unwrap()],
            calls: Mutex::new(0),
        });
        let proxy = Arc::new(
            EgressProxy::with_resolver(
                Arc::new(AllowlistEgress::new(vec!["api.example.eu".to_string()])),
                hook.clone(),
                DEFAULT_DNS_UPSTREAM,
                Some(Uuid::from_u128(7)),
                &[],
                resolver.clone(),
            )
            .unwrap(),
        );
        let response = send_connect(proxy, "api.example.eu:22").await;
        assert!(response.contains("403"));
        assert_eq!(*resolver.calls.lock().unwrap(), 0);
        assert_eq!(
            hook.events()[0].reason,
            "destination not on egress allowlist"
        );
    }

    /// Build a minimal DNS query packet for `name` (A/IN), id 0x1234.
    fn dns_query(name: &str) -> Vec<u8> {
        let mut pkt = vec![
            0x12, 0x34, // id
            0x01, 0x00, // flags: RD
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN/NS/AR = 0
        ];
        for label in name.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0); // root label
        pkt.extend_from_slice(&[0x00, 0x01]); // QTYPE = A
        pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN
        pkt
    }

    #[test]
    fn parse_qname_reads_the_question() {
        let pkt = dns_query("api.example.eu");
        assert_eq!(parse_qname(&pkt).as_deref(), Some("api.example.eu"));
    }

    #[test]
    fn parse_qname_lowercases_and_rejects_garbage() {
        let pkt = dns_query("API.Example.EU");
        assert_eq!(parse_qname(&pkt).as_deref(), Some("api.example.eu"));
        assert_eq!(parse_qname(&[0u8; 4]), None); // too short
    }

    #[test]
    fn dns_policy_rejects_unchecked_questions_and_nonquery_messages() {
        let query = dns_query("api.example.eu");
        let mut two_questions = query.clone();
        two_questions[5] = 2;
        two_questions.extend_from_slice(&dns_query("blocked.example")[12..]);
        assert_eq!(parse_qname(&two_questions), None);
        for (offset, value) in [(2, 0x81), (2, 0x29), (5, 0), (7, 1), (9, 1)] {
            let mut malformed = query.clone();
            malformed[offset] = value;
            assert_eq!(parse_qname(&malformed), None, "offset {offset}");
        }
        assert_eq!(parse_qname(&query[..query.len() - 1]), None);
        let mut trailing = query.clone();
        trailing.push(0);
        assert_eq!(parse_qname(&trailing), None);
    }

    #[test]
    fn dns_policy_preserves_edns_and_rejects_ambiguous_wire_labels() {
        let mut query = dns_query("api.example.eu");
        query[11] = 1;
        query.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
        assert_eq!(parse_qname(&query).as_deref(), Some("api.example.eu"));
        *query.last_mut().unwrap() = 1; // RDLENGTH exceeds the packet
        assert_eq!(parse_qname(&query), None);

        let mut ambiguous = dns_query("api.example.eu");
        ambiguous.truncate(12);
        ambiguous.push(14); // one literal-dot label is not three DNS labels
        ambiguous.extend_from_slice(b"api.example.eu");
        ambiguous.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert_eq!(parse_qname(&ambiguous), None);
    }

    #[test]
    fn security_property_dns_valid_names_roundtrip_and_all_truncations_fail_closed() {
        use rand::{rngs::StdRng, Rng, SeedableRng};
        let mut rng = StdRng::seed_from_u64(0x72656564652d646e);
        for _ in 0..512 {
            let labels = (0..rng.gen_range(1..=4))
                .map(|_| {
                    (0..rng.gen_range(1..=48))
                        .map(|_| char::from(b'A' + rng.gen_range(0..26)))
                        .collect::<String>()
                })
                .collect::<Vec<_>>();
            let name = labels.join(".");
            let query = dns_query(&name);
            assert_eq!(parse_qname(&query), Some(name.to_ascii_lowercase()));
            for end in 0..query.len() {
                assert_eq!(parse_qname(&query[..end]), None, "truncated at {end}");
            }
            let mut trailing = query.clone();
            trailing.extend((0..rng.gen_range(1..=32)).map(|_| rng.gen::<u8>()));
            assert_eq!(parse_qname(&trailing), None);
            for count in [0u16, 2, 255, 256, u16::MAX] {
                let mut changed = query.clone();
                changed[4..6].copy_from_slice(&count.to_be_bytes());
                assert_eq!(parse_qname(&changed), None);
            }
        }
        // Exactly 255 wire bytes, then two bytes beyond the protocol name limit.
        let valid = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        assert!(parse_qname(&dns_query(&valid)).is_some());
        let invalid = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(63),
        ]
        .join(".");
        assert!(parse_qname(&dns_query(&invalid)).is_none());
    }

    #[test]
    fn security_property_dns_edns_payload_bounds_and_arbitrary_packets_never_panic() {
        use rand::{rngs::StdRng, Rng, RngCore, SeedableRng};
        let mut rng = StdRng::seed_from_u64(0x72656564652d6f70);
        for len in 0..256usize {
            let mut query = dns_query("api.example.eu");
            query[11] = 1;
            query.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0]);
            query.extend_from_slice(&(len as u16).to_be_bytes());
            let mut data = vec![0; len];
            rng.fill_bytes(&mut data);
            query.extend_from_slice(&data);
            assert_eq!(parse_qname(&query).as_deref(), Some("api.example.eu"));
            assert!(parse_qname(&query[..query.len() - 1]).is_none());
            query.push(0);
            assert!(parse_qname(&query).is_none());
        }
        for _ in 0..4096 {
            let mut bytes = vec![0; rng.gen_range(0..=1500)];
            rng.fill_bytes(&mut bytes);
            if let Some(name) = parse_qname(&bytes) {
                assert!(!name.is_empty());
                assert!(name.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || matches!(b, b'.' | b'-' | b'_')));
            }
        }
    }

    #[test]
    fn security_property_connect_authority_and_ports_remain_distinct_from_dns_allowance() {
        let policy = AllowlistEgress::new(vec!["api.example.eu".into()]);
        for port in [1, 22, 80, 443, 8443, 65535] {
            let target = format!("api.example.eu:{port}");
            assert_eq!(
                EgressProxy::parse_connect_target(&target).unwrap(),
                ("api.example.eu".into(), port)
            );
            assert_eq!(
                policy.is_allowed_connect("api.example.eu", port),
                port == 443
            );
        }
        for target in [
            "api.example.eu:65536",
            "api.example.eu:-1",
            "api.example.eu:443@elsewhere",
            "::1:443",
            "[::1]junk",
            "[::1]:443:22",
            "[not-an-address]:443",
        ] {
            assert!(
                EgressProxy::parse_connect_target(target).is_err(),
                "{target}"
            );
        }
        for address in ["[::1]:443", "[::ffff:127.0.0.1]:443", "[127.0.0.1]:443"] {
            let (host, port) = EgressProxy::parse_connect_target(address).unwrap();
            assert!(!policy.is_allowed_connect(&host, port));
        }
    }

    #[test]
    fn refused_reply_sets_qr_and_rcode() {
        let q = dns_query("evil.example.com");
        let r = build_refused(&q);
        assert_eq!(&r[0..2], &q[0..2], "must echo the query id");
        assert_eq!(r[2] & 0x80, 0x80, "QR bit set");
        assert_eq!(r[3] & 0x0F, 5, "RCODE = REFUSED");
        // No answers claimed.
        assert_eq!(&r[6..8], &[0, 0]);
    }

    #[tokio::test]
    async fn abort_releases_both_listeners_and_accepted_connect_tasks() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let proxy = Arc::new(
            EgressProxy::for_task_with_resolver(
                Arc::new(AllowlistEgress::new(vec!["api.example.eu".to_string()])),
                RecordingHook::new(),
                DEFAULT_DNS_UPSTREAM,
                Uuid::from_u128(9),
                &[],
                Arc::new(PendingResolver {
                    entered: entered.clone(),
                }),
            )
            .unwrap(),
        );
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_addr = tcp.local_addr().unwrap();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp.local_addr().unwrap();
        let handle = proxy.spawn_on_sockets(tcp, udp);

        let mut client = TcpStream::connect(tcp_addr).await.unwrap();
        client
            .write_all(b"CONNECT api.example.eu:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), entered.notified())
            .await
            .expect("accepted CONNECT task did not enter resolver");
        handle.abort();
        let _ = handle.await;
        let mut byte = [0u8; 1];
        let closed =
            tokio::time::timeout(std::time::Duration::from_secs(1), client.read(&mut byte))
                .await
                .expect("accepted connection did not close after abort");
        assert!(
            matches!(closed, Ok(0))
                || matches!(closed, Err(ref error) if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::BrokenPipe
                )),
            "accepted CONNECT task must close cleanly or with a close-related error: {closed:?}"
        );
        drop(client);
        assert!(
            TcpListener::bind(tcp_addr).await.is_ok(),
            "CONNECT listener remained bound after abort"
        );
        assert!(
            UdpSocket::bind(udp_addr).await.is_ok(),
            "DNS listener remained bound after abort"
        );
    }

    #[tokio::test]
    async fn answer_dns_refuses_and_flags_off_allowlist_names() {
        let policy = Arc::new(AllowlistEgress::new(vec!["api.example.eu".to_string()]));
        let hook = RecordingHook::new();
        let proxy = EgressProxy::new(policy, hook.clone(), DEFAULT_DNS_UPSTREAM);

        let reply = proxy
            .answer_dns(&dns_query("tracker.evil.com"))
            .await
            .expect("a reply is produced");
        assert_eq!(reply[3] & 0x0F, 5, "denied name gets REFUSED");

        let events = hook.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EgressAttemptKind::Dns);
        assert_eq!(events[0].destination, "tracker.evil.com");
    }

    #[tokio::test]
    async fn handle_connect_denies_off_allowlist_and_flags() {
        let policy = Arc::new(AllowlistEgress::new(vec!["api.example.eu".to_string()]));
        let hook = RecordingHook::new();
        let proxy = Arc::new(EgressProxy::new(policy, hook.clone(), DEFAULT_DNS_UPSTREAM));

        // Bind a loopback listener and drive one CONNECT through it.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            proxy.handle_connect(stream).await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"CONNECT evil.example.com:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut resp = [0u8; 64];
        let n = client.read(&mut resp).await.unwrap();
        let resp = String::from_utf8_lossy(&resp[..n]);
        assert!(resp.contains("403"), "off-allowlist CONNECT is 403: {resp}");

        server.await.unwrap();
        let events = hook.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EgressAttemptKind::Connect);
        assert_eq!(events[0].destination, "evil.example.com:443");
    }

    #[tokio::test]
    async fn handle_connect_flags_non_connect_raw_stream() {
        let policy = Arc::new(AllowlistEgress::new(vec!["api.example.eu".to_string()]));
        let hook = RecordingHook::new();
        let proxy = Arc::new(EgressProxy::new(policy, hook.clone(), DEFAULT_DNS_UPSTREAM));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            proxy.handle_connect(stream).await.unwrap();
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        // A raw HTTP GET (not CONNECT) — a stand-in for a non-proxy stream.
        client
            .write_all(b"GET http://evil.example.com/ HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut resp = [0u8; 64];
        let _ = client.read(&mut resp).await.unwrap();

        server.await.unwrap();
        let events = hook.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EgressAttemptKind::RawSocket);
    }
}
