use crate::policy::DerivedPolicy;
use std::net::IpAddr;
use uuid::Uuid;

pub trait EgressPolicy: Send + Sync {
    fn is_allowed(&self, destination: &str) -> bool;
    fn blocked_domains(&self) -> &[String];

    /// Host-only entries permit HTTPS. Other ports need an explicit `host:port` entry.
    fn is_allowed_connect(&self, host: &str, port: u16) -> bool {
        port == 443 && self.is_allowed(host)
    }
}

pub struct AllowlistEgress {
    allowlist: Vec<String>,
    blocked_domains: Vec<String>,
}

impl AllowlistEgress {
    pub fn new(allowlist: Vec<String>) -> Self {
        Self {
            allowlist,
            blocked_domains: vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "169.254.169.254".to_string(),
                "metadata.google.internal".to_string(),
            ],
        }
    }

    pub fn from_policy(policy: &DerivedPolicy) -> Self {
        Self::new(policy.egress_allowlist.clone())
    }
}

impl EgressPolicy for AllowlistEgress {
    fn is_allowed(&self, destination: &str) -> bool {
        // Fail closed on empty allowlist (Standing Contract Rule 2)
        if self.allowlist.is_empty() {
            return false;
        }

        let cleaned = destination
            .trim()
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or(destination)
            .split(':')
            .next()
            .unwrap_or(destination);

        // Block explicit metadata/localhost blocked destinations
        if self
            .blocked_domains
            .iter()
            .any(|b| b.eq_ignore_ascii_case(cleaned))
        {
            return false;
        }

        // Block direct IP address bypass attempts
        if cleaned.parse::<IpAddr>().is_ok() {
            return false;
        }

        // Check allowlist matches
        self.allowlist.iter().any(|allowed| {
            let allowed_host = match allowed.rsplit_once(':') {
                Some((host, raw_port))
                    if !host.contains(':') && raw_port.parse::<u16>().is_ok() =>
                {
                    host
                }
                _ => allowed.as_str(),
            };
            if allowed_host.eq_ignore_ascii_case(cleaned) {
                true
            } else if let Some(suffix) = allowed_host.strip_prefix("*.") {
                cleaned.ends_with(&format!(".{suffix}"))
            } else {
                false
            }
        })
    }

    fn is_allowed_connect(&self, host: &str, port: u16) -> bool {
        let cleaned = host.trim().trim_end_matches('.').to_ascii_lowercase();
        if self
            .blocked_domains
            .iter()
            .any(|blocked| blocked.eq_ignore_ascii_case(&cleaned))
            || cleaned.parse::<IpAddr>().is_ok()
        {
            return false;
        }
        self.allowlist.iter().any(|entry| {
            let (entry_host, entry_port) = match entry.rsplit_once(':') {
                Some((entry_host, raw_port)) if !entry_host.contains(':') => {
                    match raw_port.parse::<u16>() {
                        Ok(entry_port) if entry_port != 0 => (entry_host, Some(entry_port)),
                        _ => return false,
                    }
                }
                _ => (entry.as_str(), None),
            };
            let entry_host = entry_host.trim_end_matches('.').to_ascii_lowercase();
            let host_matches = if let Some(suffix) = entry_host.strip_prefix("*.") {
                cleaned.ends_with(&format!(".{suffix}"))
            } else {
                cleaned == entry_host
            };
            host_matches
                && match entry_port {
                    Some(entry_port) => entry_port == port,
                    None => port == 443,
                }
        })
    }

    fn blocked_domains(&self) -> &[String] {
        &self.blocked_domains
    }
}

// ---------------------------------------------------------------------------
// Flag-to-human hook (S10)
// ---------------------------------------------------------------------------
//
// Enforcing egress at the network namespace catches an off-allowlist attempt as
// a *silent* connection failure inside the sandbox. That is correct for safety
// but useless for a human: nobody learns the agent tried to reach somewhere it
// should not. The flag-to-human hook is the event seam that turns every denial
// into something a deployment can act on — a review queue, an alert, a receipt,
// or (in tests) a recorder. It is a callback, deliberately NOT a hard-coded UI,
// so the runtime never assumes how a given operator wants to be told.

/// Which layer of the egress wall caught a denied attempt. Lets the hook (and
/// any audit built on it) distinguish a filtered HTTP CONNECT from a DNS lookup
/// or a raw-socket attempt that arrived at the proxy without a CONNECT verb.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressAttemptKind {
    /// An HTTP/HTTPS `CONNECT` presented to the Reede egress proxy.
    Connect,
    /// A DNS resolution request seen by the Reede DNS filter.
    Dns,
    /// A raw/unknown TCP attempt that reached the proxy without a CONNECT verb.
    RawSocket,
}

/// One denied egress attempt, handed to the [`FlagToHuman`] hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeniedEgress {
    pub task_id: Option<Uuid>,
    pub kind: EgressAttemptKind,
    /// The destination the sandbox tried to reach (host, host:port, or IP).
    pub destination: String,
    /// Why it was denied (not on allowlist, blocked domain, direct-IP bypass…).
    pub reason: String,
}

/// Hook fired whenever the egress wall denies an attempt.
///
/// This is an event sink, not a UI. A deployment supplies its own implementation
/// to route denials wherever it wants (human review, paging, a receipt row); the
/// proxy calls [`FlagToHuman::on_denied`] once per blocked CONNECT / DNS / raw
/// attempt. Implementations must be cheap and non-blocking — they run on the
/// proxy's accept path.
pub trait FlagToHuman: Send + Sync {
    fn on_denied(&self, event: &DeniedEgress);
}

/// Default hook: emits a structured `warn` and drops the event. A safe fallback
/// when no review queue is wired, so a denial is at least never lost silently.
pub struct LoggingFlagToHuman;

impl FlagToHuman for LoggingFlagToHuman {
    fn on_denied(&self, event: &DeniedEgress) {
        tracing::warn!(
            kind = ?event.kind,
            destination = %event.destination,
            reason = %event.reason,
            "FLAG-TO-HUMAN: reede egress wall denied an attempt"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Test hook that records every denial it is handed.
    struct RecordingHook(Mutex<Vec<DeniedEgress>>);
    impl RecordingHook {
        fn new() -> Self {
            Self(Mutex::new(Vec::new()))
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

    #[test]
    fn flag_to_human_hook_fires_and_carries_the_denial() {
        let hook = RecordingHook::new();
        let evt = DeniedEgress {
            task_id: None,
            kind: EgressAttemptKind::Connect,
            destination: "evil.example.com:443".to_string(),
            reason: "not on allowlist".to_string(),
        };
        hook.on_denied(&evt);

        let recorded = hook.events();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].kind, EgressAttemptKind::Connect);
        assert_eq!(recorded[0].destination, "evil.example.com:443");
    }

    #[test]
    fn logging_hook_is_a_usable_default() {
        // Must not panic; it is the fallback when no review queue is wired.
        LoggingFlagToHuman.on_denied(&DeniedEgress {
            task_id: None,
            kind: EgressAttemptKind::Dns,
            destination: "tracker.example.net".to_string(),
            reason: "DNS off-allowlist".to_string(),
        });
    }

    #[test]
    fn connect_ports_require_https_or_an_explicit_allowlist_port() {
        let host_only = AllowlistEgress::new(vec!["api.example.eu".to_string()]);
        assert!(host_only.is_allowed_connect("api.example.eu", 443));
        assert!(!host_only.is_allowed_connect("api.example.eu", 22));
        assert!(!host_only.is_allowed_connect("api.example.eu", 0));

        let explicit = AllowlistEgress::new(vec!["api.example.eu:8443".to_string()]);
        assert!(
            explicit.is_allowed("api.example.eu"),
            "DNS is still needed for an explicit-port host"
        );
        assert!(explicit.is_allowed_connect("api.example.eu", 8443));
        assert!(!explicit.is_allowed_connect("api.example.eu", 443));
        assert!(!explicit.is_allowed_connect("api.example.eu", 22));
    }

    #[test]
    fn test_egress_allowlist_both_directions() {
        let allowlist = vec!["api.example.eu".to_string(), "*.data.eu".to_string()];
        let egress = AllowlistEgress::new(allowlist);

        // 1. Allowed destinations pass
        assert!(egress.is_allowed("api.example.eu"));
        assert!(egress.is_allowed("https://api.example.eu/v1/query"));
        assert!(egress.is_allowed("sub.data.eu"));

        // 2. Non-allowlisted destinations denied
        assert!(!egress.is_allowed("unauthorized.com"));
        assert!(!egress.is_allowed("https://other.domain.com"));

        // 3. Direct IP bypass addresses denied
        assert!(!egress.is_allowed("192.168.1.1"));
        assert!(!egress.is_allowed("10.0.0.1"));

        // 4. Localhost and cloud metadata denied
        assert!(!egress.is_allowed("localhost"));
        assert!(!egress.is_allowed("127.0.0.1"));
        assert!(!egress.is_allowed("169.254.169.254"));
        assert!(!egress.is_allowed("metadata.google.internal"));

        // 5. Empty allowlist denies EVERYTHING (fail closed)
        let empty_egress = AllowlistEgress::new(vec![]);
        assert!(!empty_egress.is_allowed("api.example.eu"));
        assert!(!empty_egress.is_allowed("anything.com"));
    }
}
