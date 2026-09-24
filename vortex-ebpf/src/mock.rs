use super::XdpRateLimiter;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::RwLock;

/// A mock rate limiter that maintains an in-memory BPF_MAP_TYPE_HASH simulation for non-Linux targets.
pub struct MockXdpLimiter {
    blocked_ips: RwLock<HashSet<IpAddr>>,
}

impl MockXdpLimiter {
    /// Create a new MockXdpLimiter
    pub fn new() -> Self {
        Self {
            blocked_ips: RwLock::new(HashSet::new()),
        }
    }
}

impl Default for MockXdpLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl XdpRateLimiter for MockXdpLimiter {
    fn block_ip(&self, ip: IpAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::debug!("Mock XDP: Blocked IP {}", ip);
        let mut guard = self.blocked_ips.write().unwrap();
        guard.insert(ip);
        Ok(())
    }

    fn unblock_ip(&self, ip: IpAddr) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::debug!("Mock XDP: Unblocked IP {}", ip);
        let mut guard = self.blocked_ips.write().unwrap();
        guard.remove(&ip);
        Ok(())
    }

    fn is_ip_blocked(&self, ip: IpAddr) -> bool {
        let guard = self.blocked_ips.read().unwrap();
        guard.contains(&ip)
    }

    fn blocked_ip_count(&self) -> usize {
        let guard = self.blocked_ips.read().unwrap();
        guard.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_xdp_limiter_lifecycle() {
        let limiter = MockXdpLimiter::new();
        let ip: IpAddr = "192.168.1.100".parse().unwrap();

        assert!(!limiter.is_ip_blocked(ip));
        assert_eq!(limiter.blocked_ip_count(), 0);

        limiter.block_ip(ip).unwrap();
        assert!(limiter.is_ip_blocked(ip));
        assert_eq!(limiter.blocked_ip_count(), 1);

        limiter.unblock_ip(ip).unwrap();
        assert!(!limiter.is_ip_blocked(ip));
        assert_eq!(limiter.blocked_ip_count(), 0);
    }
}
