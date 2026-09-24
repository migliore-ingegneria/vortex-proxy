use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};
use vortex_ebpf::XdpRateLimiter;

/// Manages eBPF IP bans and automatically unbans them after a cooldown period.
pub struct BanManager {
    limiter: Option<Arc<dyn XdpRateLimiter>>,
    banned_ips: Arc<DashMap<IpAddr, Instant>>,
}

impl BanManager {
    /// Creates a new BanManager.
    pub fn new(limiter: Option<Arc<dyn XdpRateLimiter>>) -> Self {
        Self {
            limiter,
            banned_ips: Arc::new(DashMap::new()),
        }
    }

    /// Bans the given IP address at the kernel level for the specified duration.
    pub fn ban_ip(&self, ip: IpAddr, duration: Duration) {
        if let Some(limiter) = &self.limiter {
            if let Err(e) = limiter.block_ip(ip) {
                error!("Failed to kernel-ban IP {}: {}", ip, e);
            } else {
                warn!(
                    "IP {} successfully banished to the kernel shadow realm (eBPF XDP) for {:?}",
                    ip, duration
                );
                self.banned_ips.insert(ip, Instant::now() + duration);
            }
        }
    }

    /// Checks whether an IP address is currently actively banned.
    pub fn is_ip_banned(&self, ip: &IpAddr) -> bool {
        if let Some(limiter) = &self.limiter {
            if limiter.is_ip_blocked(*ip) {
                return true;
            }
        }
        if let Some(exp) = self.banned_ips.get(ip) {
            *exp.value() > Instant::now()
        } else {
            false
        }
    }

    /// Spawns a background Tokio task to sweep and unban expired IPs.
    pub fn spawn_sweeper(self: Arc<Self>, tick_rate: Duration) {
        if self.limiter.is_none() {
            // No need to sweep if there is no kernel blocker.
            return;
        }

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tick_rate);
            loop {
                interval.tick().await;

                let now = Instant::now();

                self.banned_ips.retain(|ip, expiration| {
                    if *expiration <= now {
                        if let Some(limiter) = &self.limiter {
                            if let Err(e) = limiter.unblock_ip(*ip) {
                                error!("Failed to unban IP {}: {}", ip, e);
                                // Retry on next tick
                                return true;
                            } else {
                                info!("IP {} cooldown expired. Unbanned from eBPF map.", ip);
                            }
                        }
                        // Remove from map
                        false
                    } else {
                        // Keep in map
                        true
                    }
                });
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vortex_ebpf::mock::MockXdpLimiter;

    #[tokio::test]
    async fn test_ban_manager_bpf_map_lifecycle_and_sweeper() {
        let mock_limiter: Arc<dyn XdpRateLimiter> = Arc::new(MockXdpLimiter::new());
        let ban_manager = Arc::new(BanManager::new(Some(mock_limiter.clone())));

        let target_ip: IpAddr = "203.0.113.42".parse().unwrap();

        // 1. Initial state: not banned
        assert!(!ban_manager.is_ip_banned(&target_ip));
        assert!(!mock_limiter.is_ip_blocked(target_ip));

        // 2. Ban IP for short duration
        ban_manager.ban_ip(target_ip, Duration::from_millis(100));
        assert!(ban_manager.is_ip_banned(&target_ip));
        assert!(mock_limiter.is_ip_blocked(target_ip));

        // 3. Spawn sweeper and wait for expiry
        let manager_clone = ban_manager.clone();
        manager_clone.spawn_sweeper(Duration::from_millis(20));

        tokio::time::sleep(Duration::from_millis(250)).await;

        assert!(!ban_manager.is_ip_banned(&target_ip));
        assert!(!mock_limiter.is_ip_blocked(target_ip));
    }
}
