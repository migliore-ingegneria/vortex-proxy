//! eBPF and XDP implementations for Vortex Proxy.
//!
//! This module attempts to load highly optimized kernel-space eBPF programs
//! to drop packets early for rate-limited IPs.

/// Linux eBPF/XDP kernel program loader implementation using `aya`.
#[cfg(target_os = "linux")]
pub mod linux;

/// Mock in-memory XDP rate limiter implementation for non-Linux targets.
#[cfg(not(target_os = "linux"))]
pub mod mock;

/// A unified interface to the XDP rate-limiter, regardless of OS.
pub trait XdpRateLimiter: Send + Sync {
    /// Add an IP address to the kernel-space drop list.
    fn block_ip(
        &self,
        ip: std::net::IpAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Remove an IP address from the kernel-space drop list.
    fn unblock_ip(
        &self,
        ip: std::net::IpAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Check if an IP address is currently blocked in the kernel XDP map.
    fn is_ip_blocked(&self, ip: std::net::IpAddr) -> bool;

    /// Get total count of blocked IPs in the kernel map.
    fn blocked_ip_count(&self) -> usize;
}
