//! Rate Limiting — Phase 5.3: Sharded token bucket per-IP middleware
//!
//! Algorithm: Token bucket with configurable rate and burst, sharded across
//! N independent locks so concurrent requests do not contend on a single
//! global lock. Each IP is hashed to a fixed shard, preserving per-IP bucket
//! semantics while removing the cross-IP write-lock bottleneck.
//!
//! Default: 1000 requests/sec per IP, burst size 100.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// Number of independent shards (must be a power of two for fast masking).
const SHARD_COUNT: usize = 64;

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    rate: f64,       // tokens per second
    max_tokens: f64, // burst size
}

impl TokenBucket {
    fn new(rate: f64, burst: f64) -> Self {
        Self {
            tokens: burst,
            last_refill: Instant::now(),
            rate,
            max_tokens: burst,
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.max_tokens);
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct Shard {
    buckets: RwLock<HashMap<IpAddr, TokenBucket>>,
}

pub struct RateLimiter {
    shards: Vec<Shard>,
    rate: f64,
    burst: f64,
}

impl RateLimiter {
    pub fn new(rate: u32, burst: u32) -> Self {
        let mut shards = Vec::with_capacity(SHARD_COUNT);
        for _ in 0..SHARD_COUNT {
            shards.push(Shard {
                buckets: RwLock::new(HashMap::new()),
            });
        }
        Self {
            shards,
            rate: rate as f64,
            burst: burst as f64,
        }
    }

    /// Number of shards (for monitoring/tests).
    #[allow(dead_code)]
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }

    #[inline]
    fn shard_index(&self, ip: IpAddr) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        ip.hash(&mut hasher);
        hasher.finish() as usize % self.shards.len()
    }

    /// Check if a request from `ip` is allowed. Returns true if allowed.
    pub fn check(&self, ip: IpAddr) -> bool {
        let mut buckets = self.shards[self.shard_index(ip)].buckets.write();
        let bucket = buckets
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(self.rate, self.burst));
        bucket.try_consume()
    }

    /// Get current token count for an IP (for monitoring).
    #[allow(dead_code)]
    pub fn tokens_remaining(&self, ip: IpAddr) -> f64 {
        let buckets = self.shards[self.shard_index(ip)].buckets.read();
        buckets.get(&ip).map(|b| b.tokens).unwrap_or(self.burst)
    }

    /// Clean up expired entries (call periodically).
    #[allow(dead_code)]
    pub fn cleanup(&self, max_age: Duration) {
        let now = Instant::now();
        for shard in &self.shards {
            let mut buckets = shard.buckets.write();
            buckets.retain(|_, b| now.duration_since(b.last_refill) < max_age);
        }
    }

    /// Get total tracked IPs.
    #[allow(dead_code)]
    pub fn tracked_ips(&self) -> usize {
        self.shards.iter().map(|s| s.buckets.read().len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_token_bucket_allows_up_to_burst() {
        let mut bucket = TokenBucket::new(10.0, 5.0);
        for _ in 0..5 {
            assert!(bucket.try_consume());
        }
        assert!(!bucket.try_consume());
    }

    #[test]
    fn test_rate_limiter_multi_ip() {
        let rl = RateLimiter::new(1, 1);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();
        assert!(rl.check(ip1));
        assert!(!rl.check(ip1));
        assert!(rl.check(ip2)); // Different IP, not rate-limited
    }

    #[test]
    fn test_same_ip_maps_to_same_shard() {
        let rl = RateLimiter::new(1, 1);
        let ip: IpAddr = "10.0.0.7".parse().unwrap();
        assert_eq!(rl.shard_index(ip), rl.shard_index(ip));
    }

    #[test]
    fn test_shard_count_is_power_of_two() {
        let rl = RateLimiter::new(1, 1);
        assert_eq!(rl.shard_count(), 64);
        assert!(rl.shard_count().is_power_of_two());
    }

    #[test]
    fn test_cleanup_removes_expired_ips() {
        let rl = RateLimiter::new(1, 1);
        let ip: IpAddr = "172.16.0.9".parse().unwrap();
        assert!(rl.check(ip));
        assert_eq!(rl.tracked_ips(), 1);
        rl.cleanup(Duration::ZERO);
        assert_eq!(rl.tracked_ips(), 0);
    }
}
