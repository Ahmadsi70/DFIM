//! Rate Limiting — Phase 5.3: Token bucket per-IP middleware
//!
//! Algorithm: Token bucket with configurable rate and burst.
//! Default: 1000 requests/sec per IP, burst size 100.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
    rate: f64,       // tokens per second
    max_tokens: f64,  // burst size
}

impl TokenBucket {
    fn new(rate: f64, burst: f64) -> Self {
        Self { tokens: burst, last_refill: Instant::now(), rate, max_tokens: burst }
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

pub struct RateLimiter {
    buckets: RwLock<HashMap<IpAddr, TokenBucket>>,
    rate: f64,
    burst: f64,
}

impl RateLimiter {
    pub fn new(rate: u32, burst: u32) -> Self {
        Self {
            buckets: RwLock::new(HashMap::new()),
            rate: rate as f64,
            burst: burst as f64,
        }
    }

    /// Check if a request from `ip` is allowed. Returns true if allowed.
    pub fn check(&self, ip: IpAddr) -> bool {
        let mut buckets = self.buckets.write();
        let bucket = buckets.entry(ip).or_insert_with(|| TokenBucket::new(self.rate, self.burst));
        bucket.try_consume()
    }

    /// Get current token count for an IP (for monitoring).
    pub fn tokens_remaining(&self, ip: IpAddr) -> f64 {
        let buckets = self.buckets.read();
        buckets.get(&ip).map(|b| b.tokens).unwrap_or(self.burst)
    }

    /// Clean up expired entries (call periodically).
    pub fn cleanup(&self, max_age: Duration) {
        let mut buckets = self.buckets.write();
        let now = Instant::now();
        buckets.retain(|_, b| now.duration_since(b.last_refill) < max_age);
    }

    /// Get total tracked IPs.
    pub fn tracked_ips(&self) -> usize {
        self.buckets.read().len()
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
        assert!(rl.check(ip2));  // Different IP, not rate-limited
    }
}
