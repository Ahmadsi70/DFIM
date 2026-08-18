//! Prometheus Metrics — Phase 5.6: /metrics endpoint
//!
//! Exposes Prometheus-formatted metrics for Grafana dashboards.

use axum::{body::Body, http::StatusCode, response::Response};
use std::sync::atomic::{AtomicU64, Ordering};

static REQUEST_COUNT: AtomicU64 = AtomicU64::new(0);
static ERROR_COUNT: AtomicU64 = AtomicU64::new(0);
static ASSET_COUNT: AtomicU64 = AtomicU64::new(0);
static ALERT_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn increment_requests() { REQUEST_COUNT.fetch_add(1, Ordering::Relaxed); }
pub fn increment_errors() { ERROR_COUNT.fetch_add(1, Ordering::Relaxed); }
pub fn set_asset_count(n: u64) { ASSET_COUNT.store(n, Ordering::Relaxed); }
pub fn set_alert_count(n: u64) { ALERT_COUNT.store(n, Ordering::Relaxed); }

pub async fn metrics_handler() -> Response<Body> {
    let metrics = format!(
        "# HELP dfim_http_requests_total Total HTTP requests\n\
         # TYPE dfim_http_requests_total counter\n\
         dfim_http_requests_total {}\n\
         # HELP dfim_http_errors_total Total HTTP errors\n\
         # TYPE dfim_http_errors_total counter\n\
         dfim_http_errors_total {}\n\
         # HELP dfim_assets_total Total enrolled assets\n\
         # TYPE dfim_assets_total gauge\n\
         dfim_assets_total {}\n\
         # HELP dfim_alerts_active Active security alerts\n\
         # TYPE dfim_alerts_active gauge\n\
         dfim_alerts_active {}\n\
         # HELP dfim_uptime_seconds API uptime\n\
         # TYPE dfim_uptime_seconds gauge\n\
         dfim_uptime_seconds {}\n\
         # HELP dfim_build_info Build metadata\n\
         # TYPE dfim_build_info gauge\n\
         dfim_build_info{{version=\"1.0.0\",phase=\"5\"}} 1\n",
        REQUEST_COUNT.load(Ordering::Relaxed),
        ERROR_COUNT.load(Ordering::Relaxed),
        ASSET_COUNT.load(Ordering::Relaxed),
        ALERT_COUNT.load(Ordering::Relaxed),
        0u64,
    );

    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; version=0.0.4")
        .body(Body::from(metrics))
        .unwrap()
}
