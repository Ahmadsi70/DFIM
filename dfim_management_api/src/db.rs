//! Database Layer — Phase 5.1: PostgreSQL persistence with sqlx

use chrono::{DateTime, Utc};
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::env;

pub type DbPool = PgPool;

/// Connect to PostgreSQL with connection pooling.
///
/// `DATABASE_URL` is required; no fallback credentials are embedded.
pub async fn connect() -> Result<DbPool, sqlx::Error> {
    let db_url = env::var("DATABASE_URL")
        .map_err(|_| sqlx::Error::Configuration("DATABASE_URL environment variable is not set".into()))?;

    PgPoolOptions::new()
        .max_connections(50)
        .min_connections(5)
        .connect(&db_url)
        .await
}

/// Run database migrations
pub async fn migrate(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS assets (
            asset_id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            asset_kind TEXT NOT NULL,
            host_name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            integrity_hash TEXT,
            last_verified TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            enrolled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            policy_id TEXT,
            tenant_id TEXT NOT NULL DEFAULT 'default'
        )"
    ).execute(pool).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS policies (
            policy_id TEXT NOT NULL,
            name TEXT NOT NULL,
            version INT NOT NULL DEFAULT 1,
            enforcement_mode TEXT NOT NULL DEFAULT 'protected-scope',
            tenant_id TEXT NOT NULL DEFAULT 'default',
            PRIMARY KEY (policy_id, tenant_id)
        )"
    ).execute(pool).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS nodes (
            node_id TEXT PRIMARY KEY,
            host_name TEXT NOT NULL,
            platform TEXT NOT NULL DEFAULT 'linux',
            status TEXT NOT NULL DEFAULT 'online',
            last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            asset_count INT NOT NULL DEFAULT 0
        )"
    ).execute(pool).await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            severity TEXT NOT NULL,
            asset_id TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            acknowledged BOOLEAN NOT NULL DEFAULT false,
            tenant_id TEXT NOT NULL DEFAULT 'default'
        )"
    ).execute(pool).await?;

    // Seed demo data
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM assets WHERE tenant_id = 'default'")
        .fetch_one(pool).await?;
    if count.0 == 0 {
        let demo = [
            ("sha256:bootmgfw", "bootmgfw.efi", "WindowsBootManager", "node-01", "healthy"),
            ("sha256:vmlinuz", "vmlinuz", "LinuxKernel", "node-02", "healthy"),
            ("sha256:systemd", "systemd", "InitSystem", "node-03", "healthy"),
            ("sha256:sshd", "sshd", "SSHDaemon", "node-01", "healthy"),
        ];
        for (id, name, kind, host, status) in demo {
            sqlx::query("INSERT INTO assets (asset_id, display_name, asset_kind, host_name, status, tenant_id) VALUES ($1,$2,$3,$4,$5,'default') ON CONFLICT DO NOTHING")
                .bind(id).bind(name).bind(kind).bind(host).bind(status)
                .execute(pool).await?;
        }
        sqlx::query("INSERT INTO policies (policy_id, name, tenant_id) VALUES ('default-policy','Enterprise Baseline','default') ON CONFLICT DO NOTHING")
            .execute(pool).await?;
    }

    tracing::info!("Database migrated successfully");
    Ok(())
}

// ── Asset CRUD ──

pub async fn count_assets(pool: &DbPool, tenant: &str) -> Result<Option<i64>, sqlx::Error> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM assets WHERE tenant_id = $1")
        .bind(tenant).fetch_one(pool).await?;
    Ok(Some(row.0))
}

pub async fn list_assets(pool: &DbPool, tenant: &str, limit: i64, offset: i64,
                          status: Option<&str>, host: Option<&str>, kind: Option<&str>) -> Result<Vec<super::AssetRecord>, sqlx::Error> {
    let rows = match (status, host, kind) {
        (Some(s), Some(h), Some(k)) => {
            sqlx::query_as("SELECT asset_id,display_name,asset_kind,host_name,status,integrity_hash,last_verified,enrolled_at,policy_id,tenant_id FROM assets WHERE tenant_id=$1 AND status=$2 AND host_name=$3 AND asset_kind=$4 ORDER BY last_verified DESC")
                .bind(tenant).bind(s).bind(h).bind(k)
        }
        (Some(s), Some(h), None) => {
            sqlx::query_as("SELECT asset_id,display_name,asset_kind,host_name,status,integrity_hash,last_verified,enrolled_at,policy_id,tenant_id FROM assets WHERE tenant_id=$1 AND status=$2 AND host_name=$3 ORDER BY last_verified DESC")
                .bind(tenant).bind(s).bind(h)
        }
        (Some(s), None, None) => {
            sqlx::query_as("SELECT asset_id,display_name,asset_kind,host_name,status,integrity_hash,last_verified,enrolled_at,policy_id,tenant_id FROM assets WHERE tenant_id=$1 AND status=$2 ORDER BY last_verified DESC")
                .bind(tenant).bind(s)
        }
        (None, Some(h), None) => {
            sqlx::query_as("SELECT asset_id,display_name,asset_kind,host_name,status,integrity_hash,last_verified,enrolled_at,policy_id,tenant_id FROM assets WHERE tenant_id=$1 AND host_name=$2 ORDER BY last_verified DESC")
                .bind(tenant).bind(h)
        }
        _ => {
            sqlx::query_as("SELECT asset_id,display_name,asset_kind,host_name,status,integrity_hash,last_verified,enrolled_at,policy_id,tenant_id FROM assets WHERE tenant_id=$1 ORDER BY last_verified DESC")
                .bind(tenant)
        }
    };
    let all = rows.fetch_all(pool).await?;
    let page: Vec<_> = all.into_iter().skip(offset as usize).take(limit as usize).collect();
    Ok(page)
}

pub async fn get_asset(pool: &DbPool, tenant: &str, id: &str) -> Option<super::AssetRecord> {
    sqlx::query_as::<_, super::AssetRecord>(
        "SELECT asset_id, display_name, asset_kind, host_name, status, integrity_hash, last_verified, enrolled_at, policy_id, tenant_id FROM assets WHERE asset_id = $1 AND tenant_id = $2"
    ).bind(id).bind(tenant).fetch_optional(pool).await.ok().flatten()
}

pub async fn insert_asset(pool: &DbPool, a: &super::AssetRecord) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO assets (asset_id,display_name,asset_kind,host_name,status,integrity_hash,last_verified,enrolled_at,policy_id,tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)")
        .bind(&a.asset_id).bind(&a.display_name).bind(&a.asset_kind).bind(&a.host_name)
        .bind(&a.status).bind(&a.integrity_hash).bind(a.last_verified).bind(a.enrolled_at)
        .bind(&a.policy_id).bind(&a.tenant_id)
        .execute(pool).await?;
    Ok(())
}

pub async fn update_asset_status(pool: &DbPool, tenant: &str, id: &str, status: &str, verified: DateTime<Utc>) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE assets SET status = $1, last_verified = $2 WHERE asset_id = $3 AND tenant_id = $4")
        .bind(status).bind(verified).bind(id).bind(tenant)
        .execute(pool).await?;
    Ok(())
}

pub async fn delete_asset(pool: &DbPool, tenant: &str, id: &str) -> Result<(), sqlx::Error> {
    let r = sqlx::query("DELETE FROM assets WHERE asset_id = $1 AND tenant_id = $2")
        .bind(id).bind(tenant).execute(pool).await?;
    if r.rows_affected() == 0 { Err(sqlx::Error::RowNotFound) } else { Ok(()) }
}

// ── Policies ──

pub async fn count_policies(pool: &DbPool, tenant: &str) -> Result<Option<i64>, sqlx::Error> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM policies WHERE tenant_id = $1")
        .bind(tenant).fetch_one(pool).await?;
    Ok(Some(row.0))
}

pub async fn list_policies(pool: &DbPool, tenant: &str) -> Result<Vec<super::PolicyRecord>, sqlx::Error> {
    sqlx::query_as("SELECT policy_id, name, version, enforcement_mode, tenant_id FROM policies WHERE tenant_id = $1")
        .bind(tenant).fetch_all(pool).await
}

pub async fn insert_policy(pool: &DbPool, p: &super::PolicyRecord) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO policies (policy_id, name, version, enforcement_mode, tenant_id) VALUES ($1,$2,$3,$4,$5)")
        .bind(&p.policy_id).bind(&p.name).bind(p.version).bind(&p.enforcement_mode).bind(&p.tenant_id)
        .execute(pool).await?;
    Ok(())
}

// ── Nodes ──

pub async fn count_nodes(pool: &DbPool) -> Result<Option<i64>, sqlx::Error> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM nodes").fetch_one(pool).await?;
    Ok(Some(row.0))
}

pub async fn list_nodes(pool: &DbPool) -> Result<Vec<super::NodeRecord>, sqlx::Error> {
    sqlx::query_as("SELECT node_id, host_name, platform, status, last_seen, asset_count FROM nodes ORDER BY last_seen DESC")
        .fetch_all(pool).await
}

pub async fn insert_node(pool: &DbPool, n: &super::NodeRecord) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO nodes (node_id, host_name, platform, status, last_seen, asset_count) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (node_id) DO UPDATE SET last_seen = $5, status = 'online'")
        .bind(&n.node_id).bind(&n.host_name).bind(&n.platform).bind(&n.status).bind(n.last_seen).bind(n.asset_count)
        .execute(pool).await?;
    Ok(())
}

// ── Alerts ──

pub async fn count_alerts(pool: &DbPool, tenant: &str) -> Result<Option<i64>, sqlx::Error> {
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM alerts WHERE tenant_id = $1")
        .bind(tenant).fetch_one(pool).await?;
    Ok(Some(row.0))
}

pub async fn list_alerts(pool: &DbPool, tenant: &str, limit: i64) -> Result<Vec<super::AlertRecord>, sqlx::Error> {
    sqlx::query_as("SELECT alert_id, severity, asset_id, message, timestamp, acknowledged, tenant_id FROM alerts WHERE tenant_id = $1 ORDER BY timestamp DESC LIMIT $2")
        .bind(tenant).bind(limit).fetch_all(pool).await
}

pub async fn insert_alert(pool: &DbPool, a: &super::AlertRecord) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO alerts (alert_id, severity, asset_id, message, timestamp, acknowledged, tenant_id) VALUES ($1,$2,$3,$4,$5,$6,$7)")
        .bind(&a.alert_id).bind(&a.severity).bind(&a.asset_id).bind(&a.message).bind(a.timestamp).bind(a.acknowledged).bind(&a.tenant_id)
        .execute(pool).await?;
    Ok(())
}

pub async fn acknowledge_alert(pool: &DbPool, tenant: &str, id: &str) -> Result<super::AlertRecord, sqlx::Error> {
    sqlx::query("UPDATE alerts SET acknowledged = true WHERE alert_id = $1 AND tenant_id = $2")
        .bind(id).bind(tenant).execute(pool).await?;
    sqlx::query_as("SELECT alert_id, severity, asset_id, message, timestamp, acknowledged, tenant_id FROM alerts WHERE alert_id = $1 AND tenant_id = $2")
        .bind(id).bind(tenant).fetch_one(pool).await
}

// ── Fleet Summary ──

#[derive(Debug, Default)]
pub struct FleetSummaryRaw {
    pub total_assets: i64, pub healthy: i64, pub tampered: i64,
    pub blocked: i64, pub pending: i64,
    pub total_nodes: i64, pub total_policies: i64, pub active_alerts: i64,
}

pub async fn fleet_summary(pool: &DbPool, tenant: &str) -> Result<FleetSummaryRaw, sqlx::Error> {
    #[derive(sqlx::FromRow)]
    struct SummaryRow {
        total_assets: i64,
        healthy: i64,
        tampered: i64,
        blocked: i64,
        pending: i64,
        total_nodes: i64,
        total_policies: i64,
        active_alerts: i64,
    }

    let row: SummaryRow = sqlx::query_as(
        "SELECT
            (SELECT COUNT(*) FROM assets WHERE tenant_id = $1)::bigint AS total_assets,
            (SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND status = 'healthy')::bigint AS healthy,
            (SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND status = 'tampered')::bigint AS tampered,
            (SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND status = 'blocked')::bigint AS blocked,
            (SELECT COUNT(*) FROM assets WHERE tenant_id = $1 AND status = 'pending')::bigint AS pending,
            (SELECT COUNT(*) FROM nodes)::bigint AS total_nodes,
            (SELECT COUNT(*) FROM policies WHERE tenant_id = $1)::bigint AS total_policies,
            (SELECT COUNT(*) FROM alerts WHERE tenant_id = $1 AND acknowledged = false)::bigint AS active_alerts",
    )
    .bind(tenant)
    .fetch_one(pool)
    .await?;

    Ok(FleetSummaryRaw {
        total_assets: row.total_assets,
        healthy: row.healthy,
        tampered: row.tampered,
        blocked: row.blocked,
        pending: row.pending,
        total_nodes: row.total_nodes,
        total_policies: row.total_policies,
        active_alerts: row.active_alerts,
    })
}
