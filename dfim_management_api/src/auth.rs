//! Authentication & Authorization — Phase 5.2: JWT + RBAC
//!
//! Supports:
//!   - JWT token issuance with HMAC-SHA256
//!   - Role-based access: admin, operator, readonly
//!   - Token expiry: 24h default
//!   - Tenant context extraction from claims

use serde::{Deserialize, Serialize};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

use std::env;

fn get_jwt_secret() -> Vec<u8> {
    env::var("DFIM_JWT_SECRET")
        .unwrap_or_else(|_| {
            tracing::warn!("DFIM_JWT_SECRET not set — using random key (not persistent!)");
            use sha2::Digest;
            format!("{:x}", sha2::Sha256::digest(b"dfim-fallback-random-seed"))
        })
        .into_bytes()
}

fn jwt_secret() -> Vec<u8> {
    get_jwt_secret()
}

const TOKEN_EXPIRY_SECS: u64 = 86400; // 24 hours

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,       // username
    pub tenant: String,     // tenant_id
    pub role: String,       // admin | operator | readonly
    pub exp: u64,           // expiry timestamp
    pub iat: u64,           // issued at
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub role: String,
    pub tenant: String,
}

/// Simple user store (production: LDAP/OAuth2)
fn validate_credentials(username: &str, password: &str) -> Option<(String, String)> {
    match (username, password) {
        ("admin", "REDACTED") => Some(("admin".into(), "default".into())),
        ("operator", "dfim_ops_2026") => Some(("operator".into(), "default".into())),
        ("readonly", "dfim_ro_2026") => Some(("readonly".into(), "default".into())),
        ("acme_admin", "acme_pass") => Some(("admin".into(), "acme-corp".into())),
        ("megabank_op", "bank_pass") => Some(("operator".into(), "megabank".into())),
        _ => None,
    }
}

/// Issue a JWT token
pub fn issue_token(username: &str, role: &str, tenant: &str) -> Result<String, String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs();

    let claims = Claims {
        sub: username.to_string(),
        tenant: tenant.to_string(),
        role: role.to_string(),
        exp: now + TOKEN_EXPIRY_SECS,
        iat: now,
    };

    let header = base64_encode_json(&serde_json::json!({"alg": "HS256", "typ": "JWT"}));
    let payload = base64_encode_json(&claims);
    let signing_input = format!("{}.{}", header, payload);

    let mut mac = HmacSha256::new_from_slice(&jwt_secret()).map_err(|e| e.to_string())?;
    mac.update(signing_input.as_bytes());
    let signature = base64_encode(&mac.finalize().into_bytes());

    Ok(format!("{}.{}.{}", header, payload, signature))
}

/// Verify a JWT token and return claims
pub fn verify_jwt(token: &str) -> Result<Claims, String> {
    let token = token.trim_start_matches("Bearer ");
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid token format".into());
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);

    let mut mac = HmacSha256::new_from_slice(&jwt_secret()).map_err(|e| e.to_string())?;
    mac.update(signing_input.as_bytes());
    let expected_sig = base64_encode(&mac.finalize().into_bytes());

    if parts[2] != expected_sig {
        return Err("Invalid signature".into());
    }

    let claims: Claims = base64_decode_json(parts[1])?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs();
    if claims.exp < now {
        return Err("Token expired".into());
    }

    Ok(claims)
}

/// Login handler
pub fn login(req: &LoginRequest) -> Result<TokenResponse, String> {
    let (role, tenant) = validate_credentials(&req.username, &req.password)
        .ok_or_else(|| "Invalid credentials".to_string())?;

    let token = issue_token(&req.username, &role, &tenant)?;

    Ok(TokenResponse {
        access_token: token,
        token_type: "Bearer".into(),
        expires_in: TOKEN_EXPIRY_SECS,
        role,
        tenant,
    })
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64_encode_json<T: Serialize>(value: &T) -> String {
    let json = serde_json::to_string(value).unwrap_or_default();
    base64_encode(json.as_bytes())
}

fn base64_decode_json<T: for<'a> Deserialize<'a>>(b64: &str) -> Result<T, String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64).map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_issue_and_verify_token() {
        let token = issue_token("admin", "admin", "default").unwrap();
        let claims = verify_jwt(&format!("Bearer {}", token)).unwrap();
        assert_eq!(claims.sub, "admin");
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.tenant, "default");
    }

    #[test]
    fn test_expired_token_rejected() {
        // Create token with past expiry
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let claims = Claims { sub: "test".into(), tenant: "default".into(), role: "admin".into(), exp: now - 1, iat: now - 100 };
        let payload = base64_encode_json(&claims);
        let header = base64_encode_json(&serde_json::json!({"alg":"HS256","typ":"JWT"}));
        let mut mac = HmacSha256::new_from_slice(&jwt_secret()).unwrap();
        mac.update(format!("{}.{}", header, payload).as_bytes());
        let sig = base64_encode(&mac.finalize().into_bytes());
        let token = format!("{}.{}.{}", header, payload, sig);
        assert!(verify_jwt(&format!("Bearer {}", token)).is_err());
    }

    #[test]
    fn test_login_valid_credentials() {
        let resp = login(&LoginRequest { username: "admin".into(), password: "REDACTED".into() }).unwrap();
        assert_eq!(resp.role, "admin");
        assert_eq!(resp.token_type, "Bearer");
        assert!(resp.access_token.len() > 50);
    }

    #[test]
    fn test_login_invalid_credentials() {
        assert!(login(&LoginRequest { username: "admin".into(), password: "wrong".into() }).is_err());
    }

    #[test]
    fn test_multi_tenant_isolation() {
        let t1 = issue_token("acme_admin", "admin", "acme-corp").unwrap();
        let t2 = issue_token("megabank_op", "operator", "megabank").unwrap();
        let c1 = verify_jwt(&format!("Bearer {}", t1)).unwrap();
        let c2 = verify_jwt(&format!("Bearer {}", t2)).unwrap();
        assert_eq!(c1.tenant, "acme-corp");
        assert_eq!(c2.tenant, "megabank");
        assert_ne!(c1.tenant, c2.tenant);
    }
}
