//! Authentication & Authorization — Phase 5.2: JWT + RBAC
//!
//! Supports:
//!   - JWT token issuance with HMAC-SHA256
//!   - Role-based access: admin, operator, readonly
//!   - Tenant context carried in the JWT claims (not client-controlled headers)
//!   - Credentials supplied exclusively via environment (no hardcoded secrets)

use serde::{Deserialize, Serialize};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

use std::env;

/// Minimum acceptable `DFIM_JWT_SECRET` length (bytes).
const MIN_JWT_SECRET_LEN: usize = 32;

const TOKEN_EXPIRY_SECS: u64 = 86400; // 24 hours

/// Resolves the HMAC signing secret.
///
/// If `DFIM_JWT_SECRET` is set and long enough, it is used verbatim.
/// Otherwise the API fails closed by generating a fresh, cryptographically
/// random key that is stable for the lifetime of the process (tokens are
/// invalidated on restart, but can never be forged from a public constant).
fn jwt_secret() -> Vec<u8> {
    if let Ok(secret) = env::var("DFIM_JWT_SECRET") {
        let secret = secret.trim().to_string();
        if secret.len() >= MIN_JWT_SECRET_LEN {
            return secret.into_bytes();
        }
        tracing::warn!(
            "DFIM_JWT_SECRET shorter than {MIN_JWT_SECRET_LEN} bytes — ignoring insecure value"
        );
    }

    static FALLBACK: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    FALLBACK
        .get_or_init(|| {
            tracing::warn!(
                "DFIM_JWT_SECRET not set — using an ephemeral random key (tokens invalid on restart)"
            );
            let mut key = [0u8; 32];
            getrandom::getrandom(&mut key).expect("operating system CSPRNG unavailable");
            key.to_vec()
        })
        .clone()
}

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

/// Role and tenant resolved for an authenticated user.
#[derive(Debug, Clone)]
pub struct UserIdentity {
    pub role: String,
    pub tenant: String,
}

/// Builds the account list from the environment. No credentials are compiled
/// into the binary; if no accounts are configured, login is impossible.
fn configured_accounts() -> Vec<(String, String, UserIdentity)> {
    let mut accounts = Vec::new();

    if let (Ok(user), Ok(pass)) = (env::var("DFIM_ADMIN_USER"), env::var("DFIM_ADMIN_PASSWORD")) {
        if !user.is_empty() && !pass.is_empty() {
            accounts.push((user, pass, UserIdentity {
                role: "admin".into(),
                tenant: tenant_from_env("DFIM_ADMIN_TENANT"),
            }));
        }
    }
    if let (Ok(user), Ok(pass)) =
        (env::var("DFIM_OPERATOR_USER"), env::var("DFIM_OPERATOR_PASSWORD"))
    {
        if !user.is_empty() && !pass.is_empty() {
            accounts.push((user, pass, UserIdentity {
                role: "operator".into(),
                tenant: tenant_from_env("DFIM_OPERATOR_TENANT"),
            }));
        }
    }
    if let (Ok(user), Ok(pass)) =
        (env::var("DFIM_READONLY_USER"), env::var("DFIM_READONLY_PASSWORD"))
    {
        if !user.is_empty() && !pass.is_empty() {
            accounts.push((user, pass, UserIdentity {
                role: "readonly".into(),
                tenant: tenant_from_env("DFIM_READONLY_TENANT"),
            }));
        }
    }

    accounts
}

fn tenant_from_env(key: &str) -> String {
    env::var(key).unwrap_or_else(|_| "default".into())
}

fn resolve_identity(
    accounts: &[(String, String, UserIdentity)],
    username: &str,
    password: &str,
) -> Option<UserIdentity> {
    accounts
        .iter()
        .find(|(u, p, _)| u == username && p == password)
        .map(|(_, _, identity)| identity.clone())
}

/// Validates credentials against the environment-configured account store.
pub fn validate_credentials(username: &str, password: &str) -> Option<UserIdentity> {
    resolve_identity(&configured_accounts(), username, password)
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

/// Verify a JWT token and return claims (constant-time signature check).
pub fn verify_jwt(token: &str) -> Result<Claims, String> {
    let token = token.trim_start_matches("Bearer ");
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("Invalid token format".into());
    }

    let signing_input = format!("{}.{}", parts[0], parts[1]);

    let mut mac = HmacSha256::new_from_slice(&jwt_secret()).map_err(|e| e.to_string())?;
    mac.update(signing_input.as_bytes());
    let expected = mac.finalize().into_bytes();
    let provided = base64_decode(parts[2])?;

    if expected.len() != provided.len()
        || !bool::from(expected.as_slice().ct_eq(provided.as_slice()))
    {
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
    let identity =
        validate_credentials(&req.username, &req.password).ok_or_else(|| "Invalid credentials".to_string())?;

    let token = issue_token(&req.username, &identity.role, &identity.tenant)?;

    Ok(TokenResponse {
        access_token: token,
        token_type: "Bearer".into(),
        expires_in: TOKEN_EXPIRY_SECS,
        role: identity.role,
        tenant: identity.tenant,
    })
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64_decode(b64: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|e| e.to_string())
}

fn base64_encode_json<T: Serialize>(value: &T) -> String {
    let json = serde_json::to_string(value).unwrap_or_default();
    base64_encode(json.as_bytes())
}

fn base64_decode_json<T: for<'a> Deserialize<'a>>(b64: &str) -> Result<T, String> {
    let bytes = base64_decode(b64)?;
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn admin_identity() -> UserIdentity {
        UserIdentity { role: "admin".into(), tenant: "default".into() }
    }

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
    fn test_resolve_identity_matches_and_isolates() {
        let accounts = vec![
            ("acme_admin".to_string(), "acme_pass".to_string(), UserIdentity { role: "admin".into(), tenant: "acme-corp".into() }),
            ("megabank_op".to_string(), "bank_pass".to_string(), UserIdentity { role: "operator".into(), tenant: "megabank".into() }),
        ];
        let a = resolve_identity(&accounts, "acme_admin", "acme_pass").unwrap();
        assert_eq!(a.role, "admin");
        assert_eq!(a.tenant, "acme-corp");
        let b = resolve_identity(&accounts, "megabank_op", "bank_pass").unwrap();
        assert_eq!(b.role, "operator");
        assert_ne!(a.tenant, b.tenant);
    }

    #[test]
    fn test_resolve_identity_rejects_wrong_password() {
        let accounts = vec![
            ("admin".to_string(), "secret".to_string(), admin_identity()),
        ];
        assert!(resolve_identity(&accounts, "admin", "wrong").is_none());
    }

    #[test]
    fn test_login_requires_configured_account() {
        // Without env-configured accounts, login must fail (fail closed).
        let resp = login(&LoginRequest { username: "admin".into(), password: "dfim_admin_2026".into() });
        assert!(resp.is_err());
    }
}
