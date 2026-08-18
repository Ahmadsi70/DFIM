// Propagates `DFIM_CRYPTO_KEY` (or `DFIM_CRYPTO_KEY_FILE`) into litcrypt at compile time (IEC 62443 CR 1.8).

/// Minimum acceptable secret length for string-encryption at compile time.
const MIN_KEY_LEN: usize = 16;

/// Resolves the compile-time encryption key from the host build environment.
///
/// Build scripts always execute on the **host** OS, so cross-compiling to
/// `x86_64-unknown-linux-musl` from Windows still reads `DFIM_CRYPTO_KEY` here.
fn resolve_crypto_key() -> Result<String, String> {
    if let Ok(key) = std::env::var("DFIM_CRYPTO_KEY") {
        return Ok(key);
    }
    if let Ok(path) = std::env::var("DFIM_CRYPTO_KEY_FILE") {
        return std::fs::read_to_string(&path).map_err(|err| {
            format!("DFIM_CRYPTO_KEY_FILE={path} could not be read: {err}")
        });
    }
    Err(
        "DFIM_CRYPTO_KEY must be set before building DFIM crates (IEC 62443 CR 1.8). \
         Cross-compile hosts: export DFIM_CRYPTO_KEY or DFIM_CRYPTO_KEY_FILE. \
         Example: export DFIM_CRYPTO_KEY=\"$(openssl rand -hex 32)\""
            .into(),
    )
}

/// Configures `LITCRYPT_ENCRYPT_KEY` from the deployment environment.
pub fn configure_litcrypt_key() {
    let key = match resolve_crypto_key() {
        Ok(key) => key,
        Err(message) => panic!("{message}"),
    };

    if key.len() < MIN_KEY_LEN {
        panic!(
            "DFIM_CRYPTO_KEY must be at least {MIN_KEY_LEN} bytes (got {})",
            key.len()
        );
    }

    if key.bytes().any(|b| b == b'\n' || b == b'\r' || b == 0) {
        panic!("DFIM_CRYPTO_KEY contains invalid control characters");
    }

    let trimmed = key.trim();
    if trimmed.len() < MIN_KEY_LEN {
        panic!(
            "DFIM_CRYPTO_KEY must be at least {MIN_KEY_LEN} bytes after trimming (got {})",
            trimmed.len()
        );
    }

    println!("cargo:rustc-env=LITCRYPT_ENCRYPT_KEY={trimmed}");
    println!("cargo:rerun-if-env-changed=DFIM_CRYPTO_KEY");
    println!("cargo:rerun-if-env-changed=DFIM_CRYPTO_KEY_FILE");
}
