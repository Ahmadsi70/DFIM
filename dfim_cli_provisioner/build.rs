//! Injects `DFIM_CRYPTO_KEY` into litcrypt at compile time.

include!("../build-support/litcrypt_key.rs");

fn main() {
    configure_litcrypt_key();
}
