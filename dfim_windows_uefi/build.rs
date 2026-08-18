use std::{env, fs, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-env-changed=DFIM_BOOT_PUBLIC_KEY_HEX");
    println!("cargo:rerun-if-env-changed=DFIM_BOOT_KEY_ID_HEX");
    println!("cargo:rerun-if-env-changed=DFIM_BOOT_MIN_RELEASE");

    let enabled = env::var_os("CARGO_FEATURE_UEFI_APP").is_some();
    let (public_key, key_id, minimum_release) = if enabled {
        let public_key = decode_hex_exact::<33>("DFIM_BOOT_PUBLIC_KEY_HEX");
        assert!(
            matches!(public_key[0], 0x02 | 0x03),
            "DFIM_BOOT_PUBLIC_KEY_HEX must be a compressed SEC1 P-256 key"
        );
        let key_id = decode_hex_exact::<16>("DFIM_BOOT_KEY_ID_HEX");
        let minimum_release = env::var("DFIM_BOOT_MIN_RELEASE")
            .expect("DFIM_BOOT_MIN_RELEASE is required for uefi-app")
            .parse::<u64>()
            .expect("DFIM_BOOT_MIN_RELEASE must be an unsigned integer");
        assert!(
            minimum_release > 0,
            "DFIM_BOOT_MIN_RELEASE must be greater than zero"
        );
        (public_key, key_id, minimum_release)
    } else {
        ([0u8; 33], [0u8; 16], 0)
    };

    let generated = format!(
        "pub const BOOT_PUBLIC_KEY: [u8; 33] = {public_key:?};\n\
         pub const BOOT_KEY_ID: [u8; 16] = {key_id:?};\n\
         pub const BOOT_MIN_RELEASE: u64 = {minimum_release};\n"
    );
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is required"))
        .join("deployment_trust.rs");
    fs::write(output, generated).expect("failed to write deployment trust constants");
}

fn decode_hex_exact<const N: usize>(name: &str) -> [u8; N] {
    let text = env::var(name).unwrap_or_else(|_| panic!("{name} is required for uefi-app"));
    assert_eq!(
        text.len(),
        N * 2,
        "{name} must contain exactly {} hexadecimal characters",
        N * 2
    );
    let bytes = text.as_bytes();
    let mut output = [0u8; N];
    for index in 0..N {
        output[index] = (decode_nibble(name, bytes[index * 2]) << 4)
            | decode_nibble(name, bytes[index * 2 + 1]);
    }
    output
}

fn decode_nibble(name: &str, value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("{name} contains a non-hexadecimal character"),
    }
}
