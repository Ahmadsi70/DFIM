//! BPF workspace SHA-256 — keeps message schedule off the 512 B kernel stack.

use crate::constants::SHA256_LEN;

const INIT_STATE: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Scratch for SHA-256 compression (lives in a per-CPU map, not on the BPF stack).
#[repr(C)]
pub struct Sha256Workspace {
    pub state: [u32; 8],
    pub w: [u32; 64],
    /// Padding / compression block buffer (avoids 64 B stack frames).
    pub block: [u8; 64],
    /// Parent-hash concat buffer (avoids 64 B stack frames).
    pub merge: [u8; 64],
}

impl Sha256Workspace {
    pub const fn new() -> Self {
        Self {
            state: INIT_STATE,
            w: [0u32; 64],
            block: [0u8; 64],
            merge: [0u8; 64],
        }
    }
}

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[inline(always)]
fn rotr(x: u32, n: u32) -> u32 {
    x.rotate_right(n)
}

#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
fn sig0(x: u32) -> u32 {
    rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
}

#[inline(always)]
fn sig1(x: u32) -> u32 {
    rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
}

#[inline(always)]
fn gam0(x: u32) -> u32 {
    rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
}

#[inline(always)]
fn gam1(x: u32) -> u32 {
    rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)
}

#[inline(never)]
fn compress_block_raw(state: &mut [u32; 8], w: &mut [u32; 64], block: &[u8; 64]) {
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for i in 16..64 {
        w[i] = gam1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(gam0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }

    let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
        state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
    );

    for i in 0..64 {
        let t1 = h
            .wrapping_add(sig1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let t2 = sig0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

fn reset_sha256(ws: &mut Sha256Workspace) {
    ws.state = INIT_STATE;
    ws.w.fill(0);
}

fn state_to_digest(state: &[u32; 8]) -> [u8; SHA256_LEN] {
    let mut out = [0u8; SHA256_LEN];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// SHA-256 digest using map-backed workspace (BPF-safe stack footprint).
#[inline(never)]
pub fn sha256_digest(data: &[u8], ws: &mut Sha256Workspace) -> [u8; SHA256_LEN] {
    reset_sha256(ws);

    let full_len = data.len();
    let mut offset = 0usize;

    while offset + 64 <= full_len {
        ws.block.copy_from_slice(&data[offset..offset + 64]);
        compress_block_raw(&mut ws.state, &mut ws.w, &ws.block);
        offset += 64;
    }

    let rem = full_len - offset;
    ws.block.fill(0);
    ws.block[..rem].copy_from_slice(&data[offset..]);
    ws.block[rem] = 0x80;
    if rem >= 56 {
        compress_block_raw(&mut ws.state, &mut ws.w, &ws.block);
        ws.block.fill(0);
    }
    let bit_len = (full_len as u64).wrapping_mul(8);
    ws.block[56..64].copy_from_slice(&bit_len.to_be_bytes());
    compress_block_raw(&mut ws.state, &mut ws.w, &ws.block);

    state_to_digest(&ws.state)
}

/// Parent Merkle node hash using workspace-backed SHA-256.
#[inline(never)]
pub fn parent_hash(
    left: &[u8; SHA256_LEN],
    right: &[u8; SHA256_LEN],
    ws: &mut Sha256Workspace,
) -> [u8; SHA256_LEN] {
    ws.merge[..SHA256_LEN].copy_from_slice(left);
    ws.merge[SHA256_LEN..].copy_from_slice(right);
    reset_sha256(ws);
    compress_block_raw(&mut ws.state, &mut ws.w, &ws.merge);
    ws.block.fill(0);
    ws.block[0] = 0x80;
    let bit_len = (512u64).to_be_bytes();
    ws.block[56..64].copy_from_slice(&bit_len);
    compress_block_raw(&mut ws.state, &mut ws.w, &ws.block);
    state_to_digest(&ws.state)
}
