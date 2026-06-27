//! Self-contained keyed hash for the capability demo.
//!
//! ⚠️  DEMO-GRADE ONLY. This is NOT cryptographically secure. It exists so the
//! capability demo runs without pulling in a full HMAC-SHA-256 implementation.
//! In the real kernel, replace every call here with your verified
//! `crypto.rs` HMAC-SHA-256 (RFC 2104), which you already have.
//!
//! This is the FNV-1a hash mixed with a key — fine for a "does the tag match"
//! demonstration, useless against an actual attacker. The whole point of the
//! real AXIOM is that the tag is a real MAC; this placeholder just lets the
//! control flow run end-to-end.

/// A 64-bit keyed hash of `data` under `key`. Demo-grade, not secure.
pub fn keyed_hash(key: u64, data: &[u8]) -> u64 {
    // FNV-1a 64-bit constants.
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET ^ key;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    // A little extra mixing of the key at the end.
    hash ^= key.rotate_left(32);
    hash = hash.wrapping_mul(FNV_PRIME);
    hash
}

/// Constant-time-ish comparison of two tags. (Demo-grade: the real version
/// in your crypto.rs should be genuinely constant-time.)
pub fn tags_equal(a: u64, b: u64) -> bool {
    let diff = a ^ b;
    diff == 0
}
