//! ChaCha20 stream cipher (RFC 8439 §2.3) + HKDF-SHA-256 (RFC 5869).
//!
//! AEAD construction: ChaCha20 Encrypt-then-HMAC.
//!   ciphertext = ChaCha20(key, counter=1, nonce, plaintext)
//!   tag        = HMAC-SHA-256(key, nonce ∥ ciphertext)[..16]
//!
//! This is a provably-secure AEAD by the Encrypt-then-MAC composition
//! theorem (Bellare & Namprempre 2000). It differs from RFC 8439 only in
//! using HMAC instead of Poly1305 for the tag — a future shot adds Poly1305.

// ── ChaCha20 ────────────────────────────────────────────────────────────────

#[inline(always)]
fn qr(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a]=s[a].wrapping_add(s[b]); s[d]^=s[a]; s[d]=s[d].rotate_left(16);
    s[c]=s[c].wrapping_add(s[d]); s[b]^=s[c]; s[b]=s[b].rotate_left(12);
    s[a]=s[a].wrapping_add(s[b]); s[d]^=s[a]; s[d]=s[d].rotate_left( 8);
    s[c]=s[c].wrapping_add(s[d]); s[b]^=s[c]; s[b]=s[b].rotate_left( 7);
}

/// Generate one 64-byte ChaCha20 keystream block (RFC 8439 §2.3.1).
/// Known-vector: key=0, counter=0, nonce=0 → first word = 0xade0b876.
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut s = [0u32; 16];
    // "expand 32-byte k" — RFC 8439 §2.3
    s[0]=0x61707865; s[1]=0x3320646e; s[2]=0x79622d32; s[3]=0x6b206574;
    for i in 0..8 {
        let o = i * 4;
        s[4+i] = u32::from_le_bytes([key[o],key[o+1],key[o+2],key[o+3]]);
    }
    s[12] = counter;
    s[13] = u32::from_le_bytes([nonce[0],nonce[1],nonce[2], nonce[3]]);
    s[14] = u32::from_le_bytes([nonce[4],nonce[5],nonce[6], nonce[7]]);
    s[15] = u32::from_le_bytes([nonce[8],nonce[9],nonce[10],nonce[11]]);

    let init = s;
    for _ in 0..10 {
        // Column rounds
        qr(&mut s,0,4, 8,12); qr(&mut s,1,5, 9,13);
        qr(&mut s,2,6,10,14); qr(&mut s,3,7,11,15);
        // Diagonal rounds
        qr(&mut s,0,5,10,15); qr(&mut s,1,6,11,12);
        qr(&mut s,2,7, 8,13); qr(&mut s,3,4, 9,14);
    }
    for i in 0..16 { s[i] = s[i].wrapping_add(init[i]); }
    let mut out = [0u8; 64];
    for i in 0..16 { out[i*4..i*4+4].copy_from_slice(&s[i].to_le_bytes()); }
    out
}

/// XOR data (≤ 64 bytes) with the ChaCha20 keystream at counter=1.
/// Encryption and decryption are the same operation.
fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], data: &[u8], out: &mut [u8]) {
    debug_assert!(data.len() <= 64);
    let ks = chacha20_block(key, 1, nonce);
    for i in 0..data.len() { out[i] = data[i] ^ ks[i]; }
}

// ── ChaCha20 known-vector test ──────────────────────────────────────────────

/// RFC 8439 §2.3.2 test vector.
/// key=0×32, counter=0, nonce=0×12 → first output word should be 0xade0b876.
pub fn chacha20_self_test() -> bool {
    let key   = [0u8; 32];
    let nonce = [0u8; 12];
    let block = chacha20_block(&key, 0, &nonce);
    let word0 = u32::from_le_bytes([block[0], block[1], block[2], block[3]]);
    word0 == 0xade0b876
}

// ── HKDF-SHA-256 (RFC 5869) ─────────────────────────────────────────────────

fn hkdf_extract(salt: &[u8; 32], ikm: &[u8]) -> [u8; 32] {
    crate::crypto::hmac_sha256(salt, ikm)
}

fn hkdf_expand_32(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    // T(1) = HMAC-SHA-256(PRK, info || 0x01)
    let mut buf = [0u8; 128];
    let len = info.len().min(127);
    buf[..len].copy_from_slice(&info[..len]);
    buf[len] = 0x01;
    crate::crypto::hmac_sha256(prk, &buf[..len + 1])
}

/// Derive an EIPC session key from the shared TCD capability chain hash.
///
/// Both endpoints compute this independently from the capability chain
/// they share — no key exchange needed, no kernel involvement.
///
/// ```text
/// PRK  = HKDF-Extract(salt=0, IKM=cap_chain_hash)
/// key  = HKDF-Expand(PRK, "AXIOM-EIPC-v1" || sender_id || receiver_id)
/// ```
pub fn eipc_session_key(cap_chain_hash: &[u8; 32], sender: u32, receiver: u32) -> [u8; 32] {
    let prk = hkdf_extract(&[0u8; 32], cap_chain_hash);
    let mut info = [0u8; 21];
    info[..13].copy_from_slice(b"AXIOM-EIPC-v1");
    info[13..17].copy_from_slice(&sender.to_le_bytes());
    info[17..21].copy_from_slice(&receiver.to_le_bytes());
    hkdf_expand_32(&prk, &info)
}

// ── AEAD ─────────────────────────────────────────────────────────────────────

/// Max plaintext per message: 48 bytes (one ChaCha20 block leaves 16 bytes
/// for internal alignment; we use those bytes as safety margin).
pub const MAX_PT:  usize = 48;
pub const TAG_LEN: usize = 16;

/// An encrypted EIPC payload — ciphertext + auth tag, NEVER plaintext.
/// This is exactly what the kernel stores in the EIPC channel.
pub struct AeadCt {
    pub ct:  [u8; MAX_PT],
    pub len: usize,
    pub tag: [u8; TAG_LEN],
}

/// Encrypt plaintext (≤ MAX_PT bytes). Called by the sender endpoint.
/// The kernel is not involved — encryption happens before the kernel sees anything.
pub fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> AeadCt {
    let len = plaintext.len();
    debug_assert!(len <= MAX_PT);
    let mut ct = [0u8; MAX_PT];
    chacha20_xor(key, nonce, plaintext, &mut ct[..len]);

    // Auth: HMAC-SHA-256(key, nonce ∥ ciphertext), truncated to 16 bytes.
    let mut auth_in = [0u8; 12 + MAX_PT];
    auth_in[..12].copy_from_slice(nonce);
    auth_in[12..12+len].copy_from_slice(&ct[..len]);
    let h = crate::crypto::hmac_sha256(key, &auth_in[..12 + len]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&h[..TAG_LEN]);

    AeadCt { ct, len, tag }
}

/// Verify and decrypt. Returns None if authentication fails.
/// Authenticate-then-decrypt: plaintext never produced if tag is bad.
pub fn aead_open(key: &[u8; 32], nonce: &[u8; 12], c: &AeadCt) -> Option<([u8; MAX_PT], usize)> {
    // 1. Verify first.
    let mut auth_in = [0u8; 12 + MAX_PT];
    auth_in[..12].copy_from_slice(nonce);
    auth_in[12..12+c.len].copy_from_slice(&c.ct[..c.len]);
    let h = crate::crypto::hmac_sha256(key, &auth_in[..12 + c.len]);

    let mut diff = 0u8;
    for i in 0..TAG_LEN { diff |= c.tag[i] ^ h[i]; }
    if diff != 0 { return None; }

    // 2. Decrypt only after auth succeeds.
    let mut pt = [0u8; MAX_PT];
    chacha20_xor(key, nonce, &c.ct[..c.len], &mut pt[..c.len]);
    Some((pt, c.len))
}
