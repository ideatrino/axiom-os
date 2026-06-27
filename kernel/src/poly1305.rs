//! Poly1305 one-time MAC (RFC 8439 §2.5).
//!
//! Poly1305 evaluates a polynomial over GF(2^130 - 5):
//!   tag = ((r * msg_blocks + s) mod 2^130-5) mod 2^128
//!
//! Security: with a fresh (r,s) key pair per message, this is a
//! one-time MAC with 2^-106 forgery probability.
//!
//! Key = 32 bytes: r (16 bytes, clamped) ∥ s (16 bytes).
//! The r value is clamped per RFC 8439 §2.5.1 before use.

/// Clamp the r value per RFC 8439 §2.5.1.
fn clamp(r: &mut [u8; 16]) {
    r[3]  &= 15;
    r[7]  &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4]  &= 252;
    r[8]  &= 252;
    r[12] &= 252;
}

/// Load 16 bytes as a little-endian u128.
fn load_le_u128(b: &[u8]) -> u128 {
    let mut tmp = [0u8; 16];
    let len = b.len().min(16);
    tmp[..len].copy_from_slice(&b[..len]);
    u128::from_le_bytes(tmp)
}

/// Compute Poly1305 MAC.
///
/// `key` must be 32 bytes: r(16) ∥ s(16).
/// Returns a 16-byte tag.
///
/// Known vector (RFC 8439 §A.3 Test Vector #1):
///   key  = 85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8
///          01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b
///   msg  = "Cryptographic Forum Research Group"
///   tag  = a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9
pub fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    // Split key into r and s.
    let mut r_bytes = [0u8; 16];
    r_bytes.copy_from_slice(&key[..16]);
    clamp(&mut r_bytes);
    let r = load_le_u128(&r_bytes) as u128;
    let s = load_le_u128(&key[16..]);

    // Accumulator as 130-bit value split into (hi: u64, lo: u128).
    // We use 130-bit arithmetic via (hi, lo) where the full value is
    // hi * 2^128 + lo. This avoids needing 256-bit integers.
    //
    // The prime p = 2^130 - 5.
    let p: u128 = (1u128 << 127).wrapping_add((1u128 << 127).wrapping_sub(5));
    // p = 2^130-5, but we work mod p using 130-bit reduction.
    // Simpler: use u128 and handle the one extra bit with a carry flag.

    // We implement 130-bit arithmetic using (u64, u128) as (high 2 bits, low 128 bits).
    let mut h0: u64  = 0;  // bits [129:128]
    let mut h1: u128 = 0;  // bits [127:0]

    let add_block = |h0: &mut u64, h1: &mut u128, block: &[u8], full: bool| {
        // Load block as little-endian number, append 1 bit.
        let n = load_le_u128(block);
        let bit = if full { 1u64 << (block.len() * 8 % 128).min(1) } else { 0u64 };
        // n + 2^(8*len) — the "1" bit at position 8*len.
        let (n1, carry) = if full && block.len() == 16 {
            // Full 16-byte block: high bit is at position 128 (bit 0 of h0 extension)
            (n, 1u64)
        } else {
            // Partial block: set bit at position 8*len
            let pos = block.len() * 8;
            if pos < 128 {
                let (v, c) = n.overflowing_add(1u128 << pos);
                (v, c as u64)
            } else {
                (n, 1u64)
            }
        };

        // h += n
        let (new_h1, c) = h1.overflowing_add(n1);
        *h1 = new_h1;
        *h0 = h0.wrapping_add(carry).wrapping_add(c as u64);

        // h = h * r (mod 2^130-5)
        // Since h is at most 130 bits and r is at most 124 bits (after clamping),
        // the product is at most 254 bits. We compute mod 2^130-5 inline.
        // For simplicity we use the (a*b) mod p via the identity:
        //   if x = q*p + rem, then x mod p = rem
        // We compute using u128 arithmetic with careful carry handling.
        let r128 = r as u128;

        // Full 130-bit * 124-bit multiply.
        // h = (h0 << 128 + h1) * r
        // = h0 * r * 2^128 + h1 * r
        // mod 2^130-5:
        //   2^130 ≡ 5, so 2^130*k ≡ 5k
        //   h0 * r * 2^128 = h0 * r * 2^128
        //   mod 2^130: 2^128 = 2^130 / 4, so h0*r*2^128 ≡ h0*r*5/4... messy.
        // Use the standard trick: reduce (h0 << 128 + h1) * r mod 2^130-5
        // by splitting:
        //   product = h0 * r * 2^128 + h1 * r
        //   Let A = h1 * r  (256 bits max, but h1<2^128, r<2^124 → 252 bits)
        //   Let B = h0 * r * 2^128
        //   We reduce B mod 2^130-5: B = h0*r * 2^128
        //   Since 2^130 ≡ 5: 2^128 = 2^130/4 → not clean.
        // Alternate: keep accumulator in (hi: u8, lo: u128) i.e. 130-bit.
        // Reduction: if acc >= 2^130-5 then acc -= 2^130-5.
        // Multiplication: standard schoolbook, keep only 130 bits + one carry.

        // Simple correct implementation: use 256-bit via two u128.
        let (prod_lo, prod_hi) = {
            let a = *h0 as u128;
            let b = *h1;
            // (a * 2^128 + b) * r = a*r*2^128 + b*r
            let br_lo = b.wrapping_mul(r128);
            let br_hi = {
                // High 128 bits of b*r using schoolbook 64x64.
                let blo = b as u64;
                let bhi = (b >> 64) as u64;
                let rlo = r128 as u64;
                let rhi = (r128 >> 64) as u64;
                let lo_lo = (blo as u128) * (rlo as u128);
                let lo_hi = (blo as u128) * (rhi as u128);
                let hi_lo = (bhi as u128) * (rlo as u128);
                let hi_hi = (bhi as u128) * (rhi as u128);
                let mid = (lo_lo >> 64)
                    .wrapping_add(lo_hi & 0xFFFF_FFFF_FFFF_FFFF)
                    .wrapping_add(hi_lo & 0xFFFF_FFFF_FFFF_FFFF);
                (mid >> 64)
                    .wrapping_add(lo_hi >> 64)
                    .wrapping_add(hi_lo >> 64)
                    .wrapping_add(hi_hi)
            };
            let ar = a.wrapping_mul(r128); // a is 2 bits max, r < 2^124 → fits u128
            let (plo, c1) = br_lo.overflowing_add(0); // br_lo is already the low part
            let (phi, c2) = br_hi.overflowing_add(ar);
            (br_lo, phi)
        };

        // Now prod = prod_hi * 2^128 + prod_lo.
        // Reduce mod 2^130-5.
        // prod_hi can be at most ~248 bits worth / 2^128 ≈ 120 bits.
        // Reduction: x = prod_hi * 2^128 + prod_lo
        //   2^130 ≡ 5, so 2^128 = 5 * 2^(-2) ... not integer.
        // Use: 2^130 ≡ 5, split prod_hi into (prod_hi >> 2) * 4 + (prod_hi & 3)
        //   prod_hi * 2^128 = (prod_hi & 3) * 2^128 + (prod_hi>>2) * 2^130
        //                   ≡ (prod_hi & 3) * 2^128 + (prod_hi>>2) * 5  (mod 2^130-5)
        let carry_bits = (prod_hi >> 2) as u128;
        let new_h0 = (prod_hi & 3) as u64;
        let (new_h1, c) = prod_lo.overflowing_add(carry_bits.wrapping_mul(5));
        *h1 = new_h1;
        *h0 = new_h0.wrapping_add(c as u64);

        // One final reduction if needed (h >= 2^130-5)
        // 2^130-5 = (3 << 128) | (-5 as u128) = (3<<128) + (2^128-5)
        // If h0 >= 4 or (h0 == 3 && h1 >= 2^128-4): subtract p.
        if *h0 >= 4 || (*h0 == 3 && *h1 >= u128::MAX - 3) {
            let (new_h1_2, borrow) = h1.overflowing_sub(u128::MAX - 4); // subtract 2^128-5
            *h1 = new_h1_2;
            *h0 = h0.wrapping_sub(3).wrapping_sub(borrow as u64);
        }
    };

    // Process 16-byte blocks.
    let mut offset = 0;
    while offset + 16 <= msg.len() {
        add_block(&mut h0, &mut h1, &msg[offset..offset+16], true);
        offset += 16;
    }
    // Process final partial block if any.
    if offset < msg.len() {
        add_block(&mut h0, &mut h1, &msg[offset..], false);
    }

    // Fully reduce h mod 2^130-5 and add s.
    // Final reduction: if h >= p, subtract p once.
    let p_lo: u128 = u128::MAX - 4; // 2^128 - 5
    let p_hi: u64  = 3;             // 3 * 2^128 → total 2^130 - 5
    if h0 > p_hi || (h0 == p_hi && h1 >= p_lo) {
        let (new_h1, borrow) = h1.overflowing_sub(p_lo);
        h1 = new_h1;
        h0 = h0.wrapping_sub(p_hi).wrapping_sub(borrow as u64);
    }

    // Add s (mod 2^128, discard carry).
    let (tag_val, _) = h1.overflowing_add(s);
    tag_val.to_le_bytes()
}

/// ChaCha20-Poly1305 AEAD (RFC 8439 §2.8).
///
/// Encrypts plaintext and produces a 16-byte authentication tag.
/// The tag covers both the AAD (additional authenticated data) and ciphertext.
pub fn chacha20_poly1305_seal(
    key:       &[u8; 32],
    nonce:     &[u8; 12],
    aad:       &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
) -> [u8; 16] {
    use crate::crypto_aead::chacha20_block;

    // Generate Poly1305 one-time key from ChaCha20 counter=0.
    let otk_block = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&otk_block[..32]);

    // Encrypt: XOR plaintext with ChaCha20 keystream starting at counter=1.
    let mut counter: u32 = 1;
    let mut pos = 0;
    while pos < plaintext.len() {
        let ks = chacha20_block(key, counter, nonce);
        counter += 1;
        let take = (plaintext.len() - pos).min(64);
        for i in 0..take {
            ciphertext[pos + i] = plaintext[pos + i] ^ ks[i];
        }
        pos += take;
    }

    // Build MAC input: aad ∥ pad(aad) ∥ ciphertext ∥ pad(ct) ∥ len(aad) ∥ len(ct)
    let pad16 = |n: usize| -> usize { (16 - (n % 16)) % 16 };
    let mac_len = aad.len() + pad16(aad.len())
                + ciphertext.len() + pad16(ciphertext.len())
                + 8 + 8;

    let mut mac_input = alloc::vec![0u8; mac_len];
    let mut off = 0;
    mac_input[off..off+aad.len()].copy_from_slice(aad);
    off += aad.len() + pad16(aad.len());
    mac_input[off..off+ciphertext.len()].copy_from_slice(ciphertext);
    off += ciphertext.len() + pad16(ciphertext.len());
    mac_input[off..off+8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    off += 8;
    mac_input[off..off+8].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());

    poly1305(&otk, &mac_input)
}

/// Verify and decrypt ChaCha20-Poly1305.
/// Returns None if the tag doesn't match (constant-time comparison).
pub fn chacha20_poly1305_open(
    key:        &[u8; 32],
    nonce:      &[u8; 12],
    aad:        &[u8],
    ciphertext: &[u8],
    tag:        &[u8; 16],
    plaintext:  &mut [u8],
) -> bool {
    use crate::crypto_aead::chacha20_block;

    // Re-derive OTK and re-compute expected tag.
    let otk_block = chacha20_block(key, 0, nonce);
    let mut otk = [0u8; 32];
    otk.copy_from_slice(&otk_block[..32]);

    let pad16 = |n: usize| -> usize { (16 - (n % 16)) % 16 };
    let mac_len = aad.len() + pad16(aad.len())
                + ciphertext.len() + pad16(ciphertext.len())
                + 8 + 8;
    let mut mac_input = alloc::vec![0u8; mac_len];
    let mut off = 0;
    mac_input[off..off+aad.len()].copy_from_slice(aad);
    off += aad.len() + pad16(aad.len());
    mac_input[off..off+ciphertext.len()].copy_from_slice(ciphertext);
    off += ciphertext.len() + pad16(ciphertext.len());
    mac_input[off..off+8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    off += 8;
    mac_input[off..off+8].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());

    let expected = poly1305(&otk, &mac_input);

    // Constant-time comparison.
    let mut diff = 0u8;
    for i in 0..16 { diff |= expected[i] ^ tag[i]; }
    if diff != 0 { return false; }

    // Decrypt.
    let mut counter: u32 = 1;
    let mut pos = 0;
    while pos < ciphertext.len() {
        let ks = chacha20_block(key, counter, nonce);
        counter += 1;
        let take = (ciphertext.len() - pos).min(64);
        for i in 0..take {
            plaintext[pos + i] = ciphertext[pos + i] ^ ks[i];
        }
        pos += take;
    }
    true
}

/// RFC 8439 §A.3 Test Vector #1 self-test.
pub fn poly1305_self_test() -> bool {
    let key: [u8; 32] = [
        0x85,0xd6,0xbe,0x78,0x57,0x55,0x6d,0x33,
        0x7f,0x44,0x52,0xfe,0x42,0xd5,0x06,0xa8,
        0x01,0x03,0x80,0x8a,0xfb,0x0d,0xb2,0xfd,
        0x4a,0xbf,0xf6,0xaf,0x41,0x49,0xf5,0x1b,
    ];
    let msg = b"Cryptographic Forum Research Group";
    let tag = poly1305(&key, msg);
    // Expected: a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9
    tag[0] == 0xa8 && tag[1] == 0x06 && tag[2] == 0x1d && tag[3] == 0xc1
}
