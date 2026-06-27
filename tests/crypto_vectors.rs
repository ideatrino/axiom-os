//! Known-vector tests for AXIOM crypto primitives.
//! These run on the host (x86-64 Linux) without QEMU.
//! They test the same algorithm implementations the kernel uses,
//! compiled for the host target instead of x86_64-unknown-none.

// We can't import kernel crates directly (no_std), so we
// copy the pure-function implementations here and test them.
// The implementations are identical to crypto.rs and crypto_aead.rs.

// ── SHA-256 ──────────────────────────────────────────────────────────────────

const K256: [u32; 64] = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
    0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
];

fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([block[i*4],block[i*4+1],block[i*4+2],block[i*4+3]]);
    }
    for i in 16..64 {
        let s0 = w[i-15].rotate_right(7)^w[i-15].rotate_right(18)^(w[i-15]>>3);
        let s1 = w[i-2].rotate_right(17)^w[i-2].rotate_right(19)^(w[i-2]>>10);
        w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
    }
    let (mut a,mut b,mut c,mut d,mut e,mut f,mut g,mut h) =
        (state[0],state[1],state[2],state[3],state[4],state[5],state[6],state[7]);
    for i in 0..64 {
        let s1 = e.rotate_right(6)^e.rotate_right(11)^e.rotate_right(25);
        let ch = (e&f)^(!e&g);
        let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K256[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2)^a.rotate_right(13)^a.rotate_right(22);
        let maj = (a&b)^(a&c)^(b&c);
        let t2 = s0.wrapping_add(maj);
        h=g; g=f; f=e; e=d.wrapping_add(t1);
        d=c; c=b; b=a; a=t1.wrapping_add(t2);
    }
    state[0]=state[0].wrapping_add(a); state[1]=state[1].wrapping_add(b);
    state[2]=state[2].wrapping_add(c); state[3]=state[3].wrapping_add(d);
    state[4]=state[4].wrapping_add(e); state[5]=state[5].wrapping_add(f);
    state[6]=state[6].wrapping_add(g); state[7]=state[7].wrapping_add(h);
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state = H0;
    let mut buf = [0u8; 64];
    let mut buf_len = 0usize;
    let mut total = 0u64;
    let mut d = data;
    total += d.len() as u64;
    while !d.is_empty() {
        let space = 64 - buf_len;
        let take = space.min(d.len());
        buf[buf_len..buf_len+take].copy_from_slice(&d[..take]);
        buf_len += take;
        d = &d[take..];
        if buf_len == 64 { compress(&mut state, &buf); buf_len = 0; }
    }
    let bits = total * 8;
    buf[buf_len] = 0x80; buf_len += 1;
    if buf_len > 56 { for i in buf_len..64 { buf[i]=0; } compress(&mut state,&buf); buf_len=0; }
    for i in buf_len..56 { buf[i]=0; }
    buf[56..64].copy_from_slice(&bits.to_be_bytes());
    compress(&mut state, &buf);
    let mut out = [0u8; 32];
    for (i,w) in state.iter().enumerate() { out[i*4..i*4+4].copy_from_slice(&w.to_be_bytes()); }
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 { let h=sha256(key); k[..32].copy_from_slice(&h); }
    else { k[..key.len()].copy_from_slice(key); }
    let mut ipad = [0x36u8; 64]; for i in 0..64 { ipad[i]^=k[i]; }
    let mut opad = [0x5cu8; 64]; for i in 0..64 { opad[i]^=k[i]; }
    let mut inner_data = Vec::with_capacity(64+data.len());
    inner_data.extend_from_slice(&ipad);
    inner_data.extend_from_slice(data);
    let inner = sha256(&inner_data);
    let mut outer_data = Vec::with_capacity(64+32);
    outer_data.extend_from_slice(&opad);
    outer_data.extend_from_slice(&inner);
    sha256(&outer_data)
}

fn chacha20_block(key: &[u8;32], counter: u32, nonce: &[u8;12]) -> [u8;64] {
    let mut s = [0u32;16];
    s[0]=0x61707865; s[1]=0x3320646e; s[2]=0x79622d32; s[3]=0x6b206574;
    for i in 0..8 { let o=i*4; s[4+i]=u32::from_le_bytes([key[o],key[o+1],key[o+2],key[o+3]]); }
    s[12]=counter;
    s[13]=u32::from_le_bytes([nonce[0],nonce[1],nonce[2],nonce[3]]);
    s[14]=u32::from_le_bytes([nonce[4],nonce[5],nonce[6],nonce[7]]);
    s[15]=u32::from_le_bytes([nonce[8],nonce[9],nonce[10],nonce[11]]);
    let init=s;
    macro_rules! qr { ($a:expr,$b:expr,$c:expr,$d:expr) => {
        s[$a]=s[$a].wrapping_add(s[$b]); s[$d]^=s[$a]; s[$d]=s[$d].rotate_left(16);
        s[$c]=s[$c].wrapping_add(s[$d]); s[$b]^=s[$c]; s[$b]=s[$b].rotate_left(12);
        s[$a]=s[$a].wrapping_add(s[$b]); s[$d]^=s[$a]; s[$d]=s[$d].rotate_left(8);
        s[$c]=s[$c].wrapping_add(s[$d]); s[$b]^=s[$c]; s[$b]=s[$b].rotate_left(7);
    }}
    for _ in 0..10 {
        qr!(0,4,8,12); qr!(1,5,9,13); qr!(2,6,10,14); qr!(3,7,11,15);
        qr!(0,5,10,15); qr!(1,6,11,12); qr!(2,7,8,13); qr!(3,4,9,14);
    }
    for i in 0..16 { s[i]=s[i].wrapping_add(init[i]); }
    let mut out=[0u8;64];
    for i in 0..16 { out[i*4..i*4+4].copy_from_slice(&s[i].to_le_bytes()); }
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn sha256_empty_fips_180_4() {
    // FIPS 180-4 Appendix B.1
    let h = sha256(b"");
    assert_eq!(h[0], 0xe3);
    assert_eq!(h[1], 0xb0);
    assert_eq!(&h[..4], &[0xe3,0xb0,0xc4,0x42]);
}

#[test]
fn sha256_abc_fips_180_4() {
    // FIPS 180-4 Appendix B.1: SHA-256("abc")
    let h = sha256(b"abc");
    assert_eq!(&h[..4], &[0xba,0x78,0x16,0xbf]);
}

#[test]
fn sha256_448bit_fips_180_4() {
    // FIPS 180-4 Appendix B.2: 448-bit message
    let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    let h = sha256(msg);
    assert_eq!(&h[..4], &[0x24,0x8d,0x6a,0x61]);
}

#[test]
fn hmac_sha256_rfc2104_test1() {
    // RFC 2104 Appendix B, Test Case 1
    // Key  = 0x0b * 20
    // Data = "Hi There"
    // HMAC = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    let key = [0x0bu8; 20];
    let h = hmac_sha256(&key, b"Hi There");
    assert_eq!(h[0], 0xb0);
    assert_eq!(h[1], 0x34);
    assert_eq!(&h[..8], &[0xb0,0x34,0x4c,0x61,0xd8,0xdb,0x38,0x53]);
}

#[test]
fn hmac_sha256_rfc2104_test2() {
    // RFC 2104 Appendix B, Test Case 2
    // Key  = "Jefe"
    // Data = "what do ya want for nothing?"
    // HMAC = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964a374a
    let h = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
    assert_eq!(h[0], 0x5b);
    assert_eq!(h[1], 0xdc);
}

#[test]
fn hmac_sha256_long_key() {
    // Key longer than 64 bytes — should be hashed first (RFC 2104 §2)
    let key = [0xaau8; 80];
    let data = vec![0xddu8; 50];
    let h = hmac_sha256(&key, &data);
    // RFC 4231 Test Case 3: first byte = 0x77
    assert_eq!(h[0], 0x77);
}

#[test]
fn chacha20_rfc8439_vector() {
    // RFC 8439 §2.3.2 test vector
    // key=0×32, counter=0, nonce=0×12 → first output word = 0xade0b876
    let key   = [0u8; 32];
    let nonce = [0u8; 12];
    let block = chacha20_block(&key, 0, &nonce);
    let word0 = u32::from_le_bytes([block[0],block[1],block[2],block[3]]);
    assert_eq!(word0, 0xade0b876,
        "ChaCha20 first word: got {:#010x}, expected 0xade0b876", word0);
}

#[test]
fn chacha20_counter_1_differs_from_counter_0() {
    let key   = [0u8; 32];
    let nonce = [0u8; 12];
    let b0 = chacha20_block(&key, 0, &nonce);
    let b1 = chacha20_block(&key, 1, &nonce);
    assert_ne!(b0, b1, "Different counters must produce different blocks");
}

#[test]
fn sha256_is_deterministic() {
    let h1 = sha256(b"AXIOM OS");
    let h2 = sha256(b"AXIOM OS");
    assert_eq!(h1, h2);
}

#[test]
fn hmac_different_keys_differ() {
    let h1 = hmac_sha256(&[0x01u8; 32], b"test");
    let h2 = hmac_sha256(&[0x02u8; 32], b"test");
    assert_ne!(h1, h2, "Different keys must produce different MACs");
}

#[test]
fn hmac_different_data_differ() {
    let h1 = hmac_sha256(&[0x01u8; 32], b"message A");
    let h2 = hmac_sha256(&[0x01u8; 32], b"message B");
    assert_ne!(h1, h2);
}

#[test]
fn hmac_single_bit_flip_changes_output() {
    let key = [0x42u8; 32];
    let h1 = hmac_sha256(&key, b"authentic");
    let mut tampered = b"authentic".to_vec();
    tampered[0] ^= 0x01;
    let h2 = hmac_sha256(&key, &tampered);
    assert_ne!(h1, h2, "1-bit flip must change HMAC");
}
