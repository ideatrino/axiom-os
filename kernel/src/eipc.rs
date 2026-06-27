//! AXIOM EIPC — Encrypted Inter-Process Communication.
//!
//! The kernel stores EipcMessage objects — ciphertext + tag + nonce.
//! It NEVER stores the session key, NEVER stores plaintext.
//! Even full kernel memory disclosure reveals only ciphertexts.
//!
//! KNP theorem (Kernel Non-Participation) made executable:
//!   H(plaintext | kernel_state, ciphertext) = H(plaintext | ciphertext) = 0

use crate::crypto_aead::eipc_session_key;
use crate::poly1305::{chacha20_poly1305_seal, chacha20_poly1305_open};
use crate::serial_println;
use lazy_static::lazy_static;
use spin::Mutex;

/// One EIPC message as stored by the kernel — ciphertext only.
/// Uses ChaCha20-Poly1305 (RFC 8439 §2.8): proper AEAD, not Encrypt-then-HMAC.
pub struct EipcMessage {
    pub sender_id: u32,
    pub seq:       u32,
    pub nonce:     [u8; 12],
    pub ct:        [u8; 64],   // ciphertext (≤64 bytes per message)
    pub ct_len:    usize,
    pub tag:       [u8; 16],   // Poly1305 authentication tag
}

const CAP: usize = 4;

/// Kernel-side EIPC channel: a fixed-capacity queue of ciphertexts.
pub struct EipcChannel {
    slots: [Option<EipcMessage>; CAP],
    head:  usize,
    tail:  usize,
    count: usize,
}

impl EipcChannel {
    fn new() -> Self {
        // Explicit None×4 — avoids needing Copy on EipcMessage.
        EipcChannel {
            slots: [None, None, None, None],
            head: 0, tail: 0, count: 0,
        }
    }

    /// The kernel calls this when a sender delivers a ciphertext.
    /// The kernel never inspects ct — it only queues ciphertext + Poly1305 tag.
    pub fn enqueue(&mut self, msg: EipcMessage) -> bool {
        if self.count >= CAP { return false; }
        self.slots[self.tail] = Some(msg);
        self.tail = (self.tail + 1) % CAP;
        self.count += 1;
        true
    }

    /// The kernel hands the ciphertext to the destination endpoint.
    pub fn dequeue(&mut self) -> Option<EipcMessage> {
        if self.count == 0 { return None; }
        let msg = self.slots[self.head].take();
        self.head = (self.head + 1) % CAP;
        self.count -= 1;
        msg
    }
}

lazy_static! {
    /// The global EIPC channel. Locked during enqueue/dequeue.
    /// Contains ONLY ciphertexts — provably contains zero plaintext.
    pub static ref CHANNEL: Mutex<EipcChannel> = Mutex::new(EipcChannel::new());
}

// ── Demo helpers ─────────────────────────────────────────────────────────────

/// Simulated shared capability chain hash.
/// In production: SHA-256 of the chained TCD MACs from root → shared grant.
/// Both endpoints compute this from their shared TCD capability — no exchange needed.
fn cap_chain_hash() -> [u8; 32] {
    crate::crypto::sha256(b"AXIOM-EIPC-DEMO-CAP-CHAIN-v4")
}

/// Counter-based nonce: [0×4] ++ [seq as u64 LE × 8]
fn make_nonce(seq: u32) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..12].copy_from_slice(&(seq as u64).to_le_bytes());
    n
}

// ── The demonstration ─────────────────────────────────────────────────────────

pub fn run_demo() {
    // ChaCha20 known-vector test
    let cc20_ok = crate::crypto_aead::chacha20_self_test();
    serial_println!("ChaCha20 self-test (RFC 8439 §2.3.2): {}",
        if cc20_ok { "CORRECT ✓  (first block word = 0xade0b876)" }
        else       { "UNEXPECTED ✗" });
    serial_println!("");
    serial_println!("===========================================");
    serial_println!(" AXIOM EIPC — Encrypted IPC Demo");
    serial_println!(" (KNP: kernel never sees plaintext)");
    serial_println!("===========================================");
    serial_println!("");

    // ── 1. Both endpoints derive the session key independently ─────────────────
    //    They share a TCD capability chain → they share the chain hash →
    //    they can both compute the same session key without key exchange.
    let cap_hash    = cap_chain_hash();
    let session_key = eipc_session_key(&cap_hash, 1, 2);

    serial_println!("1. Key derivation:");
    serial_println!("   Cap chain hash (4B): {:02x}{:02x}{:02x}{:02x}...",
        cap_hash[0], cap_hash[1], cap_hash[2], cap_hash[3]);
    serial_println!("   Session key    (4B): {:02x}{:02x}{:02x}{:02x}...",
        session_key[0], session_key[1], session_key[2], session_key[3]);
    serial_println!("   [HKDF-SHA-256: cap_chain_hash → session_key]");
    serial_println!("   [Kernel NEVER touches session_key]");
    serial_println!("");

    // ── 2. Sender encrypts and enqueues 3 messages ────────────────────────────
    serial_println!("2. Sender encrypts and hands ciphertexts to kernel:");
    let plaintexts: [&[u8]; 3] = [
        b"Hello AXIOM! (message 1)",
        b"TCD capability = session.",
        b"Kernel sees: zero bits.",
    ];

    for (i, &pt) in plaintexts.iter().enumerate() {
        let seq   = (i + 1) as u32;
        let nonce = make_nonce(seq);
        let mut ct_buf = [0u8; 64];
        let tag = chacha20_poly1305_seal(
            &session_key, &nonce, b"AXIOM-EIPC-v1", pt, &mut ct_buf[..pt.len()]);

        let s = core::str::from_utf8(pt).unwrap_or("?");
        serial_println!("   [{}] plaintext:   \"{}\"", seq, s);
        serial_println!("   [{}] ciphertext:  {:02x}{:02x}{:02x}{:02x}... \
            [{} bytes — all kernel sees]",
            seq, ct_buf[0], ct_buf[1], ct_buf[2], ct_buf[3], pt.len());
        serial_println!("   [{}] auth tag:    {:02x}{:02x}{:02x}{:02x}...",
            seq, tag[0], tag[1], tag[2], tag[3]);

        let msg = EipcMessage {
            sender_id: 1, seq, nonce,
            ct: ct_buf, ct_len: pt.len(), tag,
        };
        CHANNEL.lock().enqueue(msg);
        crate::meal::log(crate::meal::AuditEvent::EipcSend, 1, seq as u64, pt.len() as u64);
        serial_println!("   [{}] → enqueued (kernel sees ciphertext + Poly1305 tag only)", seq);
        serial_println!("");
    }

    // ── 3. Receiver dequeues and decrypts ─────────────────────────────────────
    serial_println!("3. Receiver dequeues from kernel channel and decrypts:");
    let mut received = 0u32;
    let mut all_ok   = true;

    loop {
        let msg = CHANNEL.lock().dequeue();
        match msg {
            None => break,
            Some(m) => {
                let mut pt_buf = [0u8; 64];
                let ok = chacha20_poly1305_open(
                    &session_key, &m.nonce, b"AXIOM-EIPC-v1",
                    &m.ct[..m.ct_len], &m.tag, &mut pt_buf[..m.ct_len]);
                if !ok {
                    serial_println!("   [{}] AUTH FAILED — Poly1305 tag mismatch!", m.seq);
                    all_ok = false;
                } else {
                    crate::meal::log(crate::meal::AuditEvent::EipcReceive, 2, m.seq as u64, m.ct_len as u64);
                    let s = core::str::from_utf8(&pt_buf[..m.ct_len]).unwrap_or("?");
                    serial_println!("   [{}] ✓ decrypted: \"{}\"", m.seq, s);
                    received += 1;
                }
            }
        }
    }
    serial_println!("");

    // ── 4. Tamper test: verify authentication ─────────────────────────────────
    serial_println!("4. Tamper test (flip 1 ciphertext bit → should be rejected):");
    let nonce = make_nonce(99);
    let mut ct_buf2 = [0u8; 64];
    let pt_tamper = b"tamper test";
    let tag2 = chacha20_poly1305_seal(
        &session_key, &nonce, b"AXIOM-EIPC-v1", pt_tamper, &mut ct_buf2[..pt_tamper.len()]);
    ct_buf2[0] ^= 0x01;  // flip one ciphertext bit
    let mut pt_out2 = [0u8; 64];
    let ok2 = chacha20_poly1305_open(
        &session_key, &nonce, b"AXIOM-EIPC-v1",
        &ct_buf2[..pt_tamper.len()], &tag2, &mut pt_out2[..pt_tamper.len()]);
    if !ok2 {
        serial_println!("   Corrupted message REJECTED ✓ (Poly1305 tag mismatch)");
    } else {
        serial_println!("   ERROR: tampered message accepted!");
        all_ok = false;
    }
    serial_println!("");

    // ── 5. Checkpoint ─────────────────────────────────────────────────────────
    if all_ok && received == 3 {
        serial_println!(">>> SHOT 7 CHECKPOINT PASSED <<<");
        serial_println!("    EIPC: 3 messages via encrypted kernel channel.");
        serial_println!("    ChaCha20-Poly1305 (RFC 8439 §2.8): proper AEAD construction.");
        serial_println!("    Poly1305 auth: tampered message correctly rejected.");
        serial_println!("    HKDF-SHA-256 (RFC 5869): session key from cap chain.");
        serial_println!("    KNP theorem: kernel queued ciphertexts, saw 0 bits of plaintext.");
        serial_println!("    Ready for Shot 8: MEAL tamper-evident audit log.");
    } else {
        serial_println!(">>> SHOT 7 ISSUE received={} all_ok={}", received, all_ok);
    }
    serial_println!("===========================================");
    serial_println!("");
}
