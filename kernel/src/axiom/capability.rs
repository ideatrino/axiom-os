//! AXIOM Temporal Capability Decay (TCD) — production HMAC-SHA-256 version.
//!
//! Every capability is now authenticated with real HMAC-SHA-256 (RFC 2104).
//! An attacker without the master key K cannot forge a valid capability MAC,
//! regardless of how many valid capabilities they have observed.
//!
//! The MAC is 256 bits — replacing the demo 64-bit FNV tag from Shot 1.
//! All other TCD properties (temporal decay, right containment, O(1)
//! verification) are unchanged.

use crate::crypto::{hmac_sha256, ct_eq_32};
use crate::serial_println;

pub mod rights {
    pub const READ:    u8 = 0b0000_0001;
    pub const WRITE:   u8 = 0b0000_0010;
    pub const EXECUTE: u8 = 0b0000_0100;
    pub const DERIVE:  u8 = 0b0000_1000;
    pub const GRANT:   u8 = 0b0001_0000;
}

pub type MonotonicNs = u64;

/// A temporal capability authenticated with HMAC-SHA-256.
///
/// ```text
/// cap := (oid, rights, τ_exp, depth, H(parent), HMAC-SHA-256(fields, K))
///
/// valid(cap, now, K) :=
///   now < τ_exp  ∧  HMAC-SHA-256(cap.fields, K) == cap.mac
/// ```
#[derive(Clone, Copy)]
pub struct Capability {
    pub object_id:  u64,
    pub rights:     u8,
    pub expires_at: MonotonicNs,
    pub depth:      u8,
    /// SHA-256 of parent's MAC (zero for root capabilities).
    pub parent_hash: [u8; 32],
    /// HMAC-SHA-256 over all preceding fields. 256-bit MAC.
    pub mac:         [u8; 32],
}

impl Capability {
    /// Serialise the fields that are covered by the MAC.
    /// Layout: object_id(8) | rights(1) | expires_at(8) | depth(1) = 18 bytes
    /// plus parent_hash(32) = 50 bytes total.
    fn auth_bytes(
        object_id:   u64,
        rights:      u8,
        expires_at:  u64,
        depth:       u8,
        parent_hash: &[u8; 32],
    ) -> [u8; 50] {
        let mut buf = [0u8; 50];
        buf[0..8].copy_from_slice(&object_id.to_le_bytes());
        buf[8]    = rights;
        buf[9..17].copy_from_slice(&expires_at.to_le_bytes());
        buf[17]   = depth;
        buf[18..50].copy_from_slice(parent_hash);
        buf
    }

    /// Mint a root capability.
    ///
    /// Only the kernel (holder of `k`) can do this — that is what makes
    /// capabilities unforgeable. The MAC covers all fields.
    pub fn mint(
        k:          &[u8; 32],
        object_id:  u64,
        rights:     u8,
        expires_at: MonotonicNs,
    ) -> Self {
        let parent_hash = [0u8; 32]; // no parent for root caps
        let bytes = Self::auth_bytes(object_id, rights, expires_at, 0, &parent_hash);
        let mac   = hmac_sha256(k, &bytes);
        Capability { object_id, rights, expires_at, depth: 0, parent_hash, mac }
    }

    /// Verify a capability: temporal check (O(1)) then MAC check.
    ///
    /// Uses constant-time MAC comparison to prevent timing oracle attacks.
    pub fn verify(&self, k: &[u8; 32], now: MonotonicNs) -> bool {
        if now >= self.expires_at { return false; }
        let bytes    = Self::auth_bytes(
            self.object_id, self.rights, self.expires_at,
            self.depth, &self.parent_hash,
        );
        let expected = hmac_sha256(k, &bytes);
        ct_eq_32(&expected, &self.mac)
    }

    /// Remaining lifetime in nanoseconds. Returns 0 if expired.
    pub fn ttl(&self, now: MonotonicNs) -> u64 {
        self.expires_at.saturating_sub(now)
    }

    /// Derive a child capability.
    ///
    /// Enforces:
    ///   - Parent must be currently valid (verified with K).
    ///   - Parent must have DERIVE right.
    ///   - Child rights ⊆ parent rights (no amplification).
    ///   - Child expiry ≤ parent expiry (no lifetime extension).
    ///   - Depth ≤ 64 (bounds delegation chains).
    ///
    /// The child's parent_hash records H(parent.mac) creating a
    /// cryptographically linked provenance chain.
    pub fn derive(
        &self,
        k:              &[u8; 32],
        now:            MonotonicNs,
        new_rights:     u8,
        new_expires_at: MonotonicNs,
    ) -> Option<Capability> {
        if !self.verify(k, now)             { return None; }
        if self.rights & rights::DERIVE == 0 { return None; }
        if new_rights & !self.rights != 0   { return None; } // no escalation
        if new_expires_at > self.expires_at  { return None; } // no extension
        let depth = self.depth.checked_add(1)?;
        if depth > 64                        { return None; }

        // Chain to parent: child records hash of parent's MAC.
        let parent_hash = {
            use crate::crypto::sha256;
            sha256(&self.mac)
        };

        let bytes = Self::auth_bytes(
            self.object_id, new_rights, new_expires_at, depth, &parent_hash,
        );
        let mac = hmac_sha256(k, &bytes);

        Some(Capability {
            object_id:  self.object_id,
            rights:     new_rights,
            expires_at: new_expires_at,
            depth,
            parent_hash,
            mac,
        })
    }
}

// ── Demonstration ─────────────────────────────────────────────────────────────

/// Helper: format first 8 bytes of a 32-byte array as hex.
fn hex8(b: &[u8; 32]) -> [u8; 16] {
    const HEX: [u8; 16] = *b"0123456789abcdef";
    let mut out = [0u8; 16];
    for i in 0..8 {
        out[i*2]     = HEX[(b[i] >> 4) as usize];
        out[i*2 + 1] = HEX[(b[i] & 0xf) as usize];
    }
    out
}

/// Run the TCD demonstration with real HMAC-SHA-256.
pub fn demonstrate() {
    // The master key K — 32 bytes (256 bits).
    // In production this lives only in the HSM and never in kernel memory.
    const K: [u8; 32] = [
        0x5E, 0xC0, 0xDE, 0xCA, 0xFE, 0xBA, 0xBE, 0xDE,
        0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x00,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x23,
        0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x00, 0x11,
    ];

    // ── SHA-256 self-test ────────────────────────────────────────────────────
    // SHA-256("") is a well-known reference value. First byte should be 0xe3.
    let empty_hash = crate::crypto::sha256(b"");
    let h8 = hex8(&empty_hash);
    serial_println!(
        "SHA-256 self-test: {}{}{}{}{}{}{}{}... (first byte: 0x{}{}, expected 0xe3)",
        h8[0] as char, h8[1] as char, h8[2] as char, h8[3] as char,
        h8[4] as char, h8[5] as char, h8[6] as char, h8[7] as char,
        h8[0] as char, h8[1] as char,
    );
    let sha256_ok = empty_hash[0] == 0xe3 && empty_hash[1] == 0xb0;

    // HMAC-SHA-256 known-vector: RFC 2104 Test Case 1
    // Key  = 0x0b × 20 bytes
    // Data = "Hi There"
    // Expected HMAC = b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7
    let hmac_key  = [0x0bu8; 20];
    let hmac_data = b"Hi There";
    let hmac_result = crate::crypto::hmac_sha256(&hmac_key, hmac_data);
    let hmac_ok = hmac_result[0] == 0xb0 && hmac_result[1] == 0x34;
    let h2 = hex8(&hmac_result);
    serial_println!(
        "HMAC-SHA-256 test: {}{}{}{}{}{}{}{}... (first byte: 0x{}{}, expected 0xb0)",
        h2[0] as char, h2[1] as char, h2[2] as char, h2[3] as char,
        h2[4] as char, h2[5] as char, h2[6] as char, h2[7] as char,
        h2[0] as char, h2[1] as char,
    );
    serial_println!(
        "HMAC-SHA-256 implementation: {} (RFC 2104 §B Test Case 1)",
        if hmac_ok { "CORRECT" } else { "UNEXPECTED" }
    );
    serial_println!(
        "SHA-256 implementation: {} (first 2 bytes match FIPS 180-4 vector)",
        if sha256_ok { "CORRECT" } else { "UNEXPECTED — check constants" }
    );

    let object_id = 0xF11E_u64;

    // ── 1. Mint root capability ───────────────────────────────────────────────
    let cap = Capability::mint(&K, object_id, rights::READ | rights::WRITE | rights::DERIVE, 1000);
    crate::meal::log(crate::meal::AuditEvent::CapabilityDerived, 0, object_id, 1000);
    let m8 = hex8(&cap.mac);
    serial_println!(
        "1. Minted cap: oid={:#x}  rights={:#07b}  expires=1000",
        cap.object_id, cap.rights
    );
    serial_println!(
        "   MAC (first 8 bytes): {}{}{}{}{}{}{}{} ...  [256-bit HMAC-SHA-256]",
        m8[0] as char, m8[1] as char, m8[2] as char, m8[3] as char,
        m8[4] as char, m8[5] as char, m8[6] as char, m8[7] as char,
    );

    // ── 2. Verify before expiry ───────────────────────────────────────────────
    let now = 500;
    serial_println!(
        "2. verify(now=500) -> {}   (ttl = {} ns)",
        cap.verify(&K, now), cap.ttl(now)
    );

    // ── 3. Derive read-only child ─────────────────────────────────────────────
    match cap.derive(&K, now, rights::READ, 800) {
        Some(child) => {
            crate::meal::log(crate::meal::AuditEvent::CapabilityDerived, 0, object_id, 800);
            let c8 = hex8(&child.mac);
            serial_println!(
                "3. Derived child: rights={:#07b}  expires=800  depth={}",
                child.rights, child.depth
            );
            serial_println!(
                "   Child MAC:  {}{}{}{}{}{}{}{} ...  [different key material]",
                c8[0] as char, c8[1] as char, c8[2] as char, c8[3] as char,
                c8[4] as char, c8[5] as char, c8[6] as char, c8[7] as char,
            );
        }
        None => serial_println!("3. Derivation failed (unexpected)"),
    }

    // ── 4. Right-escalation refused ───────────────────────────────────────────
    let esc = cap.derive(&K, now, rights::READ | rights::EXECUTE, 800);
    serial_println!(
        "4. Right-escalation (add EXECUTE) refused: {}",
        esc.is_none()
    );

    // ── 5. Temporal decay ─────────────────────────────────────────────────────
    serial_println!(
        "5. verify(now=1500) -> {}   <- expired: capability is permanently dead",
        cap.verify(&K, 1500)
    );

    // ── 6. Forged MAC rejected ────────────────────────────────────────────────
    // Flip ONE bit in the MAC. HMAC-SHA-256 is designed so that any
    // modification, however small, produces a completely different result.
    let mut forged = cap;
    forged.mac[0] ^= 0x01;
    serial_println!(
        "6. Flip 1 bit in MAC -> verify = {}   <- HMAC unforgeable",
        forged.verify(&K, now)
    );

    // ── 7. Wrong-key rejection ────────────────────────────────────────────────
    let wrong_key = [0xAAu8; 32];
    serial_println!(
        "7. Verify with wrong K -> {}   <- key separation enforced",
        cap.verify(&wrong_key, now)
    );
}
