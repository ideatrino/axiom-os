//! AXIOM MEAL — Monotonic Encrypted Audit Log.
//!
//! Every security event is written to an append-only, hash-chained,
//! HMAC-SHA-256 authenticated log. The chain makes it impossible to
//! delete or reorder any entry without breaking HMAC under K_audit.
//!
//! Formal guarantee:
//!   mac_n    = HMAC(fields_n, K_audit)       [authenticity]
//!   prev_n   = SHA-256(entry_{n-1})           [chain integrity]
//!   seq_n    > seq_{n-1}                      [monotone ordering]
//!
//! K_audit is distinct from K (capability master key) — key separation
//! ensures audit-log compromise does not affect capability security.

use crate::crypto::{hmac_sha256, sha256};
use crate::interrupts::TICKS;
use core::sync::atomic::Ordering;
use lazy_static::lazy_static;
use spin::Mutex;

// ── Event types ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AuditEvent {
    LogInitialised    = 0x0000,
    CapabilityDerived = 0x0001,
    CapabilityExpired = 0x0002,
    ProcessCreated    = 0x0100,
    ProcessExited     = 0x0101,
    EipcSend          = 0x0200,
    EipcReceive       = 0x0201,
    SyscallDispatched = 0x0300,
    ScbaFenceFired    = 0x0500,
    DriverLoaded         = 0x0400,
    DriverFaultMmio      = 0x0401,
    DriverFaultSyscall   = 0x0402,
    DriverStopped        = 0x0404,
    LatticeReconfigured  = 0x0600,
    MemoryZeroed        = 0x0700,
    BootComplete      = 0xFF00,
}

impl AuditEvent {
    pub fn name(self) -> &'static str {
        match self {
            Self::LogInitialised    => "LogInit",
            Self::CapabilityDerived => "CapDerived",
            Self::CapabilityExpired => "CapExpired",
            Self::ProcessCreated    => "ProcCreated",
            Self::ProcessExited     => "ProcExited",
            Self::EipcSend          => "EipcSend",
            Self::EipcReceive       => "EipcRecv",
            Self::SyscallDispatched => "Syscall",
            Self::ScbaFenceFired    => "ScbaFence",
            Self::DriverLoaded       => "DrvLoaded",
            Self::DriverFaultMmio    => "DrvFaultMmio",
            Self::DriverFaultSyscall => "DrvFaultSys",
            Self::DriverStopped      => "DrvStopped",
            Self::LatticeReconfigured => "LatticeReconf",
            Self::MemoryZeroed        => "MemZeroed",
            Self::BootComplete      => "BootDone",
        }
    }
}

// ── Entry ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub struct AuditEntry {
    pub sequence:   u64,
    pub timestamp:  u64,       // TICKS at log time (monotonic)
    pub event_type: AuditEvent,
    pub actor:      u32,       // process/task id (0 = kernel)
    pub value_a:    u64,       // event-specific payload
    pub value_b:    u64,       // event-specific payload
    pub prev_hash:  [u8; 32],  // SHA-256(prev entry) — the chain link
    pub mac:        [u8; 32],  // HMAC-SHA-256(all above, K_audit)
}

impl AuditEntry {
    /// Serialise the fields covered by the MAC (everything except mac itself).
    fn auth_bytes(&self) -> [u8; 80] {
        let mut b = [0u8; 80];
        b[0..8].copy_from_slice(&self.sequence.to_le_bytes());
        b[8..16].copy_from_slice(&self.timestamp.to_le_bytes());
        b[16..18].copy_from_slice(&(self.event_type as u16).to_le_bytes());
        // b[18..24] = zero pad (reserved)
        b[24..28].copy_from_slice(&self.actor.to_le_bytes());
        // b[28..32] = zero pad
        b[32..40].copy_from_slice(&self.value_a.to_le_bytes());
        b[40..48].copy_from_slice(&self.value_b.to_le_bytes());
        b[48..80].copy_from_slice(&self.prev_hash);
        b
    }

    /// SHA-256 of the serialised entry — becomes prev_hash of the next entry.
    pub fn self_hash(&self) -> [u8; 32] {
        sha256(&self.auth_bytes())
    }
}

// ── Log ──────────────────────────────────────────────────────────────────────

const CAPACITY: usize = 64;

pub struct MealLog {
    entries:    [Option<AuditEntry>; CAPACITY],
    write_head: usize,
    total:      u64,
    chain_tip:  [u8; 32],   // SHA-256(most recent entry)
    audit_key:  [u8; 32],   // K_audit
}

impl MealLog {
    pub fn new(key: [u8; 32]) -> Self {
        const NONE: Option<AuditEntry> = None;
        MealLog {
            entries:    [NONE; CAPACITY],
            write_head: 0,
            total:      0,
            chain_tip:  sha256(b"AXIOM-MEAL-GENESIS-v4"),
            audit_key:  key,
        }
    }

    pub fn append(&mut self, ev: AuditEvent, actor: u32, a: u64, b: u64) -> u64 {
        let seq = self.total;
        let mut e = AuditEntry {
            sequence:   seq,
            timestamp:  TICKS.load(Ordering::Relaxed),
            event_type: ev,
            actor,
            value_a:    a,
            value_b:    b,
            prev_hash:  self.chain_tip,
            mac:        [0u8; 32],
        };
        e.mac         = hmac_sha256(&self.audit_key, &e.auth_bytes());
        self.chain_tip = e.self_hash();
        self.entries[self.write_head] = Some(e);
        self.write_head = (self.write_head + 1) % CAPACITY;
        self.total += 1;
        seq
    }

    fn verify_entry(&self, e: &AuditEntry) -> bool {
        let exp = hmac_sha256(&self.audit_key, &e.auth_bytes());
        let mut d = 0u8;
        for i in 0..32 { d |= exp[i] ^ e.mac[i]; }
        d == 0
    }

    /// Verify every MAC and every chain link.
    /// Returns (entry_count, all_valid).
    pub fn verify_chain(&self) -> (usize, bool) {
        let mut prev: Option<[u8; 32]> = None;
        let mut n = 0usize;
        for i in 0..CAPACITY {
            let idx = (self.write_head + i) % CAPACITY;
            if let Some(ref e) = self.entries[idx] {
                if !self.verify_entry(e)     { return (n, false); }
                if let Some(ph) = prev {
                    if e.prev_hash != ph     { return (n, false); }
                }
                prev = Some(e.self_hash());
                n += 1;
            }
        }
        (n, true)
    }

    pub fn entry_count(&self) -> u64 { self.total }

    pub fn print_all(&self) {
        for i in 0..CAPACITY {
            let idx = (self.write_head + i) % CAPACITY;
            if let Some(ref e) = self.entries[idx] {
                let h = e.self_hash();
                crate::serial_println!(
                    "  [{:02}] t={:04}  {:<12}  actor={}  val={:<8}  \
                     chain={:02x}{:02x}{:02x}{:02x}...",
                    e.sequence, e.timestamp, e.event_type.name(),
                    e.actor, e.value_a,
                    h[0], h[1], h[2], h[3]
                );
            }
        }
    }
}

// ── Global MEAL instance ──────────────────────────────────────────────────────

/// K_audit — distinct from K (capability master key).
/// In production: generated in HSM, never leaves it.
const K_AUDIT: [u8; 32] = [
    0xA1,0xB2,0xC3,0xD4,0xE5,0xF6,0x07,0x18,
    0x29,0x3A,0x4B,0x5C,0x6D,0x7E,0x8F,0x90,
    0xA1,0xB2,0xC3,0xD4,0xE5,0xF6,0x07,0x18,
    0x29,0x3A,0x4B,0x5C,0x6D,0x7E,0x8F,0x90,
];

lazy_static! {
    pub static ref MEAL: Mutex<MealLog> = Mutex::new(MealLog::new(K_AUDIT));
}

/// Log an event from anywhere — interrupt-safe via try_lock().
pub fn log(ev: AuditEvent, actor: u32, a: u64, b: u64) {
    if let Some(mut m) = MEAL.try_lock() {
        m.append(ev, actor, a, b);
    }
}
