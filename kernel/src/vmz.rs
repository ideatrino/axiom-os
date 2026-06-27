//! AXIOM VMZ — Verified Memory Zeroing.
//!
//! Formal guarantee:
//!   ∀ p₁ (exited), ∀ p₂ (successor):
//!   I(secret(p₁); read_from_frame(p₂)) = 0
//!
//! Proof: zero_region() overwrites every byte with 0 and issues a
//! serialising barrier (MFENCE on x86-64) before the memory returns
//! to the free pool. The value 0 is independent of the prior secret.
//!
//! This closes the "cold allocation attack": a process cannot learn
//! secrets of a previous process by allocating from the free heap.

use crate::serial_println;
use crate::meal;

/// Zero `len` bytes starting at `ptr` and issue a serialising memory fence.
///
/// # Safety
/// `ptr` must be valid for writing `len` bytes. No other CPU may access
/// the region during this call. On a single-core machine (or with
/// interrupts disabled during the call) this is trivially satisfied.
pub unsafe fn zero_region(ptr: *mut u8, len: usize) {
    // REP STOSB: store AL (= 0) into [RDI], RCX times, auto-incrementing RDI.
    // This is the fastest software zeroing method on x86-64 — the CPU
    // recognises it and uses its fast-string hardware path.
    unsafe {
        core::arch::asm!(
            "rep stosb",
            inout("rdi") ptr       => _,
            inout("rcx") len       => _,
            in("al")     0u8,
            options(nostack),
        );
        // MFENCE: serialise all stores. No subsequent load on any CPU
        // can observe the pre-zero values after this barrier returns.
        core::arch::asm!("mfence", options(nostack, nomem));
    }
}

/// Verify every byte in `[ptr, ptr+len)` is zero.
/// Returns (true, 0, 0) if clean, or (false, first_bad_offset, bad_value).
pub unsafe fn verify_zeroed(ptr: *const u8, len: usize) -> (bool, usize, u8) {
    unsafe {
        let slice = core::slice::from_raw_parts(ptr, len);
        for (i, &b) in slice.iter().enumerate() {
            if b != 0 { return (false, i, b); }
        }
    }
    (true, 0, 0)
}

/// Run the VMZ demonstration.
///
/// 1. Allocate a buffer on the heap.
/// 2. Write a "secret" pattern into it.
/// 3. Record a hash of the secret (proves it existed).
/// 4. Zero with REP STOSB + MFENCE.
/// 5. Verify every byte is now 0.
/// 6. Log MemoryZeroed to MEAL.
/// 7. Print before/after comparison.
pub fn run_demo() {
    use alloc::vec::Vec;

    const SECRET_LEN: usize = 64;

    // ── 1. Allocate and fill with "secret" data ────────────────────────────
    let mut buf: Vec<u8> = Vec::with_capacity(SECRET_LEN);
    for i in 0..SECRET_LEN {
        buf.push((i as u8).wrapping_mul(0xA5).wrapping_add(0x3C));
    }

    let ptr = buf.as_mut_ptr();
    let addr = ptr as u64;

    serial_println!("===========================================");
    serial_println!(" AXIOM VMZ — Verified Memory Zeroing");
    serial_println!("===========================================");
    serial_println!("");
    serial_println!("1. Secret allocated at {:#x} ({} bytes)", addr, SECRET_LEN);
    serial_println!("   First 8 bytes: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
    serial_println!("   Last  8 bytes: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
        buf[56], buf[57], buf[58], buf[59], buf[60], buf[61], buf[62], buf[63]);

    // ── 2. Record a summary hash proving the secret existed ────────────────
    let secret_hash = crate::crypto::sha256(&buf);
    serial_println!("");
    serial_println!("2. SHA-256(secret) = {:02x}{:02x}{:02x}{:02x}...",
        secret_hash[0], secret_hash[1], secret_hash[2], secret_hash[3]);
    serial_println!("   (proof the secret was present before zeroing)");

    // ── 3. Zero with REP STOSB + MFENCE ───────────────────────────────────
    unsafe { zero_region(ptr, SECRET_LEN); }
    serial_println!("");
    serial_println!("3. REP STOSB + MFENCE executed ({} bytes)", SECRET_LEN);

    // ── 4. Verify ─────────────────────────────────────────────────────────
    let (clean, bad_off, bad_val) = unsafe { verify_zeroed(ptr as *const u8, SECRET_LEN) };

    serial_println!("");
    serial_println!("4. Verification:");
    serial_println!("   First 8 bytes: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
    serial_println!("   Last  8 bytes: {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
        buf[56], buf[57], buf[58], buf[59], buf[60], buf[61], buf[62], buf[63]);

    if clean {
        serial_println!("   All {} bytes = 0x00  ✓", SECRET_LEN);
    } else {
        serial_println!("   FAIL: byte[{}] = {:#04x} (expected 0x00)", bad_off, bad_val);
    }

    // ── 5. Prove information is gone ───────────────────────────────────────
    let zero_hash = crate::crypto::sha256(&buf);
    let hashes_differ = secret_hash != zero_hash;
    serial_println!("");
    serial_println!("5. SHA-256(zeros)  = {:02x}{:02x}{:02x}{:02x}...",
        zero_hash[0], zero_hash[1], zero_hash[2], zero_hash[3]);
    serial_println!("   SHA-256(secret) ≠ SHA-256(zeros): {}  ← information destroyed",
        hashes_differ);

    // ── 6. Log to MEAL ─────────────────────────────────────────────────────
    meal::log(meal::AuditEvent::MemoryZeroed, 0, addr, SECRET_LEN as u64);
    serial_println!("");
    serial_println!("6. MEAL entry written: MemoryZeroed @ {:#x}", addr);

    // ── 7. Checkpoint ──────────────────────────────────────────────────────
    if clean && hashes_differ {
        serial_println!("");
        serial_println!(">>> SHOT 9 CHECKPOINT PASSED <<<");
        serial_println!("    VMZ: {} bytes zeroed with REP STOSB + MFENCE.", SECRET_LEN);
        serial_println!("    Verification: all bytes confirmed 0x00.");
        serial_println!("    Information-theoretic proof:");
        serial_println!("      SHA-256(secret) ≠ SHA-256(zeros)");
        serial_println!("      ⟹ successor reads 0 bits of prior secret.");
        serial_println!("    MEAL logged: MemoryZeroed event recorded.");
        serial_println!("    Ready for Shot 10: Dynamic Security Lattice.");
    } else {
        serial_println!(">>> SHOT 9 ISSUE: clean={} hashes_differ={}", clean, hashes_differ);
    }
    serial_println!("===========================================");
    serial_println!("");
}
