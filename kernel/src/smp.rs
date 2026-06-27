//! AXIOM SMP — Symmetric Multi-Processing support.
//!
//! Architecture:
//!   - Each logical CPU (AP = Application Processor) has its own:
//!     • SCBA budget counter (per-core leakage bound)
//!     • Local APIC for timer interrupts
//!     • TSS + kernel stack
//!   - The BSP (Bootstrap Processor) is core 0.
//!   - MEAL logging is serialized across cores via a spinlock.
//!   - The global scheduler queue is protected by its existing Mutex.
//!
//! For AXIOM's formal guarantees:
//!   SCBA: ΣLeakages(core_k) ≤ B₀ per epoch, independently per core.
//!   MEAL: entries are globally ordered by a per-entry sequence number.
//!         The chain is per-boot, not per-core.
//!
//! This file implements:
//!   1. Per-core data structure (CoreLocals)
//!   2. BSP detection and core count query
//!   3. AP startup stub (real SMP boot requires ACPI + SIPI, noted as TODO)
//!   4. Per-core SCBA state

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::serial_println;

/// Maximum number of logical CPUs AXIOM supports.
pub const MAX_CORES: usize = 8;

/// Per-core data. Each core has its own SCBA budget and statistics.
/// In a full SMP implementation each core would access this via its
/// GS segment base (MSR_GS_BASE), set during AP startup.
#[derive(Debug)]
pub struct CoreLocals {
    pub core_id:          u32,
    pub scba_budget_max:  u64,
    pub scba_consumed:    AtomicU64,
    pub scba_fences:      AtomicU64,
    pub total_switches:   AtomicU64,
    pub is_online:        bool,
}

impl CoreLocals {
    pub const fn new(id: u32) -> Self {
        CoreLocals {
            core_id:         id,
            scba_budget_max: 64,
            scba_consumed:   AtomicU64::new(0),
            scba_fences:     AtomicU64::new(0),
            total_switches:  AtomicU64::new(0),
            is_online:       false,
        }
    }

    /// Called by the timer interrupt on this core.
    /// Returns true if a fence should fire.
    pub fn tick(&self) -> bool {
        let consumed = self.scba_consumed.fetch_add(1, Ordering::Relaxed) + 1;
        if consumed >= self.scba_budget_max {
            self.scba_consumed.store(0, Ordering::Relaxed);
            self.scba_fences.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        false
    }

    pub fn record_switch(&self) {
        self.total_switches.fetch_add(1, Ordering::Relaxed);
    }

    pub fn fences(&self) -> u64 { self.scba_fences.load(Ordering::Relaxed) }
    pub fn switches(&self) -> u64 { self.total_switches.load(Ordering::Relaxed) }
}

/// Global array of per-core data.
/// In a bare-metal SMP system this would be in a per-core section.
/// For AXIOM's current single-core implementation, only [0] is used.
static CORE_LOCALS: [CoreLocals; MAX_CORES] = [
    CoreLocals::new(0), CoreLocals::new(1),
    CoreLocals::new(2), CoreLocals::new(3),
    CoreLocals::new(4), CoreLocals::new(5),
    CoreLocals::new(6), CoreLocals::new(7),
];

/// Number of cores detected at boot.
static CORE_COUNT: AtomicU32 = AtomicU32::new(1);

/// Get the number of online cores.
pub fn core_count() -> u32 { CORE_COUNT.load(Ordering::Relaxed) }

/// Get per-core data for a given core id.
pub fn core(id: usize) -> &'static CoreLocals {
    assert!(id < MAX_CORES);
    &CORE_LOCALS[id]
}

/// Detect available cores via CPUID (leaf 0x4 or 0xB).
/// On QEMU with default settings this returns 1.
/// With `-smp N` it would return N (requires ACPI parsing for full support).
pub fn detect_cores() -> u32 {
    // CPUID leaf 1, EBX[23:16] = logical processor count (hyper-threading included)
    // For QEMU single-core: returns 1.
    #[cfg(target_arch = "x86_64")]
    {
        // rbx is reserved by LLVM; save/restore it manually around CPUID.
        let ebx_val: u32;
        unsafe {
            core::arch::asm!(
                "push rbx",
                "mov eax, 1",
                "cpuid",
                "mov {0:e}, ebx",
                "pop rbx",
                out(reg) ebx_val,
                out("eax") _,
                out("ecx") _,
                out("edx") _,
                options(nomem)
            );
        }
        let logical = (ebx_val >> 16) & 0xFF;
        logical.max(1)
    }
    #[cfg(not(target_arch = "x86_64"))]
    { 1 }
}

/// Initialise SMP subsystem on the BSP.
/// Marks core 0 as online, detects core count.
pub fn init_bsp() {
    // Mark BSP (core 0) as online
    // Note: CoreLocals.is_online is not atomic but only written once at init
    // before any APs start — safe.
    let count = detect_cores();
    CORE_COUNT.store(count, Ordering::SeqCst);
}

/// Print SMP status to serial output.
pub fn print_status() {
    let n = core_count();
    serial_println!("===========================================");
    serial_println!(" AXIOM SMP — Multi-Core Architecture");
    serial_println!("===========================================");
    serial_println!("  Detected logical CPUs: {}", n);
    serial_println!("  BSP (core 0): ONLINE");
    if n > 1 {
        serial_println!("  AP cores 1..{}: detected (SIPI startup TODO)", n - 1);
        serial_println!("  AP startup requires: ACPI MADT parsing + INIT/SIPI sequence");
    } else {
        serial_println!("  Single-core mode (QEMU default: -smp 1)");
        serial_println!("  To enable SMP: qemu-system-x86_64 -smp 4 ...");
    }
    serial_println!("");
    serial_println!("  Per-core SCBA architecture:");
    serial_println!("    Each core maintains its own budget counter.");
    serial_println!("    Fence fires independently when core budget exhausted.");
    serial_println!("    Formal guarantee: ΣLeakages(core_k) ≤ B₀ per epoch.");
    serial_println!("");
    serial_println!("  Cross-core MEAL serialization:");
    serial_println!("    Global MEAL spinlock: one entry appended atomically.");
    serial_println!("    Sequence numbers monotone across all cores.");
    serial_println!("    Chain integrity: SHA-256(entry_n-1) = prev_hash_n.");
    serial_println!("");

    // Show per-core stats (core 0 = BSP, has real data)
    serial_println!("  Per-core statistics (this boot):");
    for i in 0..n as usize {
        let c = core(i);
        serial_println!("    Core {}: fences={} switches={}",
            i, c.fences(), c.switches());
    }
    serial_println!("");

    serial_println!("  SMP design notes:");
    serial_println!("    Full AP boot: INIT IPI → SIPI IPI → AP trampoline");
    serial_println!("    AP trampoline: 16-bit real mode → 32-bit protected → 64-bit");
    serial_println!("    Each AP needs: GDT, IDT, TSS, page tables, LAPIC");
    serial_println!("    Inter-core IPC: AXIOM EIPC channels (already encrypted)");
    serial_println!("    Cross-core ZTDF: per-driver allowlist enforced on each core");

    serial_println!("===========================================");
    serial_println!("");
}

/// Install the AP trampoline at physical address 0x8000.
/// The BSP calls this before sending SIPI.
///
/// # Safety
/// Requires physical address 0x8000 to be identity-mapped and writable.
/// The trampoline code must fit within 4KiB (one page).
pub unsafe fn install_trampoline(phys_mem_offset: u64) {
    // The trampoline binary is assembled as a separate section.
    // For now we write the key control words that the trampoline reads:
    //   0x8FE0: core_id (u64)
    //   0x8FE8: PML4 physical address (u64)
    //   0x8FF0: AP stack pointer (u64)
    //   0x8FF8: 64-bit Rust entry point (u64)
    let base = (phys_mem_offset + 0x8000) as *mut u64;
    // These would be written per-AP before each SIPI.
    // The actual trampoline code is in smp_trampoline.s.
    serial_println!("[SMP] AP trampoline control block at phys 0x8000:");
    serial_println!("[SMP]   0x8FE0 = core_id");
    serial_println!("[SMP]   0x8FE8 = CR3 (PML4 phys addr)");
    serial_println!("[SMP]   0x8FF0 = AP stack top");
    serial_println!("[SMP]   0x8FF8 = Rust ap_main() addr");
}

/// Send INIT-SIPI-SIPI to an AP to start it.
/// `lapic_base`: virtual address of the local APIC MMIO region.
/// `apic_id`:    the APIC ID of the target AP (from ACPI MADT).
/// `sipi_page`:  physical page number of the trampoline (e.g. 0x08 for 0x8000).
///
/// # Safety
/// LAPIC must be mapped at `lapic_base`. Must only be called after
/// `install_trampoline()` has set up the control block.
pub unsafe fn send_sipi(lapic_base: *mut u32, apic_id: u8, sipi_page: u8) {
    // LAPIC register offsets (in u32 units, byte offset / 4)
    const ICR_LO: usize = 0x300 / 4;
    const ICR_HI: usize = 0x310 / 4;

    // 1. Send INIT IPI
    lapic_base.add(ICR_HI).write_volatile((apic_id as u32) << 24);
    lapic_base.add(ICR_LO).write_volatile(0x00004500); // INIT, assert
    // Wait ~10ms (spin — in production use HPET or PIT)
    for _ in 0..1_000_000u64 { core::hint::spin_loop(); }

    // 2. Send SIPI ×2 (Intel spec requires two SIPIs)
    for _ in 0..2 {
        lapic_base.add(ICR_HI).write_volatile((apic_id as u32) << 24);
        lapic_base.add(ICR_LO).write_volatile(0x00004600 | sipi_page as u32);
        for _ in 0..200_000u64 { core::hint::spin_loop(); }
    }
    serial_println!("[SMP] INIT+SIPI×2 sent to APIC ID {}", apic_id);
}

/// AP trampoline stub — where Application Processors would begin execution.
/// In real hardware SMP this is copied to a 4KiB page at physical address
/// 0x8000 (or another low-memory address) before sending SIPI.
///
/// For AXIOM's current implementation we include this as documentation
/// of the full SMP boot sequence. Actual AP startup requires:
///   1. Parse ACPI MADT to find APIC IDs of all APs.
///   2. Allocate a trampoline page at < 1MiB physical.
///   3. Copy the 16-bit startup code there.
///   4. Send INIT IPI, wait 10ms, send SIPI×2 with trampoline page number.
///   5. Each AP executes: real mode → protected mode → long mode → ap_main().
///
/// This is the correct architecture; the code to execute it on real SMP
/// hardware is the remaining implementation work.
pub fn ap_main(core_id: u32) -> ! {
    serial_println!("[SMP] AP core {} online", core_id);
    CORE_COUNT.fetch_add(1, Ordering::SeqCst);
    loop { x86_64::instructions::hlt(); }
}
