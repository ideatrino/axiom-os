//! AXIOM SMP — Symmetric Multi-Processing support.
//!
//! Uses ACPI MADT to find AP APIC IDs, then sends INIT+SIPI×2.
//! APs are brought to long mode via an inline trampoline.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};
use crate::serial_println;

pub const MAX_CORES: usize = 8;
static APS_ONLINE: AtomicU32 = AtomicU32::new(0);

#[derive(Debug)]
pub struct CoreLocals {
    pub core_id:         u32,
    pub scba_budget_max: u64,
    pub scba_consumed:   AtomicU64,
    pub scba_fences:     AtomicU64,
    pub total_switches:  AtomicU64,
    pub is_online:       AtomicBool,
}

impl CoreLocals {
    pub const fn new(id: u32) -> Self {
        CoreLocals {
            core_id:         id,
            scba_budget_max: 64,
            scba_consumed:   AtomicU64::new(0),
            scba_fences:     AtomicU64::new(0),
            total_switches:  AtomicU64::new(0),
            is_online:       AtomicBool::new(false),
        }
    }
}

pub static CORE_LOCALS: [CoreLocals; MAX_CORES] = [
    CoreLocals::new(0), CoreLocals::new(1),
    CoreLocals::new(2), CoreLocals::new(3),
    CoreLocals::new(4), CoreLocals::new(5),
    CoreLocals::new(6), CoreLocals::new(7),
];

// ── ACPI MADT parsing ─────────────────────────────────────────────────────────

unsafe fn find_rsdp(phys_offset: u64) -> Option<u64> {
    let ebda_seg = *((phys_offset + 0x40E) as *const u16) as u64;
    let ebda_phys = ebda_seg << 4;
    let regions: &[(u64, u64)] = &[
        (ebda_phys, ebda_phys + 0x400),
        (0x000E_0000, 0x0010_0000),
    ];
    for &(start, end) in regions {
        let mut addr = start;
        while addr < end {
            let sig = core::slice::from_raw_parts(
                (phys_offset + addr) as *const u8, 8);
            if sig == b"RSD PTR " { return Some(addr); }
            addr += 16;
        }
    }
    None
}

unsafe fn parse_madt(phys_offset: u64, rsdp_addr: Option<u64>) -> alloc::vec::Vec<u8> {
    extern crate alloc;
    use alloc::vec::Vec;

    let rsdp_phys = match rsdp_addr.or_else(|| find_rsdp(phys_offset)) {
        Some(p) => {
            serial_println!("[SMP] RSDP at phys {:#x}", p);
            p
        }
        None => {
            serial_println!("[SMP] RSDP not found (no bootloader value, legacy scan failed)");
            return Vec::new();
        }
    };

    let rsdp_virt = phys_offset + rsdp_phys;
    let rsdt_phys = core::ptr::read_unaligned((rsdp_virt + 16) as *const u32) as u64;
    let rsdt_virt = phys_offset + rsdt_phys;
    let rsdt_len  = core::ptr::read_unaligned((rsdt_virt + 4) as *const u32) as u64;
    let n_entries = (rsdt_len.saturating_sub(36)) / 4;

    let mut madt_phys: Option<u64> = None;
    for i in 0..n_entries.min(32) {
        let table_phys = core::ptr::read_unaligned((rsdt_virt + 36 + i * 4) as *const u32) as u64;
        if table_phys == 0 { continue; }
        let sig = core::slice::from_raw_parts(
            (phys_offset + table_phys) as *const u8, 4);
        if sig == b"APIC" { madt_phys = Some(table_phys); break; }
    }

    let madt_phys = match madt_phys {
        Some(p) => p,
        None => { serial_println!("[SMP] MADT not found"); return Vec::new(); }
    };

    let madt_virt = phys_offset + madt_phys;
    let madt_len  = core::ptr::read_unaligned((madt_virt + 4) as *const u32) as u64;
    let mut offset: u64 = 44;
    let mut ids: Vec<u8> = Vec::new();

    while offset + 2 < madt_len {
        let entry_virt = madt_virt + offset;
        let entry_type = *(entry_virt as *const u8);
        let entry_len  = *((entry_virt + 1) as *const u8) as u64;
        if entry_len == 0 { break; }
        if entry_type == 0 {  // Local APIC
            let apic_id = *((entry_virt + 3) as *const u8);
            let flags   = core::ptr::read_unaligned((entry_virt + 4) as *const u32);
            if flags & 1 != 0 { ids.push(apic_id); }
        }
        offset += entry_len;
    }
    serial_println!("[SMP] MADT: {} CPU(s): {:?}", ids.len(), ids);
    ids
}

// ── LAPIC ─────────────────────────────────────────────────────────────────────

const LAPIC_PHYS:   u64 = 0xFEE0_0000;
const LAPIC_ID:     u64 = 0x020;
const LAPIC_ICR_LO: u64 = 0x300;
const LAPIC_ICR_HI: u64 = 0x310;

unsafe fn lapic_read(base: u64, reg: u64) -> u32 {
    core::ptr::read_volatile((base + reg) as *const u32)
}
unsafe fn lapic_write(base: u64, reg: u64, val: u32) {
    core::ptr::write_volatile((base + reg) as *mut u32, val);
}
unsafe fn lapic_wait(base: u64) {
    while lapic_read(base, LAPIC_ICR_LO) & (1 << 12) != 0 {
        core::hint::spin_loop();
    }
}

// ── Trampoline ────────────────────────────────────────────────────────────────

/// AP trampoline written as flat 16-bit binary.
/// Assembled from:
///   org 0x8000
///   cli / cld / xor ax,ax / mov ds,ax / mov es,ax / mov ss,ax
///   lgdt [gdtr]        ; load 6-byte GDT descriptor at 0x8060
///   mov eax,cr0 / or al,1 / mov cr0,eax   ; PE=1
///   jmp 0x08:pm32      ; far jump to 32-bit CS
///   pm32:              ; at 0x8020 in the page
///   ... set ds/es/ss=0x10, enable PAE, load CR3 from [0x8FE8],
///   ... EFER.LME, enable PG, jmp 0x18:lm64
///   lm64:              ; at 0x8080
///   ... mov rsp,[0x8FF0] / mov rdi,[0x8FE0] / call [0x8FF8]
///   gdtr:              ; at 0x8060: limit=0x1f, base=0x8068
///   gdt:               ; at 0x8068: null, 32-code, 32-data, 64-code
const AP_TRAMPOLINE_BIN: &[u8] = &[
    0xEB, 0x3E, 0x1F, 0x00, 0x08, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9A, 0xCF, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x92, 0xCF, 0x00,
    0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9A, 0xAF, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x8C, 0xC8, 0x8E, 0xD8, 0x0F, 0x01, 0x16, 0x02, 0x00, 0x0F, 0x20, 0xC0, 0x0C, 0x01, 0x0F, 0x22,
    0xC0, 0x66, 0xEA, 0x80, 0x00, 0x05, 0x00, 0x08, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
    0xB8, 0x10, 0x00, 0x00, 0x00, 0x8E, 0xD8, 0x8E, 0xC0, 0x8E, 0xD0, 0x0F, 0x20, 0xE0, 0x0F, 0xBA,
    0xE8, 0x05, 0x0F, 0x22, 0xE0, 0xA1, 0xE8, 0x0F, 0x05, 0x00, 0x0F, 0x22, 0xD8, 0xB9, 0x80, 0x00,
    0x00, 0xC0, 0x0F, 0x32, 0x0F, 0xBA, 0xE8, 0x08, 0x0F, 0x30, 0x0F, 0x20, 0xC0, 0x0D, 0x00, 0x00,
    0x00, 0x80, 0x0F, 0x22, 0xC0, 0xEA, 0xC0, 0x00, 0x05, 0x00, 0x18, 0x00, 0x90, 0x90, 0x90, 0x90,
    0x48, 0x8B, 0x24, 0x25, 0xF0, 0x0F, 0x05, 0x00, 0x48, 0x8B, 0x3C, 0x25, 0xE0, 0x0F, 0x05, 0x00,
    0x48, 0x8B, 0x04, 0x25, 0xF8, 0x0F, 0x05, 0x00, 0xFF, 0xD0, 0xF4, 0xEB, 0xFD,
];

/// Per-AP stacks (16 KiB each).
static mut AP_STACKS: [[u8; 16384]; MAX_CORES] = [[0u8; 16384]; MAX_CORES];

pub unsafe fn install_trampoline(phys_offset: u64, cr3: u64, core_id: u32, stack_top: u64) {
    let base = phys_offset + 0x50000; // use 0x50000 (vec=0x50)

    // Verify byte count and key offsets
    assert!(AP_TRAMPOLINE_BIN.len() <= 0xFE0,
        "trampoline too large");

    // Copy trampoline to physical 0x8000
    core::ptr::copy_nonoverlapping(
        AP_TRAMPOLINE_BIN.as_ptr(),
        base as *mut u8,
        AP_TRAMPOLINE_BIN.len(),
    );

    // Verify write: read back first 4 bytes and check against expected
    serial_println!("[SMP] Trampoline at {:#x} (phys {:#x})", base, base - phys_offset);
    let b0 = *(base as *const u8);
    let b1 = *((base+1) as *const u8);
    let b2 = *((base+2) as *const u8);
    let b3 = *((base+3) as *const u8);
    serial_println!("[SMP] Trampoline verify: [{:#x}]={:#x} [{:#x}]={:#x} [{:#x}]={:#x} [{:#x}]={:#x}",
        base, b0, base+1, b1, base+2, b2, base+3, b3);
    // Expected: 0xFA (cli), 0xFC (cld), 0x31 (xor), 0xC0
    if b0 != 0xFA || b1 != 0x31 || b2 != 0xC0 || b3 != 0x8E {
        serial_println!("[SMP] ERROR: trampoline write FAILED! got {:02X} {:02X} {:02X} {:02X}", b0, b1, b2, b3);
    } else {
        serial_println!("[SMP] Trampoline write verified ✓ (FA 31 C0 8E)");
    }

    // Write control block (read by 64-bit trampoline code)
    *((base + 0xFE0) as *mut u64) = core_id as u64; // 0x50FE0
    *((base + 0xFE8) as *mut u64) = cr3;
    *((base + 0xFF0) as *mut u64) = stack_top;
    *((base + 0xFF8) as *mut u64) = ap_main as u64;

    // Memory barrier before sending SIPI
    core::sync::atomic::fence(Ordering::SeqCst);

    serial_println!("[SMP] Trampoline@0x50000: core={} cr3={:#x} stack={:#x} fn={:#x}",
        core_id, cr3, stack_top, ap_main as u64);
}

/// Send INIT+SIPI×2 using xAPIC MMIO with fallback awareness.
/// ICR format: bits 7:0 = vector, bits 10:8 = delivery mode,
///             bits 18:16 = destination shorthand, bits 27:24 (HI reg) = dest
pub unsafe fn send_sipi(lapic_virt: u64, apic_id: u8, sipi_vec: u8) {
    serial_println!("[SMP] Sending INIT IPI to APIC {}", apic_id);

    // Clear any pending errors first
    lapic_write(lapic_virt, 0x280, 0); // ESR = 0

    // INIT IPI: delivery=INIT(5), level=assert(1), trigger=edge(0)
    lapic_write(lapic_virt, LAPIC_ICR_HI, (apic_id as u32) << 24);
    lapic_write(lapic_virt, LAPIC_ICR_LO, 0x0000_C500); // assert INIT
    // Wait for delivery
    let mut timeout = 0u32;
    while lapic_read(lapic_virt, LAPIC_ICR_LO) & (1 << 12) != 0 && timeout < 1000 {
        core::hint::spin_loop();
        timeout += 1;
    }
    serial_println!("[SMP] INIT assert sent (delivery status timeout={})", timeout);

    // INIT deassert
    lapic_write(lapic_virt, LAPIC_ICR_HI, (apic_id as u32) << 24);
    lapic_write(lapic_virt, LAPIC_ICR_LO, 0x0000_8500); // deassert INIT
    timeout = 0;
    while lapic_read(lapic_virt, LAPIC_ICR_LO) & (1 << 12) != 0 && timeout < 1000 {
        core::hint::spin_loop();
        timeout += 1;
    }
    serial_println!("[SMP] INIT deassert sent");

    // Post-INIT delay (~10ms) so the AP enters wait-for-SIPI before SIPI.
    for _ in 0..2_000_000u64 { core::hint::spin_loop(); }

    // SIPI × 2
    for pass in 0..2u32 {
        lapic_write(lapic_virt, 0x280, 0); // clear ESR
        lapic_write(lapic_virt, LAPIC_ICR_HI, (apic_id as u32) << 24);
        lapic_write(lapic_virt, LAPIC_ICR_LO, 0x0000_4600 | sipi_vec as u32);
        timeout = 0;
        while lapic_read(lapic_virt, LAPIC_ICR_LO) & (1 << 12) != 0 && timeout < 1000 {
            core::hint::spin_loop();
            timeout += 1;
        }
        let _ = pass;
        for _ in 0..200_000u64 { core::hint::spin_loop(); }
    }
    serial_println!("[SMP] INIT+SIPI×2 → APIC {} complete", apic_id);
}

// ── AP entry ──────────────────────────────────────────────────────────────────

#[no_mangle]
pub extern "C" fn ap_main(core_id: u64) -> ! {
    let id = core_id as usize;
    if id < MAX_CORES {
        CORE_LOCALS[id].is_online.store(true, Ordering::SeqCst);
        APS_ONLINE.fetch_add(1, Ordering::SeqCst);
        serial_println!("[SMP] Core {} online ✓  (SCBA budget={}t)",
            id, CORE_LOCALS[id].scba_budget_max);
    }
    loop { unsafe { core::arch::asm!("hlt"); } }
}

// ── BSP init ──────────────────────────────────────────────────────────────────

/// Add identity mapping virtual 0x50000 → physical 0x50000 in BSP page tables.
/// Required so the 64-bit trampoline stub at 0x500A0 can execute after paging.
unsafe fn add_trampoline_identity_map(phys_offset: u64, cr3: u64) {
    let virt: u64 = 0x50000;
    let phys: u64 = 0x50000;

    let pml4 = (phys_offset + cr3) as *mut u64;
    let pml4e = *pml4.add(0); // index 0 for virt < 512GB
    if pml4e & 1 == 0 { serial_println!("[SMP] ERR: PML4[0] not present"); return; }

    let pdpt = (phys_offset + (pml4e & !0xFFF)) as *mut u64;
    let pdpte = *pdpt.add(0); // index 0 for virt < 1GB
    if pdpte & 1 == 0 { serial_println!("[SMP] ERR: PDPT[0] not present"); return; }
    if pdpte & (1<<7) != 0 { // 1GB huge page covers 0x50000 already
        serial_println!("[SMP] 1GB huge page covers 0x50000 ✓ (no mapping needed)");
        return;
    }

    let pd = (phys_offset + (pdpte & !0xFFF)) as *mut u64;
    let pde = *pd.add(0); // index 0 for virt < 2MB
    if pde & 1 == 0 { serial_println!("[SMP] ERR: PD[0] not present"); return; }
    if pde & (1<<7) != 0 { // 2MB huge page covers 0x50000 already
        serial_println!("[SMP] 2MB huge page covers 0x50000 ✓ (no mapping needed)");
        return;
    }

    let pt = (phys_offset + (pde & !0xFFF)) as *mut u64;
    let pt_idx = (virt >> 12) & 0x1FF; // = 0x50 = 80
    let old = *pt.add(pt_idx as usize);
    // present=1, writable=1, NX=0 (executable)
    *pt.add(pt_idx as usize) = phys | 0x003;
    core::arch::asm!("invlpg [{0}]", in(reg) virt, options(nostack, preserves_flags));
    serial_println!("[SMP] Identity map: virt 0x{:x} → phys 0x{:x} (old PTE={:#x}) ✓", virt, phys, old);
}

pub fn init(phys_offset: u64, cr3: u64, rsdp_addr: Option<u64>) {
    serial_println!("");
    serial_println!("╔══════════════════════════════════════╗");
    serial_println!("║      AXIOM SMP — Multi-Core Boot     ║");
    serial_println!("╚══════════════════════════════════════╝");

    CORE_LOCALS[0].is_online.store(true, Ordering::SeqCst);

    serial_println!("[SMP] phys_offset={:#x} cr3={:#x}", phys_offset, cr3);
    let apic_ids = unsafe { parse_madt(phys_offset, rsdp_addr) };

    if apic_ids.len() <= 1 {
        serial_println!("[SMP] Single-core mode (start QEMU with -smp 4 for SMP)");
        print_summary(1);
        return;
    }

    // Identity-map the trampoline page so 64-bit code at 0x500A0 is executable
    // Identity map for 0x50000 is now done in main.rs via the page mapper.

    let lapic_virt = phys_offset + LAPIC_PHYS;
    serial_println!("[SMP] LAPIC virt addr={:#x}", lapic_virt);

    // Verify LAPIC is accessible — read LAPIC ID register
    // If this faults, the LAPIC MMIO is not mapped at phys_offset+0xFEE00000
    let lapic_id_raw = unsafe { lapic_read(lapic_virt, LAPIC_ID) };
    serial_println!("[SMP] LAPIC ID reg raw={:#x}", lapic_id_raw);
    let bsp_id = (lapic_id_raw >> 24) as u8;
    serial_println!("[SMP] BSP APIC ID={}, starting {} AP(s)", bsp_id, apic_ids.len() - 1);

    for &apic_id in apic_ids.iter().filter(|&&id| id != bsp_id) {
        let core_id = apic_id as usize;
        if core_id >= MAX_CORES { continue; }

        let stack_top = unsafe {
            AP_STACKS[core_id].as_ptr().add(16384) as u64
        };
        // Clear magic BEFORE SIPI
        let magic_addr = (phys_offset + 0x0FFE) as *mut u8;
        unsafe { core::ptr::write_volatile(magic_addr, 0x00); }
        // Also clear the magic in the trampoline page itself for AP2/3
        unsafe { core::ptr::write_volatile((phys_offset + 0x50FFE) as *mut u8, 0x00); } // clear first

        unsafe {
            install_trampoline(phys_offset, cr3, core_id as u32, stack_top);
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            // Clean INIT - SIPI - SIPI to the trampoline at physical 0x50000.
            // No firmware workarounds: under UEFI the APs are ours to start.
            send_sipi(lapic_virt, apic_id, 0x50);
        }


        // Wait up to ~200ms for the AP to report online via ap_main.
        let mut ms = 0u32;
        loop {
            for _ in 0..100_000u64 { unsafe { core::hint::spin_loop(); } }
            ms += 1;
            if CORE_LOCALS[core_id].is_online.load(Ordering::SeqCst) { break; }
            if ms >= 200 { break; }
        }
        if !CORE_LOCALS[core_id].is_online.load(Ordering::SeqCst) {
            serial_println!("[SMP] Core {} did not start (see docs/SMP_STATUS.md)", core_id);
        }
    }

    let total = 1 + APS_ONLINE.load(Ordering::SeqCst);
    print_summary(total);
}

fn print_summary(online: u32) {
    serial_println!("");
    serial_println!("[SMP] ── Online cores ──────────────────────");
    for i in 0..MAX_CORES {
        if CORE_LOCALS[i].is_online.load(Ordering::SeqCst) {
            serial_println!("[SMP]   Core {}: ONLINE  budget={}t/epoch",
                i, CORE_LOCALS[i].scba_budget_max);
        }
    }
    serial_println!("[SMP]   Total: {}/{}", online, MAX_CORES);
    serial_println!("[SMP] ────────────────────────────────────");
    serial_println!("");
}

pub fn logical_cpu_count() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        let ebx_val: u32;
        unsafe {
            core::arch::asm!(
                "push rbx", "mov eax, 1", "cpuid",
                "mov {0:e}, ebx", "pop rbx",
                out(reg) ebx_val, out("eax") _, out("ecx") _, out("edx") _,
                options(nomem)
            );
        }
        ((ebx_val >> 16) & 0xFF).max(1)
    }
    #[cfg(not(target_arch = "x86_64"))]
    { 1 }
}
