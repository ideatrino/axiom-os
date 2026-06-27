//! SYSCALL/SYSRET setup and kernel-side dispatcher.
//!
//! Three MSRs configure the SYSCALL mechanism:
//!   EFER.SCE  — enable SYSCALL instruction
//!   STAR      — CS selectors for SYSCALL and SYSRET
//!   LSTAR     — RIP of our assembly entry stub (syscall_entry.s)
//!   SFMASK    — RFLAGS bits to clear on SYSCALL entry (IF → interrupts off)
//!
//! On SYSCALL:  CPU saves RIP→RCX, RFLAGS→R11, clears SFMASK bits, jumps to LSTAR.
//! On SYSRET:   CPU loads RIP from RCX, RFLAGS from R11, sets CS/SS from STAR, RPL=3.

use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use crate::serial_println;

const IA32_EFER:   u32 = 0xC000_0080;
const IA32_STAR:   u32 = 0xC000_0081;
const IA32_LSTAR:  u32 = 0xC000_0082;
const IA32_SFMASK: u32 = 0xC000_0084;

// 64 KiB kernel stack, used only during SYSCALL handling.
// Single-core simplification: one static stack is safe because SFMASK
// clears IF on entry, so the timer cannot interrupt mid-syscall.
const STACK_SIZE: usize = 64 * 1024;
static mut SYSCALL_STACK: [u8; STACK_SIZE] = [0; STACK_SIZE];

// These two statics are referenced BY NAME from syscall_entry.s via
// RIP-relative addressing. The #[no_mangle] ensures the linker can find them.
#[no_mangle]
pub static mut SYSCALL_USER_RSP: u64 = 0;   // saves user RSP on entry
#[no_mangle]
pub static mut SYSCALL_KERNEL_RSP: u64 = 0; // top of SYSCALL_STACK

// Stats visible to the logger / checkpoint message.
pub static SYSCALL_COUNT:   AtomicU64 = AtomicU64::new(0);
pub static LAST_SYSCALL_NR: AtomicU64 = AtomicU64::new(u64::MAX);
pub static LAST_SYSCALL_RET: AtomicI64 = AtomicI64::new(0);

extern "C" { fn syscall_entry(); }

unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32; let hi: u32;
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr, out("eax") lo, out("edx") hi,
            options(nostack, nomem),
        );
    }
    ((hi as u64) << 32) | lo as u64
}

unsafe fn wrmsr(msr: u32, value: u64) {
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") (value as u32),
            in("edx") ((value >> 32) as u32),
            options(nostack),
        );
    }
}

/// Initialise SYSCALL/SYSRET. Call once, early in boot.
pub fn init() {
    unsafe {
        // 1. Enable SYSCALL: set EFER.SCE (bit 0).
        wrmsr(IA32_EFER, rdmsr(IA32_EFER) | 1);

        // 2. STAR selectors.
        //    bits [47:32] = 0x0008 → kernel_code=0x08, kernel_data=0x10
        //    bits [63:48] = 0x0020 → SYSRET: SS=0x28|3, CS=0x30|3
        wrmsr(IA32_STAR, (0x0020_u64 << 48) | (0x0008_u64 << 32));

        // 3. LSTAR: our assembly entry point.
        wrmsr(IA32_LSTAR, syscall_entry as u64);

        // 4. SFMASK: clear IF on SYSCALL entry (bit 9).
        //    Keeps the timer out of the RSP-switch window at the top of the stub.
        wrmsr(IA32_SFMASK, 0x200);

        // 5. Point SYSCALL_KERNEL_RSP at the top of our static stack.
        let top = (SYSCALL_STACK.as_ptr() as u64 + STACK_SIZE as u64) & !0xF_u64;
        SYSCALL_KERNEL_RSP = top;
    }

    serial_println!(
        "[ok] SYSCALL/SYSRET: EFER.SCE=1  LSTAR=syscall_entry  STAR.ker=0x08/ret_base=0x20"
    );
}

/// Rust syscall dispatcher.
/// Called from syscall_entry.s with System V AMD64 calling convention:
///   rdi=nr, rsi=arg1, rdx=arg2, rcx=arg3.
/// Returns value to place in RAX for the caller.
#[no_mangle]
pub extern "C" fn syscall_dispatch(nr: u64, arg1: u64, _arg2: u64, _arg3: u64) -> i64 {
    SYSCALL_COUNT.fetch_add(1, Ordering::Relaxed);
    LAST_SYSCALL_NR.store(nr, Ordering::Relaxed);
    crate::meal::log(crate::meal::AuditEvent::SyscallDispatched, 3, nr, 0);

    let ret: i64 = match nr {
        // 0 — Yield: nothing to do yet; future: yield to scheduler.
        0 => {
            serial_println!("[ring 3 → kernel] SYSCALL  0 (Yield)      → 0");
            0
        }
        // 9 — ScbaQuery: return total speculation-barrier count.
        9 => {
            let fences = crate::scheduler::SCHEDULER
                .try_lock()
                .map(|s| s.stats.total_fences as i64)
                .unwrap_or(-1);
            serial_println!(
                "[ring 3 → kernel] SYSCALL  9 (ScbaQuery)  → {} fences fired so far", fences
            );
            fences
        }
        // 11 — Exit: user task is done.
        11 => {
            crate::user::notify_exit(arg1);
            0
        }
        _ => {
            serial_println!("[ring 3 → kernel] SYSCALL {} (unknown) → -ENOSYS", nr);
            -38
        }
    };

    LAST_SYSCALL_RET.store(ret, Ordering::Relaxed);
    ret
}
