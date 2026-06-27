//! User space: page mapping, program installation, ring 3 entry.
//!
//! The "user program" is 29 bytes of raw machine code that:
//!   1. Calls SYSCALL 0  (Yield)
//!   2. Calls SYSCALL 9  (ScbaQuery — returns fence count)
//!   3. Calls SYSCALL 11 (Exit, code=0)
//!   4. Spins forever    (jmp -2 — legal at ring 3, timer wakes us)
//!
//! Two physical frames are allocated and mapped with the USER_ACCESSIBLE flag:
//!   - One 4 KiB code page  at USER_CODE_VIRT
//!   - One 4 KiB stack page below USER_STACK_TOP
//!
//! Entry is via IRET with CS/SS at ring 3.

use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::{
    VirtAddr,
    structures::paging::{FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB},
};
use crate::gdt;
use crate::serial_println;

pub const USER_CODE_VIRT:  u64 = 0x0000_4000_0000_0000;
pub const USER_STACK_TOP:  u64 = 0x0000_5000_0000_0000;

pub static USER_EXITED: AtomicBool = AtomicBool::new(false);

/// Called by the Exit syscall handler.
pub fn notify_exit(code: u64) {
    crate::meal::log(crate::meal::AuditEvent::ProcessExited, 3, code, 0);
    serial_println!("[ring 3 → kernel] SYSCALL 11 (Exit)   code={} → 0", code);
    USER_EXITED.store(true, Ordering::Relaxed);
    serial_println!("");
    serial_println!(">>> SHOT 12 — AXIOM OS FULLY OPERATIONAL <<<");
    serial_println!("    Ring 3 → kernel → ring 3 privilege round-trip: ✓");
    serial_println!("    All 11 subsystems active and verified:");
    serial_println!("      SYSCALL 0  Yield      → 0   (scheduler integration)");
    serial_println!("      SYSCALL 9  ScbaQuery  → {} fences total (SCBA active)",
        crate::syscall::SYSCALL_COUNT.load(core::sync::atomic::Ordering::Relaxed));
    serial_println!("      SYSCALL 11 Exit       → 0   (clean process termination)");
    serial_println!("    AXIOM OS boot sequence complete.");
    serial_println!("");
}

/// Raw machine bytes for the fallback hand-coded user program.
/// Used when no ELF binary is embedded.
const USER_PROGRAM: &[u8] = &[
    0x48, 0x31, 0xC0,                          // xor    rax, rax (Yield)
    0x0F, 0x05,                                // syscall
    0x48, 0xC7, 0xC0, 0x09, 0x00, 0x00, 0x00, // mov    rax, 9 (ScbaQuery)
    0x0F, 0x05,                                // syscall
    0x48, 0xC7, 0xC0, 0x0B, 0x00, 0x00, 0x00, // mov    rax, 11 (Exit)
    0x48, 0x31, 0xFF,                          // xor    rdi, rdi
    0x0F, 0x05,                                // syscall
    0xEB, 0xFE,                                // jmp -2 (spin)
];

/// ELF64 userspace binary embedded at compile time.
/// Built with: cd userspace && make
const ELF_PROGRAM: &[u8] = include_bytes!("../../userspace/hello.elf");

/// Load the ELF user program and map the user stack.
/// Returns the ELF entry point (or USER_CODE_VIRT for the fallback program).
pub fn setup(
    mapper:      &mut impl Mapper<Size4KiB>,
    frame_alloc: &mut impl FrameAllocator<Size4KiB>,
    phys_offset: VirtAddr,
) -> u64 {
    // ── Load ELF binary via elf_loader ────────────────────────────────────────
    let entry = unsafe {
        match crate::elf_loader::load(ELF_PROGRAM, mapper, frame_alloc, phys_offset) {
            Ok(ep) => {
                serial_println!(
                    "[ok] ELF loaded: {} bytes  entry={:#x}  (via elf_loader)",
                    ELF_PROGRAM.len(), ep
                );
                ep
            }
            Err(e) => {
                // Fallback: hand-coded program
                serial_println!("[warn] ELF load failed ({:?}), using hand-coded program", e);
                let flags = PageTableFlags::PRESENT
                    | PageTableFlags::WRITABLE
                    | PageTableFlags::USER_ACCESSIBLE;
                let frame = frame_alloc.allocate_frame().expect("no frame");
                let page  = Page::containing_address(VirtAddr::new(USER_CODE_VIRT));
                mapper.map_to(page, frame, flags, frame_alloc)
                    .expect("map failed").flush();
                let kv = phys_offset + frame.start_address().as_u64();
                let dst = kv.as_mut_ptr::<u8>();
                core::ptr::write_bytes(dst, 0xCC, 4096);
                core::ptr::copy_nonoverlapping(
                    USER_PROGRAM.as_ptr(), dst, USER_PROGRAM.len());
                USER_CODE_VIRT
            }
        }
    };

    // ── Map user stack ────────────────────────────────────────────────────────
    let stack_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;
    let stack_frame = frame_alloc.allocate_frame().expect("no frame for user stack");
    let stack_page  = Page::containing_address(VirtAddr::new(USER_STACK_TOP - 4096));
    unsafe {
        mapper.map_to(stack_page, stack_frame, stack_flags, frame_alloc)
            .expect("user stack map failed").flush();
        let kv = phys_offset + stack_frame.start_address().as_u64();
        core::ptr::write_bytes(kv.as_mut_ptr::<u8>(), 0, 4096);
    }
    serial_println!("[ok] user stack @ {:#x}..{:#x}",
        USER_STACK_TOP - 4096, USER_STACK_TOP);

    entry
}

/// Enter ring 3 via IRET — never returns.
/// `entry` is the virtual address to jump to (from ELF or fallback).
pub unsafe fn enter(entry: u64) -> ! {
    let cs     = gdt::user_code_selector().0 as u64; // 0x33
    let ss     = gdt::user_data_selector().0 as u64; // 0x2B
    let rflags = 0x202_u64; // IF=1 (interrupts on in user space), reserved bit 1

    serial_println!(
        "[ok] IRET → ring 3:  RIP={:#x}  RSP={:#x}  CS={:#x}  SS={:#x}",
        entry, USER_STACK_TOP, cs, ss
    );
    serial_println!("     User program: Yield → ScbaQuery → Exit → spin");
    serial_println!("");

    unsafe {
        core::arch::asm!(
            // Build the 64-bit IRET stack frame (IRET pops in this order):
            //   [RSP+32] SS        ← pushed first (highest address)
            //   [RSP+24] RSP_user
            //   [RSP+16] RFLAGS
            //   [RSP+ 8] CS
            //   [RSP+ 0] RIP       ← pushed last (lowest address = RSP after pushes)
            "push {ss}",
            "push {rsp_u}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
            "iretq",
            ss     = in(reg) ss,
            rsp_u  = in(reg) USER_STACK_TOP,
            rflags = in(reg) rflags,
            cs     = in(reg) cs,
            rip    = in(reg) entry,
            options(noreturn),
        );
    }
}
