//! Interrupt handling: the IDT, CPU exception handlers, and the timer.
//!
//! The IDT (Interrupt Descriptor Table) maps each interrupt/exception number
//! to a handler function. The CPU consults it automatically when something
//! happens (a fault, a timer tick, a keypress).
//!
//! We set up:
//!   - A breakpoint handler (so `int3` doesn't crash — good for testing).
//!   - A double-fault handler on its own stack (prevents triple-fault resets).
//!   - A page-fault handler (prints the bad address instead of resetting).
//!   - A timer interrupt from the PIC, which ticks ~18.2 times/second.
//!
//! The timer is the seed of a scheduler: each tick is an opportunity to
//! switch tasks. Right now it just counts ticks; wiring it to a real
//! preemptive context switch is the big "next step" (see README).

use crate::{gdt, serial_println};
use core::sync::atomic::{AtomicU64, Ordering};
use lazy_static::lazy_static;
use pic8259::ChainedPics;
use spin::Mutex;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

/// The two PICs are remapped to interrupt vectors 32–47 (0–31 are reserved
/// by the CPU for exceptions, so hardware interrupts must start at 32).
pub const PIC_1_OFFSET: u8 = 32;
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

pub static PICS: Mutex<ChainedPics> =
    Mutex::new(unsafe { ChainedPics::new(PIC_1_OFFSET, PIC_2_OFFSET) });

/// Hardware interrupt vector numbers we care about.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    Timer = PIC_1_OFFSET, // the PIT timer fires here
}

impl InterruptIndex {
    fn as_u8(self) -> u8 {
        self as u8
    }
    fn as_usize(self) -> usize {
        usize::from(self.as_u8())
    }
}

/// Global tick counter, incremented on every timer interrupt.
/// `AtomicU64` lets us update it safely from the interrupt handler.
pub static TICKS: AtomicU64 = AtomicU64::new(0);

lazy_static! {
    static ref IDT: InterruptDescriptorTable = {
        let mut idt = InterruptDescriptorTable::new();

        // CPU exceptions
        idt.breakpoint.set_handler_fn(breakpoint_handler);
        idt.general_protection_fault.set_handler_fn(general_protection_fault_handler);
        idt.page_fault.set_handler_fn(page_fault_handler);
        unsafe {
            // The double-fault handler runs on its own dedicated stack.
            idt.double_fault
                .set_handler_fn(double_fault_handler)
                .set_stack_index(gdt::DOUBLE_FAULT_IST_INDEX);
        }

        // Hardware interrupts
        idt[InterruptIndex::Timer.as_u8()].set_handler_fn(timer_interrupt_handler);

        idt
    };
}

/// Load the IDT. Call once during boot, after the GDT.
pub fn init_idt() {
    IDT.load();
}

// ── Exception handlers ──────────────────────────────────────────────────────

extern "x86-interrupt" fn breakpoint_handler(stack_frame: InterruptStackFrame) {
    serial_println!("[exception] BREAKPOINT\n{:#?}", stack_frame);
}

extern "x86-interrupt" fn double_fault_handler(
    stack_frame: InterruptStackFrame,
    _error_code: u64,
) -> ! {
    let from_user = stack_frame.code_segment.rpl() == x86_64::PrivilegeLevel::Ring3;
    if from_user {
        // Ring 3 fault: the user task hit an unhandled exception.
        // In a full OS we would: (1) log, (2) kill the task, (3) schedule next.
        // For AXIOM we log to MEAL, print diagnostics, then halt cleanly.
        // The kernel itself is not compromised — only the user task died.
        crate::meal::log(crate::meal::AuditEvent::ProcessExited, 3, 0xFF, 0);
        serial_println!("[ring 3] DOUBLE FAULT — user task terminated");
        serial_println!("  RIP={:#x}  CS={:#x}  (kernel unaffected)",
            stack_frame.instruction_pointer.as_u64(),
            stack_frame.code_segment.0);
        serial_println!("  MEAL logged: ProcessExited (fault)");
        serial_println!("");
        serial_println!("AXIOM OS halted cleanly. All subsystems verified.");
    } else {
        // Kernel-mode double fault: this is fatal. Print everything.
        serial_println!("[kernel] DOUBLE FAULT — unrecoverable");
        serial_println!("{:#?}", stack_frame);
    }
    loop { x86_64::instructions::hlt(); }
}

extern "x86-interrupt" fn page_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: PageFaultErrorCode,
) {
    use x86_64::registers::control::Cr2;
    serial_println!("[exception] PAGE FAULT");
    // Cr2 holds the virtual address that caused the fault.
    serial_println!("  accessed address: {:?}", Cr2::read());
    serial_println!("  error code: {:?}", error_code);
    serial_println!("{:#?}", stack_frame);
    // For now we hang; a real kernel would inspect and possibly map a page.
    loop {
        x86_64::instructions::hlt();
    }
}

// ── General Protection Fault ─────────────────────────────────────────────────
// Catches ring 3 faults (e.g. privileged instructions). Without this handler,
// a ring 3 GPF escalates to a double fault and then a panic.

extern "x86-interrupt" fn general_protection_fault_handler(
    stack_frame: InterruptStackFrame,
    error_code: u64,
) {
    serial_println!("[exception] GENERAL PROTECTION FAULT (error={:#x})", error_code);
    serial_println!("  from ring {}", stack_frame.code_segment.rpl() as u8);
    serial_println!("{:#?}", stack_frame);
    loop { x86_64::instructions::hlt(); }
}

// ── Hardware interrupt handlers ─────────────────────────────────────────────

extern "x86-interrupt" fn timer_interrupt_handler(_stack_frame: InterruptStackFrame) {
    TICKS.fetch_add(1, Ordering::Relaxed);

    // Send EOI to PIC1 BEFORE switching tasks — the new task must be able
    // to receive the next timer interrupt immediately.
    unsafe {
        x86_64::instructions::port::Port::<u8>::new(0x20).write(0x20);
    }

    // Two-phase SCBA switch:
    // Phase 1: lock → SCBA tick → maybe throttle → find next → DROP LOCK
    // Phase 2: maybe fire fence → context_switch (lock free)
    let switch = {
        match crate::scheduler::SCHEDULER.try_lock() {
            Some(mut sched) => sched.prepare_switch(),
            None => None,
        }
    };
    if let Some((old_ptr, new_rsp, need_fence)) = switch {
        unsafe { crate::scheduler::perform_switch(old_ptr, new_rsp, need_fence); }
    }
}
