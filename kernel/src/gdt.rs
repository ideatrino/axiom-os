//! GDT + TSS — now with user segments and privilege stack for ring 3 interrupts.
//!
//! GDT layout (each slot = 8 bytes):
//!   Slot 0: null
//!   Slot 1: kernel_code  (0x08)
//!   Slot 2: kernel_data  (0x10)
//!   Slot 3-4: TSS        (0x18, 0x20) — 16 bytes, two slots
//!   Slot 5: user_data    (0x28 | RPL=3 = 0x2B)
//!   Slot 6: user_code    (0x30 | RPL=3 = 0x33)
//!
//! STAR MSR for SYSCALL/SYSRET:
//!   [47:32] = 0x0008  → SYSCALL  CS=0x08 (kernel_code), SS=0x10 (kernel_data)
//!   [63:48] = 0x0020  → SYSRET64 CS=0x30|3 (user_code), SS=0x28|3 (user_data)

use lazy_static::lazy_static;
use x86_64::PrivilegeLevel;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// Stack used when the CPU switches from ring 3 → ring 0 on any interrupt.
/// Without RSP0 set in the TSS, the CPU would load RSP=0 and immediately
/// triple-fault when a timer fires while user code is running.
static mut PRIV_STACK: [u8; 4096 * 8] = [0; 4096 * 8]; // 32 KiB

lazy_static! {
    static ref TSS: TaskStateSegment = {
        let mut tss = TaskStateSegment::new();

        // IST[0]: dedicated clean stack for the double-fault handler.
        tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
            const SIZE: usize = 4096 * 5;
            static mut STACK: [u8; SIZE] = [0; SIZE];
            let start = VirtAddr::from_ptr(&raw const STACK);
            start + SIZE as u64
        };

        // RSP0: the kernel stack the CPU switches to on ring 3 → ring 0.
        // Required for timer/exception handling while user code is running.
        tss.privilege_stack_table[0] = unsafe {
            let start = VirtAddr::from_ptr(&raw const PRIV_STACK);
            start + PRIV_STACK.len() as u64
        };

        tss
    };
}

struct Selectors {
    kernel_code: SegmentSelector,
    kernel_data: SegmentSelector,
    tss:         SegmentSelector,
    user_data:   SegmentSelector, // stored with RPL=3 for IRET frames
    user_code:   SegmentSelector, // stored with RPL=3 for IRET frames
}

lazy_static! {
    static ref GDT: (GlobalDescriptorTable, Selectors) = {
        let mut gdt = GlobalDescriptorTable::new();
        let kernel_code = gdt.append(Descriptor::kernel_code_segment()); // slot 1
        let kernel_data = gdt.append(Descriptor::kernel_data_segment()); // slot 2
        let tss         = gdt.append(Descriptor::tss_segment(&TSS));     // slots 3-4
        let ud_raw      = gdt.append(Descriptor::user_data_segment());   // slot 5
        let uc_raw      = gdt.append(Descriptor::user_code_segment());   // slot 6

        // Set RPL=3 on user selectors so they can be pushed directly into IRET frames.
        let user_data = SegmentSelector::new(ud_raw.index(), PrivilegeLevel::Ring3);
        let user_code = SegmentSelector::new(uc_raw.index(), PrivilegeLevel::Ring3);

        (gdt, Selectors { kernel_code, kernel_data, tss, user_data, user_code })
    };
}

/// Load the GDT, set CS/SS to kernel segments, load the TSS.
pub fn init() {
    use x86_64::instructions::segmentation::{Segment, CS, SS};
    use x86_64::instructions::tables::load_tss;
    GDT.0.load();
    unsafe {
        CS::set_reg(GDT.1.kernel_code);
        SS::set_reg(GDT.1.kernel_data);
        load_tss(GDT.1.tss);
    }
}

/// User code selector (slot 6, RPL=3 = 0x33). Use in IRET CS field.
pub fn user_code_selector() -> SegmentSelector { GDT.1.user_code }
/// User data selector (slot 5, RPL=3 = 0x2B). Use in IRET SS field.
pub fn user_data_selector() -> SegmentSelector { GDT.1.user_data }
