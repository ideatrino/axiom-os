//! Physical memory management.
//!
//! Two things live here:
//!
//! 1. `init()` — creates an OffsetPageTable so we can map virtual addresses
//!    to physical frames. The bootloader maps ALL physical memory at a fixed
//!    virtual offset and tells us what that offset is, so we just use it.
//!
//! 2. `BootInfoFrameAllocator` — walks the bootloader's memory map and hands
//!    out free physical 4 KiB frames one at a time. Used during heap setup.

use bootloader_api::info::{MemoryRegionKind, MemoryRegions};
use x86_64::{
    PhysAddr, VirtAddr,
    structures::paging::{
        FrameAllocator, OffsetPageTable, Page, PageTable, PhysFrame, Size4KiB,
    },
};

/// Build an OffsetPageTable from the physical memory offset the bootloader
/// tells us about. Unsafe because the caller must guarantee the offset is
/// correct and physical memory is mapped there.
pub unsafe fn init(physical_memory_offset: VirtAddr) -> OffsetPageTable<'static> {
    let level_4_table = unsafe { active_level_4_table(physical_memory_offset) };
    unsafe { OffsetPageTable::new(level_4_table, physical_memory_offset) }
}

/// Read CR3 to find the active level-4 page table and return a mutable
/// reference to it using the physical memory offset.
unsafe fn active_level_4_table(physical_memory_offset: VirtAddr) -> &'static mut PageTable {
    use x86_64::registers::control::Cr3;
    let (level_4_table_frame, _) = Cr3::read();
    let phys = level_4_table_frame.start_address();
    let virt = physical_memory_offset + phys.as_u64();
    let page_table_ptr: *mut PageTable = virt.as_mut_ptr();
    unsafe { &mut *page_table_ptr }
}

/// A FrameAllocator that walks the bootloader memory map returning
/// frames in Usable regions. O(N) per allocation — fine for boot-time use.
pub struct BootInfoFrameAllocator {
    memory_regions: &'static MemoryRegions,
    next: usize,
}

impl BootInfoFrameAllocator {
    /// Initialise from the bootloader's memory map.
    /// Unsafe because the caller must ensure the memory map is valid.
    pub unsafe fn init(memory_regions: &'static MemoryRegions) -> Self {
        BootInfoFrameAllocator { memory_regions, next: 0 }
    }

    /// Iterator over every usable physical frame in the memory map.
    fn usable_frames(&self) -> impl Iterator<Item = PhysFrame> {
        self.memory_regions
            .iter()
            .filter(|r| r.kind == MemoryRegionKind::Usable)
            .map(|r| r.start..r.end)
            .flat_map(|r| r.step_by(4096))
            .map(|addr| PhysFrame::containing_address(PhysAddr::new(addr)))
    }
}

unsafe impl FrameAllocator<Size4KiB> for BootInfoFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame> {
        let frame = self.usable_frames().nth(self.next);
        self.next += 1;
        frame
    }
}
