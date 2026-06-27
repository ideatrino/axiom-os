//! Kernel heap allocator.
//!
//! We carve out a 1 MiB virtual address region, map physical frames into it,
//! and hand it to `linked_list_allocator::LockedHeap` which we declare as the
//! `#[global_allocator]`. After `init_heap()` returns, `alloc::vec::Vec`,
//! `alloc::boxed::Box`, `alloc::collections::BTreeMap` etc. all work.

use linked_list_allocator::LockedHeap;
use x86_64::{
    VirtAddr,
    structures::paging::{
        FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB,
        mapper::MapToError,
    },
};

/// Virtual address where the kernel heap starts.
/// Chosen to be far from kernel code and the bootloader's mappings.
pub const HEAP_START: usize = 0x_4444_4444_0000;

/// 1 MiB of heap — enough for Vec, BTreeMap, and all AXIOM modules.
pub const HEAP_SIZE: usize = 8 * 1024 * 1024;

/// The global allocator. Empty until `init_heap()` is called.
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// Map the heap pages and initialise the allocator.
/// Must be called exactly once, after paging is set up.
pub fn init_heap(
    mapper: &mut impl Mapper<Size4KiB>,
    frame_allocator: &mut impl FrameAllocator<Size4KiB>,
) -> Result<(), MapToError<Size4KiB>> {
    let heap_start = VirtAddr::new(HEAP_START as u64);
    let heap_end   = heap_start + HEAP_SIZE as u64 - 1u64;
    let start_page = Page::containing_address(heap_start);
    let end_page   = Page::containing_address(heap_end);

    for page in Page::range_inclusive(start_page, end_page) {
        let frame = frame_allocator
            .allocate_frame()
            .ok_or(MapToError::FrameAllocationFailed)?;
        let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
        unsafe {
            mapper.map_to(page, frame, flags, frame_allocator)?.flush();
        }
    }

    // Tell the allocator where its memory is.
    unsafe {
        ALLOCATOR.lock().init(HEAP_START as *mut u8, HEAP_SIZE);
    }

    Ok(())
}
