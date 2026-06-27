//! Minimal ELF-64 loader for AXIOM user processes.
//!
//! Loads a statically-linked ELF binary from a byte slice into user-accessible
//! pages, then returns the entry point virtual address.
//!
//! Supported: ET_EXEC (static executable), 64-bit, little-endian, x86-64.
//! Not supported: dynamic linking, relocations, shared libraries.
//!
//! Security: every segment is mapped with the minimum required flags.
//! Read-only code segments are mapped PRESENT (not WRITABLE).
//! Writable data segments are mapped PRESENT | WRITABLE.
//! The NX bit (NO_EXECUTE) is set on non-executable segments.

use x86_64::{
    VirtAddr,
    structures::paging::{
        FrameAllocator, Mapper, Page, PageTableFlags, Size4KiB,
    },
};
use crate::serial_println;

// ── ELF-64 header constants ───────────────────────────────────────────────────
const ELFMAG:      [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64:  u8  = 2;
const ELFDATA2LSB: u8  = 1;   // little-endian
const EM_X86_64:   u16 = 62;
const ET_EXEC:     u16 = 2;
const PT_LOAD:     u32 = 1;

// ELF program header flags
const PF_X: u32 = 1;   // execute
const PF_W: u32 = 2;   // write
const PF_R: u32 = 4;   // read

#[derive(Debug)]
pub enum ElfError {
    TooShort,
    BadMagic,
    NotElf64,
    NotLittleEndian,
    NotX86_64,
    NotExecutable,
    BadPhOffset,
    SegmentOutOfBounds,
    PageMapFailed,
    FrameAllocFailed,
}

/// Load an ELF binary from `bytes` into user-accessible pages.
/// Returns the entry point virtual address on success.
pub unsafe fn load(
    bytes:       &[u8],
    mapper:      &mut impl Mapper<Size4KiB>,
    frame_alloc: &mut impl FrameAllocator<Size4KiB>,
    phys_offset: VirtAddr,
) -> Result<u64, ElfError> {
    // ── Validate ELF header ──────────────────────────────────────────────────
    if bytes.len() < 64 { return Err(ElfError::TooShort); }
    if &bytes[0..4] != ELFMAG       { return Err(ElfError::BadMagic); }
    if bytes[4]     != ELFCLASS64   { return Err(ElfError::NotElf64); }
    if bytes[5]     != ELFDATA2LSB  { return Err(ElfError::NotLittleEndian); }

    let e_type    = u16::from_le_bytes([bytes[16], bytes[17]]);
    let e_machine = u16::from_le_bytes([bytes[18], bytes[19]]);
    if e_machine != EM_X86_64 { return Err(ElfError::NotX86_64); }
    if e_type    != ET_EXEC   { return Err(ElfError::NotExecutable); }

    let e_entry   = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
    let e_phoff   = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let e_phentsize = u16::from_le_bytes([bytes[54], bytes[55]]) as usize;
    let e_phnum     = u16::from_le_bytes([bytes[56], bytes[57]]) as usize;

    serial_println!("[elf] entry={:#x}  phoff={:#x}  phnum={}  phentsize={}",
        e_entry, e_phoff, e_phnum, e_phentsize);

    // ── Load PT_LOAD segments ─────────────────────────────────────────────────
    for i in 0..e_phnum {
        let off = e_phoff + i * e_phentsize;
        if off + e_phentsize > bytes.len() { return Err(ElfError::BadPhOffset); }

        let p_type   = u32::from_le_bytes(bytes[off..off+4].try_into().unwrap());
        if p_type != PT_LOAD { continue; }

        let p_flags  = u32::from_le_bytes(bytes[off+4..off+8].try_into().unwrap());
        let p_offset = u64::from_le_bytes(bytes[off+8..off+16].try_into().unwrap()) as usize;
        let p_vaddr  = u64::from_le_bytes(bytes[off+16..off+24].try_into().unwrap());
        let p_filesz = u64::from_le_bytes(bytes[off+32..off+40].try_into().unwrap()) as usize;
        let p_memsz  = u64::from_le_bytes(bytes[off+40..off+48].try_into().unwrap()) as usize;
        let p_align  = u64::from_le_bytes(bytes[off+48..off+56].try_into().unwrap());

        serial_println!("[elf] PT_LOAD  vaddr={:#x}  filesz={:#x}  memsz={:#x}  flags={:#03x}  align={:#x}",
            p_vaddr, p_filesz, p_memsz, p_flags, p_align);

        if p_offset + p_filesz > bytes.len() { return Err(ElfError::SegmentOutOfBounds); }

        // Build page flags.
        let mut page_flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if p_flags & PF_W != 0 { page_flags |= PageTableFlags::WRITABLE; }
        if p_flags & PF_X == 0 { page_flags |= PageTableFlags::NO_EXECUTE; }

        // Map and copy one page at a time.
        let seg_data = &bytes[p_offset..p_offset + p_filesz];
        let start_page = p_vaddr & !0xFFF;
        let end_addr   = p_vaddr + p_memsz as u64;
        let end_page   = (end_addr + 0xFFF) & !0xFFF;

        let mut vpage = start_page;
        while vpage < end_page {
            let frame = frame_alloc.allocate_frame()
                .ok_or(ElfError::FrameAllocFailed)?;

            let page: Page<Size4KiB> = Page::containing_address(VirtAddr::new(vpage));
            unsafe {
                mapper.map_to(page, frame, page_flags, frame_alloc)
                    .map_err(|_| ElfError::PageMapFailed)?
                    .flush();
            }

            // Zero the physical frame via the kernel's physical-memory window.
            let kv = phys_offset + frame.start_address().as_u64();
            unsafe { core::ptr::write_bytes(kv.as_mut_ptr::<u8>(), 0, 4096); }

            // Copy segment bytes that fall within this page.
            let page_start = vpage;
            let page_end   = vpage + 4096;
            let copy_start = p_vaddr.max(page_start);
            let copy_end   = (p_vaddr + p_filesz as u64).min(page_end);
            if copy_start < copy_end {
                let src_off = (copy_start - p_vaddr) as usize;
                let dst_off = (copy_start - page_start) as usize;
                let len     = (copy_end - copy_start) as usize;
                let dst = kv.as_mut_ptr::<u8>().add(dst_off);
                unsafe { core::ptr::copy_nonoverlapping(seg_data[src_off..].as_ptr(), dst, len); }
            }

            vpage += 4096;
        }
    }

    Ok(e_entry)
}
