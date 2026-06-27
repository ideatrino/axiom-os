# AXIOM SMP AP Trampoline
# Copied to physical address 0x8000 before SIPI is sent.
# APs start in 16-bit real mode and must transition to 64-bit long mode.
#
# Memory layout at 0x8000:
#   0x8000: 16-bit startup code (this file)
#   0x8100: 32-bit protected mode code
#   0x8200: 64-bit long mode entry
#   0x8FF0: AP stack pointer (written by BSP before SIPI)
#   0x8FF8: 64-bit entry point (written by BSP before SIPI)

.section .ap_trampoline, "ax"
.code16

.global ap_trampoline_start
ap_trampoline_start:
    cli
    cld

    # Set up segments for real mode
    xor  %ax, %ax
    mov  %ax, %ds
    mov  %ax, %es
    mov  %ax, %ss

    # Load a temporary GDT (32-bit protected mode descriptors)
    lgdtl  ap_gdtr - ap_trampoline_start + 0x8000

    # Enable protected mode (CR0.PE = 1)
    mov  %cr0, %eax
    or   $1, %eax
    mov  %eax, %cr0

    # Far jump to flush prefetch queue and enter 32-bit mode
    ljmpl $0x08, $ap_32bit_entry

.code32
ap_32bit_entry:
    mov  $0x10, %ax
    mov  %ax,   %ds
    mov  %ax,   %es
    mov  %ax,   %ss

    # Enable PAE (CR4.PAE = 1) for long mode
    mov  %cr4,  %eax
    or   $0x20, %eax
    mov  %eax,  %cr4

    # Load PML4 base — BSP writes the PML4 address to 0x8FE8 before SIPI
    mov  0x8FE8, %eax
    mov  %eax,   %cr3

    # Enable long mode (EFER.LME = 1)
    mov  $0xC0000080, %ecx
    rdmsr
    or   $0x100, %eax
    wrmsr

    # Enable paging (CR0.PG = 1) — this activates long mode
    mov  %cr0,  %eax
    or   $0x80000001, %eax
    mov  %eax,  %cr0

    # Far jump to 64-bit code
    ljmpl $0x18, $ap_64bit_entry

.code64
ap_64bit_entry:
    # Load 64-bit stack (BSP writes to 0x8FF0)
    mov  0x8FF0, %rsp

    # Call ap_main(core_id) — BSP writes core_id to 0x8FE0
    mov  0x8FE0, %rdi
    mov  0x8FF8, %rax    # 64-bit entry point (Rust ap_main)
    call *%rax

    # Should never return
.ap_halt:
    hlt
    jmp  .ap_halt

# Minimal GDT for AP protected mode transition
.align 8
ap_gdt:
    .quad 0x0000000000000000   # null descriptor
    .quad 0x00CF9A000000FFFF   # 32-bit code (0x08)
    .quad 0x00CF92000000FFFF   # 32-bit data (0x10)
    .quad 0x00AF9A000000FFFF   # 64-bit code (0x18)
ap_gdt_end:

ap_gdtr:
    .word ap_gdt_end - ap_gdt - 1
    .long ap_gdt - ap_trampoline_start + 0x8000

.global ap_trampoline_end
ap_trampoline_end:
