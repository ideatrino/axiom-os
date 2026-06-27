/* AXIOM userspace linker script.
 * Maps the program to 0x400000000000 — same base as the hand-coded program.
 * The ELF loader will map PT_LOAD segments to their p_vaddr addresses.
 */
OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS {
    . = 0x400000000000;

    .text : {
        *(.text*)
    }

    .rodata : {
        *(.rodata*)
    }

    .data : {
        *(.data*)
    }

    .bss : {
        *(.bss*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.note*)
        *(.comment*)
        *(.eh_frame*)
    }
}
