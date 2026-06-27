fn main() {
    // Compile the context-switch assembly and link it into the kernel.
    // Compile both assembly files together into one static lib.
    cc::Build::new()
        .file("src/context_switch.s")
        .file("src/syscall_entry.s")
        .file("src/smp_trampoline.s")
        .compile("axiom_asm");
    println!("cargo:rerun-if-changed=src/context_switch.s");
    println!("cargo:rerun-if-changed=src/syscall_entry.s");
    println!("cargo:rerun-if-changed=src/smp_trampoline.s");
}
