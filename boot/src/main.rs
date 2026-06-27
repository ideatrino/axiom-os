//! Host-side launcher. Builds (via build.rs) and then runs the kernel in QEMU.
//!
//! Usage from the project root:
//!     cargo run --package boot              # BIOS boot (default, simplest)
//!     cargo run --package boot -- uefi      # UEFI boot (needs OVMF firmware)
//!
//! Press Ctrl+A then X to quit QEMU when running with `-serial stdio`.

use std::process::Command;

// These come from build.rs.
const BIOS_IMAGE: &str = env!("BIOS_IMAGE");
const UEFI_IMAGE: &str = env!("UEFI_IMAGE");

fn main() {
    let use_uefi = std::env::args().any(|a| a == "uefi");

    let mut cmd = Command::new("qemu-system-x86_64");

    if use_uefi {
        // UEFI boot requires the OVMF firmware. On most distros:
        //   sudo apt install ovmf
        // Adjust this path if your OVMF lives elsewhere.
        cmd.arg("-bios").arg("/usr/share/ovmf/OVMF.fd");
        cmd.arg("-drive")
            .arg(format!("format=raw,file={UEFI_IMAGE}"));
        println!("Booting AXIOM (UEFI) in QEMU...");
    } else {
        cmd.arg("-drive")
            .arg(format!("format=raw,file={BIOS_IMAGE}"));
        println!("Booting AXIOM (BIOS) in QEMU...");
    }

    // Route the kernel's serial output to this terminal. All the kernel's
    // serial_println! text shows up here.
    cmd.arg("-serial").arg("stdio");

    // A little extra RAM and a sane CPU.
    cmd.arg("-m").arg("256M");

    // Uncomment to log every interrupt + CPU reset (great for debugging a
    // triple-fault / boot loop):
    // cmd.arg("-d").arg("int,cpu_reset").arg("-no-reboot");

    println!("(Press Ctrl+A then X to quit QEMU.)\n");

    let status = cmd.status().expect(
        "failed to launch qemu-system-x86_64 — is QEMU installed and on your PATH?",
    );

    std::process::exit(status.code().unwrap_or(1));
}
