//! Build script for the `boot` crate.
//!
//! Runs at compile time on the HOST. It:
//!   1. Locates the compiled kernel ELF (provided by the artifact dependency).
//!   2. Uses the `bootloader` crate to wrap it into bootable BIOS and UEFI
//!      disk images.
//!   3. Exports the image paths as environment variables so `main.rs` can
//!      find them with `env!(...)`.
//!
//! This mirrors the official `bootloader` crate's disk-image example.

use std::path::PathBuf;

fn main() {
    // The artifact dependency exposes the kernel binary's path through this
    // environment variable. The name format is:
    //   CARGO_BIN_FILE_<DEPNAME_UPPERCASE>_<binname>
    // Our dependency is named `kernel` and its binary is also `kernel`.
    let kernel_path = PathBuf::from(
        std::env::var_os("CARGO_BIN_FILE_KERNEL_kernel")
            .expect("kernel artifact dependency not found — check boot/Cargo.toml"),
    );

    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());

    // ── Create a BIOS-bootable image (works in QEMU with no firmware setup) ──
    let bios_image = out_dir.join("axiom-bios.img");
    bootloader::BiosBoot::new(&kernel_path)
        .create_disk_image(&bios_image)
        .expect("failed to create BIOS disk image");

    // ── Create a UEFI-bootable image (for modern hardware / OVMF) ────────────
    let uefi_image = out_dir.join("axiom-uefi.img");
    bootloader::UefiBoot::new(&kernel_path)
        .create_disk_image(&uefi_image)
        .expect("failed to create UEFI disk image");

    // Pass the paths to main.rs via env vars.
    println!("cargo:rustc-env=BIOS_IMAGE={}", bios_image.display());
    println!("cargo:rustc-env=UEFI_IMAGE={}", uefi_image.display());

    // Rebuild if the kernel changes.
    println!("cargo:rerun-if-changed={}", kernel_path.display());
}
