# SMP / Multi-Core Bring-Up: Status

AXIOM includes a complete SMP bring-up path: ACPI discovery, CPU
enumeration, an AP trampoline, and the xAPIC INIT–SIPI–SIPI startup
protocol. Application Processor (AP) **startup is not yet confirmed**
under the available virtualization environments; this document records
exactly what works, what does not, and what was ruled out, so the work
can be resumed cleanly.

## What works (verified)

- **ACPI RSDP discovery** on both BIOS and UEFI. The RSDP physical
  address is taken from the bootloader-provided `BootInfo.rsdp_addr`,
  with a legacy 0xE0000–0xFFFFF scan as fallback.
- **MADT parsing** finds all logical CPUs (e.g. `[0, 1, 2, 3]` under
  `-smp 4`). All multi-byte ACPI reads use unaligned accesses, so the
  parser is correct regardless of where firmware places the tables.
- **AP trampoline** is assembled (NASM) and written to physical
  `0x50000`. Its bytes, GDT, and 16→32→64-bit mode-transition encoding
  were verified under GDB.
- **Trampoline page mapping** via the kernel's `OffsetPageTable` mapper,
  which allocates intermediate tables as needed (works under the UEFI
  page-table layout, where a hand-rolled walk did not).
- **BSP IPI issue**: the xAPIC INIT–SIPI–SIPI sequence is sent via MMIO
  at `0xFEE00000`; ICR delivery-status polling reports successful
  delivery (`timeout=0`) for every IPI.

## What does not work

Under QEMU — both TCG emulation and KVM acceleration, with SeaBIOS and
with OVMF/UEFI — the APs **reset on INIT but do not start on SIPI**.
Reset-record dumps (`-d cpu_reset`) show each AP halted at the x86 reset
vector (`EIP=0000FFF0`, `CS=F000`, `CR0=60000010`, `HLT=1`), i.e. the
power-on state. No exception is raised: the trampoline is never executed,
so `ap_main` is never reached.

## Causes excluded by measurement

- **SeaBIOS SIPI interception** — APs were caught in a SeaBIOS halt loop
  at `0xFD0A9` (ROM, unpatchable). Avoided by booting UEFI/OVMF; the
  behaviour persists, so this is not the cause.
- **x2APIC MMIO inertness** — `IA32_APIC_BASE = 0xFEE00900`; x2APIC bit
  (10) is clear. The LAPIC is in legacy xAPIC mode, so MMIO IPI writes
  are the correct interface.
- **Unmapped trampoline page** — fixed; `0x50000` is identity-mapped and
  the prior `PD[0] not present` error is gone.
- **INIT/SIPI timing race** — the post-INIT delay was raised to 50M spin
  iterations with no change.
- **TCG-specific emulation quirk** — reproduced identically under KVM
  (`-enable-kvm -cpu host`), so it is not a software-emulation artifact.

## Suggested next steps

- Test on **bare metal**, where SIPI semantics are not mediated by a VMM.
- Instrument QEMU's `apic_deliver` / start-up-IPI path to see why the
  SIPI does not latch the AP out of wait-for-SIPI.
- Try alternative machine/CPU models and an MSR-based ICR path under an
  explicitly x2APIC-enabled configuration.

The single-core path (BSP only) boots cleanly on BIOS and UEFI with all
subsystems active; SMP detection runs and reports cores without
affecting single-core operation.
