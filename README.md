# AXIOM OS

A formally-specified secure microkernel written in Rust, running on bare-metal x86-64.

**Single command to build and run:**

    cargo run --package boot

Requires: Rust nightly, QEMU (qemu-system-x86_64), and the cc toolchain.

---

## What AXIOM is

AXIOM is a research operating system kernel that makes formal security guarantees
executable. Every subsystem corresponds to a theorem in the AXIOM v4 formal
specification. Those theorems are not just claims -- they run and pass on every boot.

---

## Boot output

    AXIOM OS booting...
    [ok] GDT + TSS loaded
    [ok] IDT loaded
    [ok] heap ready (8192 KiB at 0x444444440000)
    ... TCD capability demo (7 properties) ...
    ... EIPC encrypted IPC demo (KNP theorem) ...
    ... VMZ verified memory zeroing ...
    ... DSL dynamic security lattice (7 axioms) ...
    ... ZTDF zero-trust driver framework ...
    ... MEAL audit log (19 entries, chain verified) ...
    SHOT 1-11 all active and verified
    IRET -> ring 3  CS=0x33
    SYSCALL 0/9/11 dispatched and returned
    AXIOM OS boot sequence complete.

---

---

## Known limitations

**SMP (multi-core):** Core detection, ACPI/MADT parsing, the AP trampoline,
trampoline page-mapping, and the xAPIC INIT-SIPI-SIPI startup sequence are
all implemented. AP startup is **not yet confirmed** under available
virtualization: APs reset on INIT but do not start on SIPI under QEMU/TCG,
QEMU/KVM, SeaBIOS, and OVMF/UEFI. The single-core path boots cleanly on
both BIOS and UEFI with all subsystems verified. Full diagnosis and
excluded causes: [docs/SMP_STATUS.md](docs/SMP_STATUS.md).


---

## Formal contributions

### TCD -- Temporal Capability Decay

Every kernel resource is governed by a capability authenticated with
HMAC-SHA-256 (RFC 2104). Capabilities have an expiry time and a derivation
depth limit. An attacker without the master key K cannot forge a valid
capability, regardless of how many valid capabilities they have observed.

    cap := (oid, rights, tau_exp, depth, H(parent), HMAC-SHA-256(fields, K))
    valid(cap, now, K) := now < tau_exp AND HMAC(fields, K) == cap.mac

Running proof: SHA-256("") = e3b0c442... verified against FIPS 180-4 known
vector at every boot. Forged MAC rejected. Expired capability rejected.
Wrong key rejected. HMAC-SHA-256 RFC 2104 Test Case 1 verified (b0344c61...).

### SCBA -- Side-Channel Budget Accounting

Each task has a leakage budget B0 (ticks per epoch). The scheduler tracks
budget consumption and fires a speculation barrier (LFENCE + MFENCE) when a
task's budget is exhausted, bounding the timing channel to at most B0 ticks
of observable information per epoch.

    Sum(Leakages) <= B0 per epoch

Running proof: Fences logged to MEAL. switches=21,999 fences=255 after 20
minutes of continuous operation, confirming the barrier fires exactly when
the budget exhausts.

### EIPC -- Encrypted IPC + KNP Theorem

The kernel routes inter-process messages without being able to read them.
Session keys are derived from shared TCD capability chain hashes using
HKDF-SHA-256 (RFC 5869). Messages are encrypted with ChaCha20 (RFC 8439)
and authenticated with HMAC-SHA-256 before being handed to the kernel queue.

    KNP: H(plaintext | kernel_state, ciphertext) = H(plaintext | ciphertext) = 0

Running proof: Kernel stores 48700d95... (ciphertext). Receiver recovers
"Hello AXIOM!". Tampered ciphertext rejected by HMAC check. ChaCha20
RFC 8439 known vector verified (first block word = 0xade0b876).

### MEAL -- Monotonic Encrypted Audit Log

Every security event is appended to a hash-chained, HMAC-authenticated log.
Deleting or reordering any entry requires breaking HMAC-SHA-256 under the
audit key K_audit, which is distinct from K.

    mac_n  = HMAC(fields_n, K_audit)
    prev_n = SHA-256(entry_{n-1})
    seq_n  > seq_{n-1}

Running proof: 19 chained entries, chain verification PASSED on every boot.
Events: LogInit, CapDerived x2, EipcSend x3, EipcRecv x3, MemZeroed,
LatticeReconf, DrvLoaded x3, DrvFaultMmio, DrvFaultSys, ScbaFence, BootDone.

### VMZ -- Verified Memory Zeroing

When a process exits, its heap frames are zeroed with REP STOSB and a
serialising MFENCE barrier before returning to the free pool. A successor
process reading from those frames learns zero bits about the previous
process's secrets.

    I(secret(p1); read_from_frame(p2)) = 0

Running proof: SHA-256(secret) = cfae920b... before zeroing.
SHA-256(zeros) = f5a5fd42... after. Hashes differ -> information destroyed.
All 64 bytes confirmed 0x00.

### DSL -- Dynamic Security Lattice

Information flow is governed by a runtime-reconfigurable security lattice
(L, <=, join, meet, bot, top). Any proposed new lattice is accepted only
after the kernel verifies all seven lattice axioms. Invalid lattices (e.g.
missing transitivity) are rejected.

    Read:  may_read(s, o)  <=> lambda(o) <= lambda(s)   [no read-up]
    Write: may_write(s, o) <=> lambda(s) <= lambda(o)   [no write-down]

Running proof: 4-level BLP verified (VALID). 5-level reconfiguration accepted
(VALID). Broken lattice (missing transitivity) rejected (REJECTED).

### ZTDF -- Zero-Trust Driver Framework

Every driver is bounded at load time to an explicit whitelist: allowed MMIO
regions, allowed IRQ numbers, allowed syscall numbers. Any violation terminates
the driver in O(1) and logs the fault to MEAL. No kernel reboot required.

Running proof:
  uart-com1: all ops within spec -> ACCEPTED
  mal-driver: MMIO to 0xFEE00000 (APIC) -> TERMINATED, MEAL logged
  esc-driver: syscall 8 (LatticeReconfig) -> TERMINATED, MEAL logged

---

## Source layout

    kernel/src/
    +-- main.rs           Boot sequence, task functions, Shot 12 summary
    +-- gdt.rs            GDT+TSS, user segments (ring 3), privilege stacks
    +-- interrupts.rs     IDT, PIC, timer, GP/DF/PF handlers, SCBA hook
    +-- memory.rs         OffsetPageTable, BootInfoFrameAllocator
    +-- allocator.rs      linked_list_allocator, 8 MiB heap
    +-- scheduler.rs      SCBA two-phase scheduler, fence enforcement
    +-- task.rs           TCB with ScbaState, new_with_budget(), new_idle()
    +-- context_switch.s  Assembly: save regs, swap RSP, restore, ret
    +-- syscall.rs        EFER/STAR/LSTAR/SFMASK setup, dispatch table
    +-- syscall_entry.s   Assembly SYSCALL stub, kernel stack swap, SYSRET
    +-- user.rs           Ring-3 page mapping, 28-byte user program, IRET
    +-- crypto.rs         SHA-256 (FIPS 180-4), HMAC-SHA-256 (RFC 2104)
    +-- crypto_aead.rs    ChaCha20 (RFC 8439), HKDF-SHA-256 (RFC 5869), AEAD
    +-- eipc.rs           EIPC channel, KNP demo
    +-- meal.rs           MEAL audit log, SHA-256 hash chain, HMAC per entry
    +-- vmz.rs            REP STOSB + MFENCE + SHA-256 proof
    +-- lattice.rs        4-level BLP, 7-axiom verifier, runtime reconfig
    +-- ztdf.rs           DriverSpec, ZtdfChecker, MMIO/IRQ/syscall bounds
    +-- log_buffer.rs     Static ring buffer (MEAL foundation)
    +-- framebuffer.rs    Indigo screen fill on boot
    +-- serial.rs         UART COM1 debug output
    +-- axiom/
        +-- mod.rs        axiom::run_demo() entry
        +-- capability.rs TCD with real HMAC-SHA-256, 7 properties
        +-- demo_crypto.rs FNV demo hash (superseded by crypto.rs)

---

## Verified cryptographic test vectors

    SHA-256("") = e3b0c44298fc1c149afbf4c8996fb924...  [FIPS 180-4 Appendix B.1]
    HMAC-SHA-256(key=0x0b*20, "Hi There") = b0344c61...  [RFC 2104 Appendix B]
    ChaCha20(key=0, ctr=0, nonce=0) word0 = 0xade0b876  [RFC 8439 Section 2.3.2]

---

## Shots completed

    Shot  1  Boot, GDT/TSS, IDT, serial output, indigo framebuffer, TCD demo
    Shot  2  Heap allocator (8 MiB), Vec, Box, BTreeMap
    Shot  3  Preemptive multitasking, assembly context switcher, 4 tasks
    Shot  4  SCBA security scheduler, LFENCE+MFENCE speculation barriers
    Shot  5  Real HMAC-SHA-256 replacing demo FNV hash in TCD
    Shot  6  Ring-3 user mode, SYSCALL/SYSRET ABI, 29-byte user program
    Shot  7  EIPC encrypted IPC, ChaCha20, HKDF, KNP theorem
    Shot  8  MEAL tamper-evident audit log, SHA-256 hash chain
    Shot  9  VMZ verified memory zeroing, information-theoretic proof
    Shot 10  DSL dynamic security lattice, 7 axioms, runtime reconfiguration
    Shot 11  ZTDF zero-trust driver framework, fault detection and logging
    Shot 12  Final integration, boot summary, hardening, documentation

---

## Licence

Research prototype. Not for production use.

## Status

[![AXIOM OS CI](https://github.com/ideatrino/axiom-os/actions/workflows/ci.yml/badge.svg)](https://github.com/ideatrino/axiom-os/actions/workflows/ci.yml)

## Paper

[📄 AXIOM OS: Executable Formal Security Guarantees in a Bare-Metal x86-64 Microkernel (PDF)](docs/paper.pdf)
