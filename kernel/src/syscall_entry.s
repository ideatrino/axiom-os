# AXIOM syscall entry point.
#
# The CPU jumps here when userspace executes SYSCALL.  On entry:
#   RCX  = saved user RIP   (SYSRET will jump back here)
#   R11  = saved user RFLAGS
#   RSP  = user stack       (DANGEROUS — switch immediately)
#   RAX  = syscall number
#   RDI  = arg1,  RSI = arg2,  RDX = arg3
#   IF=0 (cleared by SFMASK so the timer can't fire during the RSP switch)
#
# SYSCALL_USER_RSP and SYSCALL_KERNEL_RSP are statics defined in syscall.rs
# (both marked #[no_mangle]).  We access them via RIP-relative addressing.

.global syscall_entry
.section .text
syscall_entry:
    # ── 1. Save user RSP; switch to kernel syscall stack ─────────────────────
    movq  %rsp, SYSCALL_USER_RSP(%rip)
    movq  SYSCALL_KERNEL_RSP(%rip), %rsp

    # ── 2. Save registers we must restore before SYSRET ──────────────────────
    pushq %rcx          # saved user RIP
    pushq %r11          # saved user RFLAGS
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    # ── 3. Marshal args for Rust syscall_dispatch(nr, a1, a2, a3) ────────────
    # System V AMD64: rdi=1st, rsi=2nd, rdx=3rd, rcx=4th.
    # Currently:      rax=nr,  rdi=a1,  rsi=a2,  rdx=a3.
    movq  %rdx, %rcx   # a3  → 4th param
    movq  %rsi, %rdx   # a2  → 3rd param
    movq  %rdi, %rsi   # a1  → 2nd param
    movq  %rax, %rdi   # nr  → 1st param

    # Interrupts stay OFF throughout to keep the single-core syscall stack safe.
    callq syscall_dispatch
    # RAX = return value

    # ── 4. Restore callee-saved registers ────────────────────────────────────
    popq  %r15
    popq  %r14
    popq  %r13
    popq  %r12
    popq  %rbx
    popq  %rbp
    popq  %r11          # user RFLAGS → R11 (SYSRET restores RFLAGS from here)
    popq  %rcx          # user RIP    → RCX (SYSRET returns to this address)

    # ── 5. Restore user RSP and return to ring 3 ─────────────────────────────
    movq  SYSCALL_USER_RSP(%rip), %rsp
    sysretq             # CS/SS from STAR, RIP from RCX, RFLAGS from R11, RPL=3
