# AXIOM userspace hello program
# Statically linked, no libc, no runtime.
# Makes 3 AXIOM syscalls then spins.
#
# AXIOM syscall ABI:
#   rax = syscall number
#   rdi = arg1
#   SYSCALL instruction
#   return value in rax

.section .text
.global _start
_start:
    # Syscall 0: Yield
    xor %rax, %rax
    syscall

    # Syscall 9: ScbaQuery (returns fence count in rax)
    mov $9, %rax
    syscall

    # Syscall 11: Exit (code = rax from ScbaQuery, so we pass fence count)
    mov %rax, %rdi      # exit code = fence count from ScbaQuery
    mov $11, %rax
    syscall

    # Spin (should not reach here after Exit)
.spin:
    jmp .spin
