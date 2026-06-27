# context_switch(old_rsp: *mut u64, new_rsp: u64)
#
# Called from Rust as:
#   context_switch(old_rsp_ptr, new_rsp)
#
# Arguments (System V AMD64 ABI):
#   rdi = pointer to where we should save the old RSP
#   rsi = the new RSP to load
#
# What we do:
#   1. Push all callee-saved registers + rflags onto the CURRENT stack.
#   2. Save current RSP into *rdi.
#   3. Load RSP from rsi (switch to new task's stack).
#   4. Pop all callee-saved registers + rflags from the NEW stack.
#   5. `ret` — pops RIP from the new stack, resuming the new task.
#
# The pushed layout (growing downward) matches Context in task.rs:
#   rip (via ret/call), rflags, rbp, rbx, r12, r13, r14, r15
# After push: RSP points at r15 (the lowest address).

.global context_switch
.section .text
context_switch:
    # Push callee-saved registers and rflags.
    # The `call` instruction already pushed the return address (RIP) for us,
    # so the stack already has RIP at the top when we enter here.
    pushfq          # push rflags
    push %rbp
    push %rbx
    push %r12
    push %r13
    push %r14
    push %r15

    # Save the old task's stack pointer.
    mov %rsp, (%rdi)

    # Load the new task's stack pointer.
    mov %rsi, %rsp

    # Restore the new task's registers.
    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %rbx
    pop %rbp
    popfq           # restore rflags (including the IF interrupt-enable flag)

    # ret pops RIP — either the task's entry point (first run)
    # or back into the caller of context_switch (resume).
    ret
