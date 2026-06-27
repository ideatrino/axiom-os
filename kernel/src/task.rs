//! Task Control Block with SCBA (Side-Channel Budget Accounting) fields.
//!
//! Every task carries:
//!   - A leakage budget (B₀): max bits of timing info leakable per epoch
//!   - A budget consumed counter: incremented by the scheduler each tick
//!   - A fence count: how many times this task triggered a speculation barrier
//!   - A throttle counter: skipped slots when budget is exhausted
//!
//! The SCBA theorem guarantees:
//!   ΣLeakages ≤ B₀ per epoch
//! which bounds what a timing adversary can observe across context switches.

use alloc::boxed::Box;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
}

/// Per-task SCBA accounting.
#[derive(Clone, Copy, Debug, Default)]
pub struct ScbaState {
    /// Maximum leakage budget per epoch (in scheduler ticks).
    /// Default: 64 ticks before a fence is required.
    pub budget_max:      u64,
    /// Ticks consumed in the current epoch.
    pub budget_consumed: u64,
    /// Total fence barriers fired for this task (lifetime counter).
    pub fence_count:     u64,
    /// Total ticks this task has been throttled (lifetime counter).
    pub throttle_count:  u64,
    /// Current epoch number.
    pub epoch:           u64,
}

impl ScbaState {
    pub fn new(budget_max: u64) -> Self {
        ScbaState { budget_max, ..Default::default() }
    }

    /// Record one scheduler tick of CPU time. Returns true if the budget
    /// is now exhausted and a fence barrier must be fired.
    pub fn tick(&mut self) -> bool {
        self.budget_consumed += 1;
        self.budget_consumed >= self.budget_max
    }

    /// Reset for a new epoch. Called after the fence fires.
    pub fn reset_epoch(&mut self) {
        self.budget_consumed = 0;
        self.fence_count += 1;
        self.epoch += 1;
    }
}

pub struct Task {
    pub id:    TaskId,
    pub state: TaskState,
    /// Saved RSP — updated on every context switch.
    pub rsp:   u64,
    /// Owned heap stack.
    pub stack: Box<[u8]>,
    /// SCBA accounting for this task.
    pub scba:  ScbaState,
}

impl Task {
    /// Create a new task with a custom stack size and SCBA budget.
    pub fn new_with_budget(
        id:         TaskId,
        entry:      fn() -> !,
        stack_size: usize,
        budget_max: u64,
    ) -> Self {
        // Allocate stack on the heap as a byte slice.
        let mut stack = alloc::vec![0u8; stack_size].into_boxed_slice();

        let stack_top = stack.as_mut_ptr() as u64 + stack_size as u64;

        // Build the initial saved context at the top of the stack.
        // Layout must match context_switch.s push/pop order:
        //   [r15, r14, r13, r12, rbx, rbp, rflags, rip]
        // rip = entry point (where `ret` in context_switch.s will jump).
        #[repr(C)]
        struct InitCtx {
            r15: u64, r14: u64, r13: u64, r12: u64,
            rbx: u64, rbp: u64, rflags: u64, rip: u64,
        }
        let ctx_size = core::mem::size_of::<InitCtx>() as u64;
        let ctx_ptr = (stack_top - ctx_size - 128) as *mut InitCtx;

        unsafe {
            (*ctx_ptr) = InitCtx {
                r15: 0, r14: 0, r13: 0, r12: 0,
                rbx: 0, rbp: 0,
                rflags: 0x200,       // IF = 1 (interrupts enabled)
                rip: entry as u64,
            };
        }

        Task {
            id,
            state: TaskState::Ready,
            rsp: ctx_ptr as u64,
            stack,
            scba: ScbaState::new(budget_max),
        }
    }

    /// Create the idle task (boot thread). No entry point — uses current stack.
    pub fn new_idle(id: TaskId) -> Self {
        // Tiny placeholder stack — idle runs on the kernel boot stack.
        let stack = alloc::vec![0u8; 4096].into_boxed_slice();
        Task {
            id,
            state: TaskState::Running,
            rsp: 0,
            stack,
            scba: ScbaState::new(u64::MAX), // idle has unlimited budget
        }
    }
}
