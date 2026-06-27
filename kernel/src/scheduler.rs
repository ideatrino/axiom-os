//! AXIOM SCBA Scheduler — Side-Channel Budget Accounting.
//!
//! On every timer tick:
//!   1. Tick the current task's budget counter.
//!   2. If exhausted: fire LFENCE+MFENCE (speculation barrier), reset epoch.
//!   3. Find next Ready task (round-robin), switch to it.
//!
//! The SCBA theorem: ΣLeakages ≤ B₀ per epoch.
//! The fence serialises speculative operations, bounding the timing channel.

use crate::task::{Task, TaskState};
use alloc::vec::Vec;
use spin::Mutex;

extern "C" {
    fn context_switch(old_rsp: *mut u64, new_rsp: u64);
}

pub struct ScbaStats {
    pub total_fences:   u64,
    pub total_switches: u64,
}

pub static SCHEDULER: Mutex<Scheduler> = Mutex::new(Scheduler::new());

pub struct Scheduler {
    pub tasks:   Vec<Task>,
    pub current: usize,
    pub stats:   ScbaStats,
}

impl Scheduler {
    pub const fn new() -> Self {
        Scheduler {
            tasks:   Vec::new(),
            current: 0,
            stats:   ScbaStats { total_fences: 0, total_switches: 0 },
        }
    }

    pub fn add_task(&mut self, task: Task) { self.tasks.push(task); }
    pub fn task_count(&self) -> usize { self.tasks.len() }

    /// Phase 1: hold lock, do SCBA accounting, find next task, drop lock.
    /// Returns (old_rsp_ptr, new_rsp, need_fence) as plain usizes.
    pub fn prepare_switch(&mut self) -> Option<(usize, usize, bool)> {
        if self.tasks.len() < 2 { return None; }

        let old_idx = self.current;
        let mut need_fence = false;

        // Tick the current task's SCBA budget.
        let exhausted = self.tasks[old_idx].scba.tick();
        if exhausted {
            self.tasks[old_idx].scba.reset_epoch();
            self.stats.total_fences += 1;
            need_fence = true;
        }
        self.tasks[old_idx].state = TaskState::Ready;

        // Round-robin: find next Ready task.
        let mut next_idx = (old_idx + 1) % self.tasks.len();
        let start = next_idx;
        loop {
            if self.tasks[next_idx].state == TaskState::Ready { break; }
            next_idx = (next_idx + 1) % self.tasks.len();
            if next_idx == start { return None; } // no other ready task
        }
        if next_idx == old_idx { return None; }

        self.tasks[next_idx].state = TaskState::Running;
        self.current = next_idx;
        self.stats.total_switches += 1;

        let old_rsp_ptr = (&mut self.tasks[old_idx].rsp) as *mut u64 as usize;
        let new_rsp     = self.tasks[next_idx].rsp as usize;
        Some((old_rsp_ptr, new_rsp, need_fence))
    }

    /// Snapshot of per-task SCBA stats for the logger (skips idle at [0]).
    pub fn scba_snapshot(&self) -> [(u64, u64, u64); 3] {
        let mut out = [(0u64, 0u64, 0u64); 3];
        for (i, slot) in out.iter_mut().enumerate() {
            if i + 1 < self.tasks.len() {
                let t = &self.tasks[i + 1];
                *slot = (t.scba.budget_consumed, t.scba.fence_count, t.scba.epoch);
            }
        }
        out
    }
}

/// Phase 2: fire fence if needed, then switch. Lock MUST be free.
pub unsafe fn perform_switch(old_rsp_ptr: usize, new_rsp: usize, need_fence: bool) {
    if need_fence {
        // Speculation barrier — the heart of SCBA.
        // LFENCE: drain load buffer (stops speculative reads).
        // MFENCE: drain store buffer (serialise memory operations).
        // Together they bound timing channel leakage to B₀ ticks per epoch.
        unsafe {
            core::arch::asm!(
                "lfence",
                "mfence",
                options(nostack, nomem, preserves_flags),
            );
        }
    }
    unsafe { context_switch(old_rsp_ptr as *mut u64, new_rsp as u64); }
}
