//! Static ring-buffer log — zero-stack-depth writes from any task or ISR.

use core::sync::atomic::{AtomicU64, Ordering};

pub const LOG_CAPACITY: usize = 64;

#[derive(Clone, Copy)]
pub struct LogEntry {
    pub kind: LogKind,
    pub a:    u64,
    pub b:    u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LogKind {
    Empty      = 0,
    ScbaStatus = 1,
}

/// Wrapper so we can put LogEntry in a static.
/// Safety: access is serialised by the atomic WRITE_HEAD bump —
/// no two callers ever get the same slot index simultaneously.
struct SyncEntry(core::cell::UnsafeCell<LogEntry>);
unsafe impl Sync for SyncEntry {}

static ENTRIES: [SyncEntry; LOG_CAPACITY] = {
    const EMPTY: SyncEntry = SyncEntry(core::cell::UnsafeCell::new(
        LogEntry { kind: LogKind::Empty, a: 0, b: 0 }
    ));
    [EMPTY; LOG_CAPACITY]
};

static WRITE_HEAD: AtomicU64 = AtomicU64::new(0);
static READ_HEAD:  AtomicU64 = AtomicU64::new(0);

/// Push an entry. Safe from interrupt context.
pub fn push(entry: LogEntry) {
    let idx = WRITE_HEAD.fetch_add(1, Ordering::Relaxed) as usize % LOG_CAPACITY;
    unsafe { *ENTRIES[idx].0.get() = entry; }
}

/// Drain up to `max` entries, calling `f` for each. Returns count drained.
pub fn drain(max: usize, mut f: impl FnMut(LogEntry)) -> usize {
    let mut count = 0;
    while count < max {
        let r = READ_HEAD.load(Ordering::Relaxed);
        let w = WRITE_HEAD.load(Ordering::Relaxed);
        if r >= w { break; }
        let idx = r as usize % LOG_CAPACITY;
        let entry = unsafe { *ENTRIES[idx].0.get() };
        if entry.kind == LogKind::Empty { break; }
        f(entry);
        READ_HEAD.fetch_add(1, Ordering::Relaxed);
        count += 1;
    }
    count
}
