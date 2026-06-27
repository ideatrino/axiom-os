//! AXIOM security subsystems.
//!
//! This is where your original AXIOM design lives inside the kernel.
//! Right now it contains a self-contained, runnable demonstration of the
//! TEMPORAL CAPABILITY DECAY (TCD) model — the core AXIOM innovation —
//! so you can watch your security idea actually execute on the kernel.
//!
//! As you bring in your full v3/v4 modules (capability.rs with real
//! HMAC-SHA-256, scheduler.rs with SCBA, audit.rs with MEAL, etc.), add
//! them here as `pub mod ...;` and call them from `run_demo()`.

pub mod demo_crypto; // superseded by crate::crypto (Shot 5)
pub mod capability;

use crate::serial_println;

/// Run a short demonstration of the AXIOM capability system at boot.
/// This proves the security model is live on the kernel.
pub fn run_demo() {
    serial_println!("");
    serial_println!("===========================================");
    serial_println!(" AXIOM TCD — now with real HMAC-SHA-256 (RFC 2104)");
    serial_println!("===========================================");
    capability::demonstrate();
    serial_println!("===========================================");
    serial_println!("");
}
