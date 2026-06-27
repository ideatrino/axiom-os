//! Serial port output (UART 16550, COM1 at port 0x3F8).
//!
//! This is our PRIMARY text output channel during development. When you run
//! the kernel with QEMU's `-serial stdio` flag, everything we print here
//! appears directly in your terminal — which is far easier to read and
//! copy/paste than text drawn on the emulated screen.
//!
//! Usage anywhere in the kernel:
//! ```
//! serial_println!("hello {}", 42);
//! ```

use core::fmt::Write;
use lazy_static::lazy_static;
use spin::Mutex;
use uart_16550::SerialPort;

lazy_static! {
    /// The global COM1 serial port, behind a spinlock so it's safe to use
    /// from anywhere (including, carefully, interrupt handlers).
    pub static ref SERIAL1: Mutex<SerialPort> = {
        // 0x3F8 is the standard I/O port address of COM1 on a PC.
        let mut serial_port = unsafe { SerialPort::new(0x3F8) };
        serial_port.init();
        Mutex::new(serial_port)
    };
}

/// Internal: used by the macros below. Don't call directly.
#[doc(hidden)]
pub fn _print(args: core::fmt::Arguments) {
    use x86_64::instructions::interrupts;
    // Disable interrupts while we hold the serial lock, so a timer interrupt
    // can't fire mid-print, try to print too, and deadlock on the same lock.
    interrupts::without_interrupts(|| {
        SERIAL1
            .lock()
            .write_fmt(args)
            .expect("printing to serial failed");
    });
}

/// Print to the serial port (no newline).
#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => {
        $crate::serial::_print(format_args!($($arg)*))
    };
}

/// Print to the serial port, with a trailing newline.
#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($fmt:expr) => ($crate::serial_print!(concat!($fmt, "\n")));
    ($fmt:expr, $($arg:tt)*) => {
        $crate::serial_print!(concat!($fmt, "\n"), $($arg)*)
    };
}
