//! Minimal framebuffer support.
//!
//! The bootloader hands us a linear framebuffer (a big array of pixels).
//! Drawing actual TEXT to it requires a font renderer, which is a lot of
//! code. To keep this project reliable and focused, we do the simplest
//! useful thing: fill the screen with a solid colour so you can SEE that
//! the kernel reached this code and the framebuffer works.
//!
//! All real text output goes to the serial port (see serial.rs).
//!
//! Upgrading this to a real text console (with a bitmap font) is a great
//! "next step" project once the kernel boots.

use bootloader_api::info::{FrameBuffer, PixelFormat};

/// Fill the entire framebuffer with a single RGB colour.
///
/// `r`, `g`, `b` are 0–255. We handle the two common pixel formats the
/// bootloader might give us (RGB and BGR byte order).
pub fn fill_screen(framebuffer: &mut FrameBuffer, r: u8, g: u8, b: u8) {
    let info = framebuffer.info();
    let bytes_per_pixel = info.bytes_per_pixel;
    let buffer = framebuffer.buffer_mut();

    for chunk in buffer.chunks_exact_mut(bytes_per_pixel) {
        match info.pixel_format {
            PixelFormat::Rgb => {
                chunk[0] = r;
                chunk[1] = g;
                chunk[2] = b;
            }
            PixelFormat::Bgr => {
                chunk[0] = b;
                chunk[1] = g;
                chunk[2] = r;
            }
            // For unusual formats (e.g. U8 grayscale), just write intensity.
            _ => {
                let intensity = ((r as u16 + g as u16 + b as u16) / 3) as u8;
                for byte in chunk.iter_mut() {
                    *byte = intensity;
                }
            }
        }
    }
}
