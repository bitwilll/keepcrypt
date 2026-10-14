//! keepcrypt-pi binary: the only process the Pi image starts (M3, M4).

#![forbid(unsafe_code)]

// The device drivers (tasks/todo.md, M4 group 10): their pure parts on every host, for
// `cargo test`, and on Linux the glue that runs them on the Pi (`device::run`).
#[cfg(any(target_os = "linux", test))]
mod device;

/// The firmware (Q35): `keepcrypt-pi` runs the ceremony and `keepcrypt-pi --stopped` shows the stop
/// screen; neither returns.
#[cfg(target_os = "linux")]
fn main() {
    device::run()
}

/// Off the Pi the binary does nothing; its tests cover the device module's pure parts.
#[cfg(not(target_os = "linux"))]
fn main() {}
