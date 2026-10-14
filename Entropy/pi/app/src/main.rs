//! keepcrypt-pi binary: the only process the Pi image starts (M3, M4).

#![forbid(unsafe_code)]

// The device drivers (tasks/todo.md, M4 group 10): their pure parts, tested on every host, until
// the Linux glue that runs them on the Pi arrives.
#[cfg(test)]
mod device;

fn main() {}
