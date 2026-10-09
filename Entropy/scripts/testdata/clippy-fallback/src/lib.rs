//! Gate canary for the fail-closed and no-print clippy rules; see Cargo.toml.
//! One call to each method core/clippy.toml bans. Each call carries a `// bans:` comment that
//! scripts/canaries.sh reads: every path named there, and every path in core/clippy.toml, must
//! be reported as a disallowed method, so a deleted, typo'd or unexercised entry turns CI red.

type R = Result<u8, u8>;
type O = Option<u8>;

fn four() -> u8 {
    4
}

fn some_four() -> O {
    Some(4)
}

fn ok_four(_: u8) -> R {
    Ok(4)
}

pub fn result_unwrap_or(r: R) -> u8 {
    r.unwrap_or(0) // bans: core::result::Result::unwrap_or
}

pub fn result_unwrap_or_default(r: R) -> u8 {
    r.unwrap_or_default() // bans: core::result::Result::unwrap_or_default
}

pub fn result_unwrap_or_else(r: R) -> u8 {
    r.unwrap_or_else(|e| e) // bans: core::result::Result::unwrap_or_else
}

pub fn result_map_or(r: R) -> u8 {
    r.map_or(0, |v| v ^ 1) // bans: core::result::Result::map_or
}

pub fn result_map_or_else(r: R) -> u8 {
    r.map_or_else(|e| e, |v| v ^ 1) // bans: core::result::Result::map_or_else
}

pub fn result_ok(r: R) -> O {
    r.ok() // bans: core::result::Result::ok
}

pub fn result_err(r: R) -> O {
    r.err() // bans: core::result::Result::err
}

pub fn result_or(r: R, fallback: R) -> R {
    r.or(fallback) // bans: core::result::Result::or
}

pub fn result_or_else(r: R) -> R {
    r.or_else(ok_four) // bans: core::result::Result::or_else
}

pub fn option_unwrap_or(o: O) -> u8 {
    o.unwrap_or(0) // bans: core::option::Option::unwrap_or
}

pub fn option_unwrap_or_default(o: O) -> u8 {
    o.unwrap_or_default() // bans: core::option::Option::unwrap_or_default
}

pub fn option_unwrap_or_else(o: O) -> u8 {
    o.unwrap_or_else(four) // bans: core::option::Option::unwrap_or_else
}

pub fn option_map_or(o: O) -> u8 {
    o.map_or(0, |v| v ^ 1) // bans: core::option::Option::map_or
}

pub fn option_map_or_else(o: O) -> u8 {
    o.map_or_else(four, |v| v ^ 1) // bans: core::option::Option::map_or_else
}

pub fn option_or(o: O, fallback: O) -> O {
    o.or(fallback) // bans: core::option::Option::or
}

pub fn option_or_else(o: O) -> O {
    o.or_else(some_four) // bans: core::option::Option::or_else
}

// Through std, as code spells it: the ban names core::mem::forget, which std re-exports. A
// non-Copy value, so that rustc's forgetting_copy_types lint does not fire as well.
pub fn forget(r: Result<u8, String>) {
    std::mem::forget(r) // bans: core::mem::forget
}

pub fn catch(f: fn()) -> bool {
    std::panic::catch_unwind(f).is_err() // bans: std::panic::catch_unwind
}

pub fn stdout() -> std::io::Stdout {
    std::io::stdout() // bans: std::io::stdout
}

pub fn stderr() -> std::io::Stderr {
    std::io::stderr() // bans: std::io::stderr
}
