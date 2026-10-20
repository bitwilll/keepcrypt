//! keepcrypt-guard: the phone FFI's one panic catch (Q53, Q66). Its guarded(), M5 commit 12, runs
//! the safe layer, keepcrypt-ffi, under std::panic::catch_unwind: a panic has already dropped and
//! wiped the session when it halts. The workspace's only catch, in a crate with no unsafe code.
#![forbid(unsafe_code)]
