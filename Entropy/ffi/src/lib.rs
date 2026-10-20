//! keepcrypt-ffi: the phone FFI's safe layer over `keepcrypt-core` (M5). It holds every rule, in
//! safe code only; keepcrypt-guard runs it under the one panic catch, and keepcrypt-jni is the
//! Android boundary over that (tasks/todo.md, M5 groups 7-9).
//!
//! The phone's one ceremony and every call on it are in `ceremony`; the op table and the reply's
//! bytes, and `dispatch` and `halt`, the two entries keepcrypt-guard calls, are in `wire`. This file
//! holds the module list and those two re-exports only.
#![forbid(unsafe_code)]

pub mod ceremony;
pub mod wire;

pub use wire::{dispatch, halt};
