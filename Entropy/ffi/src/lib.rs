//! keepcrypt-ffi: the phone FFI's safe layer over `keepcrypt-core` (M5). It holds every rule, in
//! safe code only; keepcrypt-guard runs it under the one panic catch, and keepcrypt-jni is the
//! Android boundary over that (tasks/todo.md, M5 groups 7-9).
#![forbid(unsafe_code)]
