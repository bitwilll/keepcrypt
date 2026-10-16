//! Auto-trait assertions (tasks/todo.md, M4 group 3), compile-time only: this target holds no
//! test, and it fails to build if a type below loses `Send` or `Sync`. A session is one
//! `Box<Inner>` plus an uninhabited state marker, so a field added to `Inner` that is not `Send`
//! (an `Rc`, a raw pointer) or not `Sync` (a `Cell`) fails here first.
//!
//! - `Send` for the session in all six states, `Wiped`, `VerifiedSnapshot`, `CheckedBackup`,
//!   `BackupFile` and `CoreError`: a worker thread would move them to it and back. The Pi has none
//!   (M4 Q39 (b): with one core it would be no faster), and it is revisited only if a wait exceeds
//!   60 seconds.
//! - `Sync` for the session in all six states: a scoped worker thread would borrow it.
//! - Both for M5 and M6: UniFFI requires every object Kotlin or Swift holds to be `Send + Sync`,
//!   since either may call it from any thread, and the FFI's objects will hold these values.

use keepcrypt_core::{
    BackupFile, CheckedBackup, Checking, Collecting, Committed, CoreError, Ready, Rolling, Sealed,
    Session, VerifiedSnapshot, Wiped,
};

const fn send<T: Send>() {}
const fn sync<T: Sync>() {}

const _: () = {
    send::<Session<Collecting>>();
    send::<Session<Committed>>();
    send::<Session<Rolling>>();
    send::<Session<Sealed>>();
    send::<Session<Checking>>();
    send::<Session<Ready>>();
    send::<Wiped>();
    send::<VerifiedSnapshot>();
    send::<CheckedBackup>();
    send::<BackupFile>();
    send::<CoreError>();

    sync::<Session<Collecting>>();
    sync::<Session<Committed>>();
    sync::<Session<Rolling>>();
    sync::<Session<Sealed>>();
    sync::<Session<Checking>>();
    sync::<Session<Ready>>();
};
