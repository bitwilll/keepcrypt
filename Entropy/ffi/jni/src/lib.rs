//! keepcrypt-jni: the Android JNI boundary, built as libkeepcrypt.so (Q53), and the workspace's
//! only unsafe code (tasks/todo.md, M5 group 10, as the re-plan's M5-21 and lead decisions M5-32
//! and M5-35 amend it). It defines two exports: `JNI_OnLoad`, and
//! `Java_com_keepcrypt_entropy_ffi_Native_call`, Kotlin's `Native.call(op: Int, input: ByteArray):
//! ByteArray`, the one call per boundary. The library also exports secp256k1-sys 0.10.1's own four
//! `#[no_mangle]` functions (`rustsecp256k1_v0_10_0_context_create`, `_context_destroy`,
//! `_default_error_callback_fn` and `_default_illegal_callback_fn`), which a cdylib keeps from its
//! dependencies; entropy-ci.yml's exports check allows those four by name and no other.
//!
//! - **The call** reads the input array into a Vec of exactly its length, under a size cap, and
//!   hands it to `keepcrypt_guard::guarded`, the one panic catch, which wipes it once the call is
//!   done. The reply, guarded's wiping buffer, is copied once into a new Java array and dropped,
//!   which wipes it.
//! - **Fail closed.** A negative op, a null or oversize array, a JNI function missing from the VM's
//!   table and an exception pending after any JNI call halt the slot, through `guarded` with an op
//!   the table does not hold (`HALT`). Nothing calls Throw and nothing is printed: a halt is the
//!   reply's status. Only a reply that cannot reach Java gives null; an exception then pending
//!   reaches Kotlin, whose crash path wipes and ends the process (Q57).
//! - **Lengths** cross through `TryFrom`, never `as`, and no secret byte is cast.
//! - **Unsafe code:** every block holds one operation and a SAFETY: comment.

use core::ffi::c_void;
use core::ptr;

use jni_sys::{
    JNI_FALSE, JNI_VERSION_1_6, JNIEnv, JNINativeInterface_, JavaVM, jbyte, jbyteArray, jclass,
    jint, jsize,
};

/// The longest input an op takes: Load registry snapshot's date, 4 bytes, then a snapshot of 2^22
/// entries, 122 + 18 x 2^22 bytes (docs/seal-watchonly-braille.md, "Snapshot format"): 75,497,598
/// bytes. A longer array is the shell's bug and halts before a byte is read.
const MAX_INPUT: usize = 4 + 122 + 18 * (1 << 22);

/// An op the table does not hold (its ops run from 1, keepcrypt-ffi's wire.rs), on which `guarded`
/// halts the slot (ffi_wire_malformed_inputs_halt): the halt of a call that cannot be read or
/// answered.
const HALT: u32 = 0;

/// A JNI step that failed: a function missing from the table, an exception pending, a null array
/// or a length out of range. The call halts.
#[derive(Debug, PartialEq, Eq)]
struct Failed;

/// At System.loadLibrary, before any session exists: the JNI version this library needs, and
/// nothing else (keepcrypt-guard sets the silent panic hook on its first call).
#[unsafe(no_mangle)]
pub extern "system" fn JNI_OnLoad(_vm: *mut JavaVM, _reserved: *mut c_void) -> jint {
    JNI_VERSION_1_6
}

/// Kotlin's `Native.call(op, input)`: `op` with `input` on the phone's slot, through the one catch,
/// and the reply's bytes, its status first (keepcrypt-ffi's wire.rs).
///
/// # Safety
///
/// The VM calls it as that native method: `env` is this call's JNIEnv and `input` a local reference
/// to a byte[] or null, and neither is used once the call returns.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_keepcrypt_entropy_ffi_Native_call(
    env: *mut JNIEnv,
    _class: jclass,
    op: jint,
    input: jbyteArray,
) -> jbyteArray {
    // SAFETY: env is this call's JNIEnv (the contract above), and jni does not outlive the call.
    let jni = unsafe { Jni::of(env) };
    let (op, input) = match &jni {
        Ok(jni) => jni.request(op, input),
        Err(Failed) => (HALT, Vec::new()),
    };
    let reply = keepcrypt_guard::guarded(op, input);
    match jni.and_then(|jni| jni.array_of(&reply)) {
        Ok(array) => array,
        Err(Failed) => halted(),
    }
}

/// Halts the slot, for a reply that cannot reach Java, and gives null.
fn halted() -> jbyteArray {
    keepcrypt_guard::guarded(HALT, Vec::new());
    ptr::null_mut()
}

/// The op, or `Failed` for a negative one: Kotlin's Int carries the table's u32 ops.
fn op_of(op: jint) -> Result<u32, Failed> {
    u32::try_from(op).map_err(|_| Failed)
}

/// The input's length, or `Failed` for a negative one or one past `MAX_INPUT`.
fn input_len(length: jsize) -> Result<usize, Failed> {
    let len = usize::try_from(length).map_err(|_| Failed)?;
    if len > MAX_INPUT {
        return Err(Failed);
    }
    Ok(len)
}

/// A length as Java's jsize, or `Failed` past what a Java array holds.
fn java_len(len: usize) -> Result<jsize, Failed> {
    jsize::try_from(len).map_err(|_| Failed)
}

/// This call's JNIEnv and the VM's function table behind it, both valid until the call returns.
/// Each JNI call below is made with no exception pending and followed by ExceptionCheck.
struct Jni<'call> {
    env: *mut JNIEnv,
    table: &'call JNINativeInterface_,
}

impl Jni<'_> {
    /// The JNIEnv and its table; `Failed` for a null pointer, which no VM passes.
    ///
    /// # Safety
    ///
    /// `env` is null or the JNIEnv the VM passed to this native call, and the result is used only
    /// during the call.
    unsafe fn of(env: *mut JNIEnv) -> Result<Self, Failed> {
        if env.is_null() {
            return Err(Failed);
        }
        // SAFETY: a non-null env is the call's JNIEnv (the contract above): a pointer to the VM's
        // function table pointer, readable during the call.
        let table = unsafe { *env };
        if table.is_null() {
            return Err(Failed);
        }
        // SAFETY: the VM's function table is non-null here, and outlives every native call.
        let table = unsafe { &*table };
        Ok(Jni { env, table })
    }

    /// What `guarded` gets: the op and the input as read, or `HALT` with whatever was read (for
    /// guarded to wipe) when the op is negative, the array null or longer than `MAX_INPUT`, or a
    /// JNI call fails.
    fn request(&self, op: jint, input: jbyteArray) -> (u32, Vec<u8>) {
        let Ok(op) = op_of(op) else {
            return (HALT, Vec::new());
        };
        if input.is_null() {
            return (HALT, Vec::new());
        }
        let Ok(len) = self.length(input).and_then(input_len) else {
            return (HALT, Vec::new());
        };
        let mut bytes = vec![0; len];
        match self.read(input, &mut bytes) {
            Ok(()) => (op, bytes),
            Err(Failed) => (HALT, bytes),
        }
    }

    /// `Failed` when an exception is pending (ExceptionCheck), or the table lacks the check.
    fn checked(&self) -> Result<(), Failed> {
        let exception_check = self.table.ExceptionCheck.ok_or(Failed)?;
        // SAFETY: env is this call's JNIEnv (Jni::of); ExceptionCheck is one of the JNI functions
        // that may be called with an exception pending.
        let pending = unsafe { exception_check(self.env) };
        if pending != JNI_FALSE {
            return Err(Failed);
        }
        Ok(())
    }

    /// The array's length (GetArrayLength).
    fn length(&self, array: jbyteArray) -> Result<jsize, Failed> {
        let get_array_length = self.table.GetArrayLength.ok_or(Failed)?;
        // SAFETY: env is this call's JNIEnv (Jni::of), with no exception pending, and array is a
        // non-null local reference to a byte[] (request checks null; Native.call's signature).
        let length = unsafe { get_array_length(self.env, array) };
        self.checked()?;
        Ok(length)
    }

    /// The whole array into `buf`, which is exactly its length (GetByteArrayRegion).
    fn read(&self, array: jbyteArray, buf: &mut [u8]) -> Result<(), Failed> {
        if buf.is_empty() {
            return Ok(());
        }
        let len = java_len(buf.len())?;
        let get_byte_array_region = self.table.GetByteArrayRegion.ok_or(Failed)?;
        // SAFETY: env is this call's JNIEnv, with no exception pending, and array the byte[] whose
        // length gave buf's; buf is valid for writes of len bytes, and jbyte (i8) and u8 share a
        // size and an alignment. A region out of range raises, which checked sees.
        unsafe { get_byte_array_region(self.env, array, 0, len, buf.as_mut_ptr().cast::<jbyte>()) };
        self.checked()
    }

    /// A new byte[] holding `bytes` (NewByteArray, then SetByteArrayRegion): the reply's one copy
    /// into Java. An exception still pending from the read fails it first.
    fn array_of(&self, bytes: &[u8]) -> Result<jbyteArray, Failed> {
        self.checked()?;
        let len = java_len(bytes.len())?;
        let new_byte_array = self.table.NewByteArray.ok_or(Failed)?;
        let set_byte_array_region = self.table.SetByteArrayRegion.ok_or(Failed)?;
        // SAFETY: env is this call's JNIEnv (Jni::of), with no exception pending (checked above).
        // Out of memory, it raises and gives null.
        let array = unsafe { new_byte_array(self.env, len) };
        self.checked()?;
        if array.is_null() {
            return Err(Failed);
        }
        if !bytes.is_empty() {
            // SAFETY: env as above, with no exception pending; array is the new byte[] of len
            // elements, and bytes is valid for reads of len bytes, jbyte (i8) and u8 sharing a
            // size and an alignment.
            unsafe {
                set_byte_array_region(self.env, array, 0, len, bytes.as_ptr().cast::<jbyte>())
            };
            self.checked()?;
        }
        Ok(array)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cap is the longest input, a full snapshot with its date: that passes, one byte more and
    /// a negative length fail (the call halts before reading).
    #[test]
    fn the_input_cap_is_a_full_snapshot_and_its_date() {
        assert_eq!(MAX_INPUT, 75_497_598);
        let cap = java_len(MAX_INPUT).expect("the cap fits a jsize");
        assert_eq!(input_len(cap), Ok(MAX_INPUT));
        assert_eq!(input_len(cap + 1), Err(Failed));
        assert_eq!(input_len(jsize::MAX), Err(Failed));
        assert_eq!(input_len(0), Ok(0));
        assert_eq!(input_len(1), Ok(1));
        assert_eq!(input_len(-1), Err(Failed));
        assert_eq!(input_len(jsize::MIN), Err(Failed));
    }

    /// A negative op fails (the call halts); every other Int is an op, which the table judges.
    #[test]
    fn a_negative_op_fails() {
        assert_eq!(op_of(0), Ok(0));
        assert_eq!(op_of(38), Ok(38));
        assert_eq!(op_of(jint::MAX), Ok(0x7fff_ffff));
        assert_eq!(op_of(-1), Err(Failed));
        assert_eq!(op_of(jint::MIN), Err(Failed));
        assert_eq!(HALT, 0, "no op of the table");
    }

    /// A reply longer than a Java array holds fails (the call halts).
    #[test]
    fn a_length_past_a_java_array_fails() {
        let most = usize::try_from(jsize::MAX).expect("a jsize fits a usize here");
        assert_eq!(java_len(0), Ok(0));
        assert_eq!(java_len(1), Ok(1));
        assert_eq!(java_len(most), Ok(jsize::MAX));
        assert_eq!(java_len(most + 1), Err(Failed));
        assert_eq!(java_len(usize::MAX), Err(Failed));
    }
}
