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
//! - **Tested on the host:** the five JNI functions a call uses sit behind the private `Env` trait,
//!   one JNI call per method, so the fail-closed rules over them (`request`, `answer` and `Env`'s
//!   provided methods) run in the unit tests over a fake VM. A fake function table would need
//!   extern fns of its own, which the gate keeps to the exports.

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
/// The VM calls it as that native method: `env` is this call's JNIEnv (or null, which no VM passes
/// and which halts) and `input` a local reference to a byte[] or null, and neither is used once the
/// call returns.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_keepcrypt_entropy_ffi_Native_call(
    env: *mut JNIEnv,
    _class: jclass,
    op: jint,
    input: jbyteArray,
) -> jbyteArray {
    // SAFETY: env is this call's JNIEnv or null (the contract above), and jni does not outlive the
    // call.
    let jni = unsafe { Jni::of(env) };
    let (op, input) = request(jni.as_ref(), op, input);
    let reply = keepcrypt_guard::guarded(op, input);
    answer(jni.as_ref(), &reply)
}

/// What `guarded` gets: the op and the input as read, or `HALT` with whatever was read (for
/// guarded to wipe) when there is no JNIEnv, the op is negative, the array null or longer than
/// `MAX_INPUT`, or a JNI call fails.
fn request(env: Option<&impl Env>, op: jint, input: jbyteArray) -> (u32, Vec<u8>) {
    let (Some(env), Ok(op)) = (env, op_of(op)) else {
        return (HALT, Vec::new());
    };
    if input.is_null() {
        return (HALT, Vec::new());
    }
    let Ok(len) = env.length(input).and_then(input_len) else {
        return (HALT, Vec::new());
    };
    let mut bytes = vec![0; len];
    match env.read(input, &mut bytes) {
        Ok(()) => (op, bytes),
        Err(Failed) => (HALT, bytes),
    }
}

/// The reply as a new byte[]; when it cannot reach Java (no JNIEnv, or a JNI call fails), the slot
/// halts and the call gives null.
fn answer(env: Option<&impl Env>, reply: &[u8]) -> jbyteArray {
    let Some(env) = env else {
        return halted();
    };
    match env.array_of(reply) {
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

/// This call's JNI functions: each required method makes one JNI call, `Failed` when the function
/// is missing from the VM's table, and the provided ones are the rules over them. Each JNI call is
/// made with no exception pending and followed by ExceptionCheck.
trait Env {
    /// ExceptionCheck: whether an exception is pending.
    fn exception_check(&self) -> Result<bool, Failed>;

    /// GetArrayLength of a non-null byte[].
    fn get_array_length(&self, array: jbyteArray) -> Result<jsize, Failed>;

    /// GetByteArrayRegion: the byte[] from index 0 into all of `buf`, which is no longer than it.
    fn get_byte_array_region(&self, array: jbyteArray, buf: &mut [u8]) -> Result<(), Failed>;

    /// NewByteArray of `len` elements; null, with an exception pending, when the VM is out of
    /// memory.
    fn new_byte_array(&self, len: jsize) -> Result<jbyteArray, Failed>;

    /// SetByteArrayRegion: all of `bytes` into the byte[] from index 0, which is no shorter.
    fn set_byte_array_region(&self, array: jbyteArray, bytes: &[u8]) -> Result<(), Failed>;

    /// `Failed` when an exception is pending, or the table lacks the check.
    fn checked(&self) -> Result<(), Failed> {
        if self.exception_check()? {
            return Err(Failed);
        }
        Ok(())
    }

    /// The array's length.
    fn length(&self, array: jbyteArray) -> Result<jsize, Failed> {
        let length = self.get_array_length(array)?;
        self.checked()?;
        Ok(length)
    }

    /// The whole array into `buf`, which is exactly its length.
    fn read(&self, array: jbyteArray, buf: &mut [u8]) -> Result<(), Failed> {
        if buf.is_empty() {
            return Ok(());
        }
        self.get_byte_array_region(array, buf)?;
        self.checked()
    }

    /// A new byte[] holding `bytes`: the reply's one copy into Java. An exception still pending
    /// from the read fails it first.
    fn array_of(&self, bytes: &[u8]) -> Result<jbyteArray, Failed> {
        self.checked()?;
        let array = self.new_byte_array(java_len(bytes.len())?)?;
        self.checked()?;
        if array.is_null() {
            return Err(Failed);
        }
        if !bytes.is_empty() {
            self.set_byte_array_region(array, bytes)?;
            self.checked()?;
        }
        Ok(array)
    }
}

/// This call's JNIEnv and the VM's function table behind it, both valid until the call returns.
struct Jni<'call> {
    env: *mut JNIEnv,
    table: &'call JNINativeInterface_,
}

impl Jni<'_> {
    /// The JNIEnv and its table; None for a null pointer, which no VM passes.
    ///
    /// # Safety
    ///
    /// `env` is null or the JNIEnv the VM passed to this native call, and the result is used only
    /// during the call.
    unsafe fn of(env: *mut JNIEnv) -> Option<Self> {
        if env.is_null() {
            return None;
        }
        // SAFETY: a non-null env is the call's JNIEnv (the contract above): a pointer to the VM's
        // function table pointer, readable during the call.
        let table = unsafe { *env };
        if table.is_null() {
            return None;
        }
        // SAFETY: the VM's function table is non-null here, and outlives every native call.
        let table = unsafe { &*table };
        Some(Jni { env, table })
    }
}

impl Env for Jni<'_> {
    fn exception_check(&self) -> Result<bool, Failed> {
        let exception_check = self.table.ExceptionCheck.ok_or(Failed)?;
        // SAFETY: env is this call's JNIEnv (Jni::of); ExceptionCheck is one of the JNI functions
        // that may be called with an exception pending.
        let pending = unsafe { exception_check(self.env) };
        Ok(pending != JNI_FALSE)
    }

    fn get_array_length(&self, array: jbyteArray) -> Result<jsize, Failed> {
        let get_array_length = self.table.GetArrayLength.ok_or(Failed)?;
        // SAFETY: env is this call's JNIEnv (Jni::of), with no exception pending (Env::length is
        // the one caller, after request's own checks), and array is a non-null local reference to
        // a byte[] (request checks null; Native.call's signature).
        Ok(unsafe { get_array_length(self.env, array) })
    }

    fn get_byte_array_region(&self, array: jbyteArray, buf: &mut [u8]) -> Result<(), Failed> {
        let len = java_len(buf.len())?;
        let get_byte_array_region = self.table.GetByteArrayRegion.ok_or(Failed)?;
        // SAFETY: env is this call's JNIEnv, with no exception pending (Env::read, after
        // Env::length's check), and array the byte[] whose length gave buf's; buf is valid for
        // writes of len bytes, and jbyte (i8) and u8 share a size and an alignment. A region out
        // of range raises, which checked sees.
        unsafe { get_byte_array_region(self.env, array, 0, len, buf.as_mut_ptr().cast::<jbyte>()) };
        Ok(())
    }

    fn new_byte_array(&self, len: jsize) -> Result<jbyteArray, Failed> {
        let new_byte_array = self.table.NewByteArray.ok_or(Failed)?;
        // SAFETY: env is this call's JNIEnv (Jni::of), with no exception pending (Env::array_of
        // checks first). Out of memory, it raises and gives null.
        Ok(unsafe { new_byte_array(self.env, len) })
    }

    fn set_byte_array_region(&self, array: jbyteArray, bytes: &[u8]) -> Result<(), Failed> {
        let len = java_len(bytes.len())?;
        let set_byte_array_region = self.table.SetByteArrayRegion.ok_or(Failed)?;
        // SAFETY: env as above, with no exception pending (Env::array_of checks after
        // NewByteArray); array is the new byte[] of len elements (Env::array_of made it for
        // bytes and checks null), and bytes is valid for reads of len bytes, jbyte (i8) and u8
        // sharing a size and an alignment.
        unsafe { set_byte_array_region(self.env, array, 0, len, bytes.as_ptr().cast::<jbyte>()) };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::cell::{Cell, RefCell};
    use std::env;
    use std::process::Command;

    use super::*;

    /// keepcrypt-ffi's wire.rs, which this crate cannot name (M5-35): Self test's op and Start's,
    /// the OK status, and the halt status of an internal halt (HALTED, then its code 4).
    const SELF_TEST: u32 = 1;
    const START: u32 = 2;
    const OK: u8 = 0;
    const HALTED_INTERNAL: [u8; 2] = [3, 4];

    /// The JNI calls a request makes, in order.
    const READ: [&str; 4] = [
        "GetArrayLength",
        "ExceptionCheck",
        "GetByteArrayRegion",
        "ExceptionCheck",
    ];
    /// The JNI calls a reply makes, in order.
    const WRITE: [&str; 5] = [
        "ExceptionCheck",
        "NewByteArray",
        "ExceptionCheck",
        "SetByteArrayRegion",
        "ExceptionCheck",
    ];

    /// A fake VM for one call: a byte[] of `length` elements whose bytes `array` holds, at most
    /// one JNI function that raises (an exception stays pending after it) and one missing from the
    /// table, and NewByteArray giving null or a new array, `made`. It logs every JNI call asked
    /// of it in order, and marks one asked with an exception pending, which JNI allows
    /// ExceptionCheck alone.
    struct Fake {
        length: jsize,
        array: Vec<u8>,
        raises: Option<&'static str>,
        missing: Option<&'static str>,
        no_array: bool,
        pending: Cell<bool>,
        calls: RefCell<Vec<String>>,
        made: RefCell<Vec<u8>>,
    }

    impl Fake {
        fn new(array: &[u8]) -> Self {
            Fake {
                length: java_len(array.len()).expect("a short array"),
                array: array.to_vec(),
                raises: None,
                missing: None,
                no_array: false,
                pending: Cell::new(false),
                calls: RefCell::new(Vec::new()),
                made: RefCell::new(Vec::new()),
            }
        }

        /// Logs a call of `name`: `Failed` when it is the missing function, and an exception
        /// pending after it when it is the one that raises.
        fn call(&self, name: &str) -> Result<(), Failed> {
            let mut entry = name.to_owned();
            if self.pending.get() && name != "ExceptionCheck" {
                entry.push_str(" with an exception pending");
            }
            self.calls.borrow_mut().push(entry);
            if self.missing == Some(name) {
                return Err(Failed);
            }
            if self.raises == Some(name) {
                self.pending.set(true);
            }
            Ok(())
        }

        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl Env for Fake {
        fn exception_check(&self) -> Result<bool, Failed> {
            self.call("ExceptionCheck")?;
            Ok(self.pending.get())
        }

        fn get_array_length(&self, _array: jbyteArray) -> Result<jsize, Failed> {
            self.call("GetArrayLength")?;
            Ok(self.length)
        }

        fn get_byte_array_region(&self, _array: jbyteArray, buf: &mut [u8]) -> Result<(), Failed> {
            self.call("GetByteArrayRegion")?;
            buf.copy_from_slice(&self.array[..buf.len()]);
            Ok(())
        }

        fn new_byte_array(&self, len: jsize) -> Result<jbyteArray, Failed> {
            self.call("NewByteArray")?;
            if self.no_array {
                return Ok(ptr::null_mut());
            }
            *self.made.borrow_mut() = vec![0; usize::try_from(len).expect("a length")];
            Ok(array())
        }

        fn set_byte_array_region(&self, _array: jbyteArray, bytes: &[u8]) -> Result<(), Failed> {
            self.call("SetByteArrayRegion")?;
            self.made.borrow_mut().copy_from_slice(bytes);
            Ok(())
        }
    }

    /// A non-null reference to a byte[], which no fake reads through.
    fn array() -> jbyteArray {
        ptr::dangling_mut()
    }

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

    /// A request reads the whole array, exactly its length, each JNI call checked, and passes the
    /// op on; an empty array is not read.
    #[test]
    fn a_request_reads_the_whole_array() {
        let vm = Fake::new(&[2, 12, 2]);
        assert_eq!(request(Some(&vm), 38, array()), (38, vec![2, 12, 2]));
        assert_eq!(vm.calls(), READ);
        let vm = Fake::new(&[]);
        assert_eq!(request(Some(&vm), 1, array()), (1, Vec::new()));
        assert_eq!(vm.calls(), &READ[..2]);
    }

    /// With no JNIEnv, a negative op or a null array, a request halts before any JNI call.
    #[test]
    fn a_request_halts_before_any_jni_call() {
        assert_eq!(request(None::<&Fake>, 1, array()), (HALT, Vec::new()));
        for (op, input) in [(-1, array()), (jint::MIN, array()), (1, ptr::null_mut())] {
            let vm = Fake::new(&[2]);
            assert_eq!(request(Some(&vm), op, input), (HALT, Vec::new()), "op {op}");
            assert!(vm.calls().is_empty(), "op {op}");
        }
    }

    /// An array longer than the cap, or a negative length, halts the request before anything is
    /// allocated or read.
    #[test]
    fn a_request_past_the_cap_halts_before_reading() {
        let cap = java_len(MAX_INPUT).expect("the cap fits a jsize");
        for length in [cap + 1, jsize::MAX, -1, jsize::MIN] {
            let vm = Fake {
                length,
                ..Fake::new(&[])
            };
            assert_eq!(request(Some(&vm), 37, array()), (HALT, Vec::new()));
            assert_eq!(vm.calls(), &READ[..2], "length {length}");
        }
    }

    /// A JNI call that raises halts the request, and only the check follows it: GetArrayLength
    /// (on an empty array too, where no read comes after to see it), and GetByteArrayRegion, which
    /// halts with what was read, for guarded to wipe. So does a function missing from the table,
    /// with nothing called after it.
    #[test]
    fn a_request_halts_when_a_jni_call_fails() {
        for bytes in [&[2, 12, 2][..], &[]] {
            let vm = Fake {
                raises: Some("GetArrayLength"),
                ..Fake::new(bytes)
            };
            assert_eq!(request(Some(&vm), 38, array()), (HALT, Vec::new()));
            assert_eq!(vm.calls(), &READ[..2]);
        }
        let vm = Fake {
            raises: Some("GetByteArrayRegion"),
            ..Fake::new(&[2, 12, 2])
        };
        assert_eq!(request(Some(&vm), 38, array()), (HALT, vec![2, 12, 2]));
        assert_eq!(vm.calls(), READ);
        for (missing, read, calls) in [
            ("GetArrayLength", Vec::new(), 1),
            ("ExceptionCheck", Vec::new(), 2),
            ("GetByteArrayRegion", vec![0; 3], 3),
        ] {
            let vm = Fake {
                missing: Some(missing),
                ..Fake::new(&[2, 12, 2])
            };
            assert_eq!(request(Some(&vm), 38, array()), (HALT, read), "{missing}");
            assert_eq!(vm.calls(), &READ[..calls], "{missing}");
        }
    }

    /// A reply reaches Java as one new byte[] holding it, each JNI call checked. A reply is never
    /// empty (its status comes first), but an empty one would make no copy.
    #[test]
    fn a_reply_reaches_java_as_one_new_array() {
        let vm = Fake::new(&[]);
        assert_eq!(vm.array_of(&[OK, 7, 9]), Ok(array()));
        assert_eq!(*vm.made.borrow(), [OK, 7, 9]);
        assert_eq!(vm.calls(), WRITE);
        let vm = Fake::new(&[]);
        assert_eq!(vm.array_of(&[]), Ok(array()));
        assert_eq!(vm.calls(), &WRITE[..3]);
    }

    /// A reply that cannot reach Java fails, with only the check after a JNI call that raised: an
    /// exception still pending from the read, NewByteArray or SetByteArrayRegion raising,
    /// NewByteArray giving null, and a function missing from the table.
    #[test]
    fn a_reply_fails_when_a_jni_call_fails() {
        let vm = Fake::new(&[]);
        vm.pending.set(true);
        assert_eq!(vm.array_of(&[OK]), Err(Failed));
        assert_eq!(vm.calls(), &WRITE[..1]);
        for (raises, calls) in [("NewByteArray", 3), ("SetByteArrayRegion", 5)] {
            let vm = Fake {
                raises: Some(raises),
                ..Fake::new(&[])
            };
            assert_eq!(vm.array_of(&[OK]), Err(Failed), "{raises}");
            assert_eq!(vm.calls(), &WRITE[..calls], "{raises}");
        }
        let vm = Fake {
            no_array: true,
            ..Fake::new(&[])
        };
        assert_eq!(vm.array_of(&[OK]), Err(Failed));
        assert_eq!(vm.calls(), &WRITE[..3]);
        for (missing, calls) in [
            ("ExceptionCheck", 1),
            ("NewByteArray", 2),
            ("SetByteArrayRegion", 4),
        ] {
            let vm = Fake {
                missing: Some(missing),
                ..Fake::new(&[])
            };
            assert_eq!(vm.array_of(&[OK]), Err(Failed), "{missing}");
            assert_eq!(vm.calls(), &WRITE[..calls], "{missing}");
        }
    }

    /// Set for the child process alone, to the case it runs on the process's fresh slot.
    const CHILD: &str = "KC_JNI_HALT_CHILD";
    /// The cases' test, by its full name.
    const CASES: &str = "tests::case_on_a_fresh_slot";

    /// One call through the catch, and its reply's bytes.
    fn guarded(op: u32, bytes: &[u8]) -> Vec<u8> {
        keepcrypt_guard::guarded(op, bytes.to_vec()).to_vec()
    }

    /// A call that cannot answer, on a fresh slot that Self test shows live: the export with no
    /// JNIEnv; the export over a VM whose table holds no function, so Jni's own missing-function
    /// branches run; and a reply that cannot reach Java. Each gives null and halts the slot, as
    /// internal, so every later call gives that halt status. It runs only in the child processes
    /// the test below starts, since the slot is the process's one.
    #[test]
    fn case_on_a_fresh_slot() {
        let Some(case) = env::var_os(CHILD) else {
            return;
        };
        assert_eq!(guarded(SELF_TEST, &[]), [OK], "the slot is live");
        let reply = match case.to_str() {
            Some("no-env") => {
                // SAFETY: a null env, which the export's contract allows (Jni::of refuses it), and
                // a null array; nothing is read through either.
                unsafe {
                    Java_com_keepcrypt_entropy_ffi_Native_call(
                        ptr::null_mut(),
                        ptr::null_mut(),
                        1,
                        ptr::null_mut(),
                    )
                }
            }
            Some("empty-table") => {
                // SAFETY: every field of JNINativeInterface_ is a raw pointer or an Option of a
                // function pointer, for which all-zero bytes are null and None.
                let table: JNINativeInterface_ = unsafe { core::mem::zeroed() };
                let mut functions: JNIEnv = &table;
                // SAFETY: env points to a function table pointer, and the table outlives the call;
                // the table holds no function, so nothing is called through it or reads the array.
                unsafe {
                    Java_com_keepcrypt_entropy_ffi_Native_call(
                        &mut functions,
                        ptr::null_mut(),
                        1,
                        array(),
                    )
                }
            }
            Some("reply-lost") => {
                let vm = Fake {
                    no_array: true,
                    ..Fake::new(&[])
                };
                answer(Some(&vm), &[OK])
            }
            _ => panic!("an unknown case"),
        };
        assert!(reply.is_null(), "null");
        assert_eq!(guarded(SELF_TEST, &[]), HALTED_INTERNAL, "halted");
        assert_eq!(guarded(START, &[12, 2]), HALTED_INTERNAL, "halted for good");
    }

    /// Runs each case above in a child process of its own, on its own fresh slot: each passes.
    #[test]
    fn a_call_that_cannot_answer_gives_null_and_halts_the_slot() {
        for case in ["no-env", "empty-table", "reply-lost"] {
            let output = Command::new(env::current_exe().expect("the test binary"))
                .args([CASES, "--exact"])
                .env(CHILD, case)
                .output()
                .expect("the child runs");
            let stdout = String::from_utf8(output.stdout).expect("text");
            assert!(output.status.success(), "{case} fails:\n{stdout}");
            assert!(stdout.contains("running 1 test\n"), "{case} ran");
        }
    }
}
