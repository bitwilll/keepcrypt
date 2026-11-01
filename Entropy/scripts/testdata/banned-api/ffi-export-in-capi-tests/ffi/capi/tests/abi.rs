// A test file is no exception: an export anywhere under ffi/ but ffi/jni/src/lib.rs is a hit.
#[unsafe(no_mangle)] pub extern "C" fn kc_test_hook() -> u8 { 0 }
