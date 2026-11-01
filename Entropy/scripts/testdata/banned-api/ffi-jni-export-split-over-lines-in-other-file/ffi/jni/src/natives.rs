pub extern "system"
fn native_raw(env: *mut JNIEnv, op: jint) -> jbyte {
    keepcrypt_ffi::dispatch(op as u32, &[])[0]
}
