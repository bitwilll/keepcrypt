//! keepcrypt-jni: the JNI boundary. Its exports call keepcrypt_guard::guarded(), which holds the one
//! catch_unwind, so this file holds none.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_keepcrypt_entropy_ffi_Native_call(env: *mut JNIEnv, op: jint, input: jbyteArray) -> jbyteArray {
    to_java(env, keepcrypt_guard::guarded(op as u32, from_java(env, input)))
}
#[unsafe(no_mangle)]
pub unsafe extern "system" fn JNI_OnLoad(vm: *mut JavaVM, reserved: *mut c_void) -> jint {
    JNI_VERSION_1_6
}
