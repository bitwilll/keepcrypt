package com.keepcrypt.entropy.ffi

/**
 * The JNI method itself (lead decision M5-41): keepcrypt-jni's
 * Java_com_keepcrypt_entropy_ffi_Native_call in libkeepcrypt.so, which System.loadLibrary loads,
 * running its JNI_OnLoad, the first time this object is used. The VM passes the object as the native
 * method's second argument, which the Rust export takes as its unused class. On the phone the
 * library is the APK's (scripts/android-rust.sh's, lead decision M5-9); in the JVM tests it is the
 * host build on java.library.path (core-ffi/build.gradle.kts).
 */
internal actual object Native {
    init {
        System.loadLibrary("keepcrypt")
    }

    actual external fun call(op: Int, input: ByteArray): ByteArray
}
