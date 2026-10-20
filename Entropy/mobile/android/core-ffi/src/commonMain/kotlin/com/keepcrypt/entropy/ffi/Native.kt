package com.keepcrypt.entropy.ffi

/**
 * The one call into the Rust core (tasks/todo.md, M5 group 13 and the re-plan's "The shared Kotlin
 * API over the bridge"). A placeholder until commit 14 makes it the one expect object, with its two
 * actuals: over JNI and libkeepcrypt.so on Android, over the C bridge and libkeepcrypt_capi.a on
 * iPhone. Until then no native code of ours is loaded or called.
 */
internal object Native
