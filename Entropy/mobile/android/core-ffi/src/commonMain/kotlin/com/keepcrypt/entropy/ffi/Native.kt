package com.keepcrypt.entropy.ffi

/**
 * The one call into the Rust core (tasks/todo.md, M5 group 13 and the re-plan's "The shared Kotlin
 * API over the bridge"). A placeholder until commit 14 makes it the one expect object, with its
 * Android actual over JNI and libkeepcrypt.so; whether the iPhone gets an actual is M6's question
 * (Q73, lead decision M5-31). Until then no native code of ours is loaded or called.
 */
internal object Native
