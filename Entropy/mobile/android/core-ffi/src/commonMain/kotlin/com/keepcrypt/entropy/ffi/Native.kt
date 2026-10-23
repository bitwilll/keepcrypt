package com.keepcrypt.entropy.ffi

/**
 * The one call into the Rust core (tasks/todo.md, M5 group 13; the re-plan's "The shared Kotlin API
 * over the bridge" and lead decision M5-21): op with input on the process's one slot, and the
 * reply's bytes, its status byte first, as keepcrypt-ffi's wire.rs lays them out and Wire decodes
 * them. Native code never throws: a halt is the reply's status. Core makes every call through it.
 * The Android actual is the JNI method itself (lead decision M5-41); whether the iPhone gets an
 * actual is M6's question (Q73, lead decision M5-31).
 */
internal expect object Native {
    fun call(op: Int, input: ByteArray): ByteArray
}
