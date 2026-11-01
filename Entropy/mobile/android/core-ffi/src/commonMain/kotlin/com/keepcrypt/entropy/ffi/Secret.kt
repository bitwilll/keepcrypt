package com.keepcrypt.entropy.ffi

/**
 * Secret bytes on the Kotlin side (tasks/todo.md, M5 group 13; Q58; rule 5): a byte array this
 * object owns from the moment it is made (the caller hands the array over and keeps no other use of
 * it), zeroed by wipe() when its page or screen leaves. No toString shows its content and equals is
 * identity, so nothing of it reaches a log, a message or a comparison by accident; its bytes are read
 * one at a time, and every copy Core makes of them for a call is zeroed once the call returns.
 */
class Secret(private val bytes: ByteArray) {
    /** How many bytes it holds. */
    val size: Int get() = bytes.size

    /** The byte at index. */
    operator fun get(index: Int): Byte = bytes[index]

    /** Zeroes every byte. */
    fun wipe() {
        bytes.fill(0)
    }

    override fun toString(): String = "Secret"

    /** The byte at index as 0-255. */
    internal fun u8(index: Int): Int = bytes[index].toInt() and 0xFF

    /** Its bytes copied into destination from at. */
    internal fun copyInto(destination: ByteArray, at: Int) {
        bytes.copyInto(destination, at)
    }

    /** length of its bytes from from, as a Secret of their own (a copy its owner wipes). */
    internal fun slice(from: Int, length: Int): Secret = Secret(bytes.copyOfRange(from, from + length))
}
