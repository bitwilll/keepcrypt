package com.keepcrypt.entropy.ffi

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * An input array past keepcrypt-jni's cap through the JNI method itself (lead decision M5-41): the
 * cap is the longest input an op takes, Load registry snapshot's date and a snapshot of 2^22
 * entries, 4 + 122 + 18 x 2^22 bytes. An input of exactly that size reaches the safe layer (a
 * snapshot of zeros, refused), and one byte more halts before a byte is read; every later call
 * halts. Its own process (forkEvery).
 */
class OversizeInputHaltTest {
    @Test
    fun anInputPastTheCapHaltsAndEveryLaterCallHalts() {
        val cap = 4 + 122 + 18 * (1 shl 22)
        val largest = ByteArray(cap)
        val today = M5_DAY
        largest[0] = (today ushr 24).toByte()
        largest[1] = (today ushr 16).toByte()
        largest[2] = (today ushr 8).toByte()
        largest[3] = today.toByte()
        val reply = Native.call(Wire.LOAD_SNAPSHOT, largest)
        assertEquals(Wire.REFUSED, reply[0].toInt(), "the largest input reaches the safe layer and is refused")
        assertContentEquals(byteArrayOf(Wire.HALTED.toByte()), Native.call(Wire.LOAD_SNAPSHOT, ByteArray(cap + 1)))
        assertFailsWith<KcHalt> { Core.selfTest() }
        assertFailsWith<KcHalt> { Core.wipeAll() }
    }
}
