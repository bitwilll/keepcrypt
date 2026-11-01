package com.keepcrypt.entropy.ffi

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * A negative op through the JNI method itself (lead decision M5-41): keepcrypt-jni's op_of refuses
 * it, and the call halts the slot through keepcrypt_guard::guarded with an op the table does not
 * hold, so the fail-closed branch the host tests reach only through their fake VM runs once over a
 * real one. The halt status comes back as bytes (native code never throws), an internal halt's (M5
 * commit U3a), and every later call halts with that reason. Its own process (forkEvery).
 */
class NegativeOpHaltTest {
    @Test
    fun aNegativeOpHaltsAndEveryLaterCallHalts() {
        assertTrue(Core.selfTest() is Reply.Done, "a live slot first")
        val internal = byteArrayOf(Wire.HALTED.toByte(), HaltReason.Internal.code.toByte())
        assertContentEquals(internal, Native.call(-1, ByteArray(0)))
        assertEquals(HaltReason.Internal, assertFailsWith<KcHalt> { Core.selfTest() }.reason)
        assertFailsWith<KcHalt> { Core.start(Words.Twelve, Mode.DiceOnly) }
        assertFailsWith<KcHalt> { Core.wipeAll() }
        assertContentEquals(internal, Native.call(Int.MIN_VALUE, ByteArray(0)))
    }
}
