package com.keepcrypt.entropy.ffi

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * A halt status with no code halts the slot (tasks/todo.md, M5 commit U3a3, the U-1 review): on a live
 * slot, Core.decode given HALTED alone throws KcHalt, internal, through Core.halt, so the slot halts as
 * internal and every later call halts with that reason. WireMalformedTest decodes it only after earlier
 * cases there have halted the slot, where a decode that threw without halting it would look the same.
 * Its own process (forkEvery), since the slot stays halted.
 */
class HaltStatusLengthTest {
    @Test
    fun aHaltStatusWithNoCodeHaltsALiveSlot() {
        assertTrue(Core.selfTest() is Reply.Done, "a live slot first")
        val halt = assertFailsWith<KcHalt> { Core.decode(byteArrayOf(Wire.HALTED.toByte())) { } }
        assertEquals(HaltReason.Internal, halt.reason)
        assertEquals(HaltReason.Internal, assertFailsWith<KcHalt> { Core.selfTest() }.reason, "the slot halted")
        assertContentEquals(byteArrayOf(Wire.HALTED.toByte(), HaltReason.Internal.code.toByte()), Native.call(Wire.WIPE_ALL, ByteArray(0)))
    }
}
