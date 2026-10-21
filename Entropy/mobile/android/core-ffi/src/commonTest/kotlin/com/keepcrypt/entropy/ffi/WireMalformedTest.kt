package com.keepcrypt.entropy.ffi

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith

/**
 * A reply that is not its layout halts (tasks/todo.md, M5 group 13; rule 3): read past its end, a
 * flag that is neither 0 nor 1, a byte left unread, a QR side no version has, a freshness byte past
 * 2, a refusal code the table does not hold. Each halts the slot (an op the table does not hold) and
 * throws KcHalt, and the halt latches: every later call halts too. Its own process (forkEvery),
 * since the slot stays halted.
 */
class WireMalformedTest {
    @Test
    fun aBodyThatIsNotItsLayoutHaltsAndTheHaltLatches() {
        assertFailsWith<KcHalt> { Body().u64(4).u32(20260301).reader().registry() }
        assertFailsWith<KcHalt> { Body().byte(0).byte(2).reader().readback() }
        assertFailsWith<KcHalt> { Body().byte(0).byte(1).byte(0).reader().also { it.readback() }.end() }
        assertFailsWith<KcHalt> { Body().byte(22).raw(ByteArray(61)).reader().qrMatrix() }
        assertFailsWith<KcHalt> { Body().byte(21).raw(ByteArray(55) + byteArrayOf(1)).reader().qrMatrix() }
        assertFailsWith<KcHalt> { Body().u64(1).u32(1).u32(1).byte(3).reader().registry() }
        assertFailsWith<KcHalt> { Body().raw(ByteArray(31)).reader().commitment() }
        assertFailsWith<KcHalt> { Refusal.of(4) }
        assertFailsWith<KcHalt> { Core.selfTest() }
        assertFailsWith<KcHalt> { Core.wipeAll() }
        assertContentEquals(byteArrayOf(Wire.HALTED.toByte()), Native.call(Wire.WIPE_ALL, ByteArray(0)))
    }
}
