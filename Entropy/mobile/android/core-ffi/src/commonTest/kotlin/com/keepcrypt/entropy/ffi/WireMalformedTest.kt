package com.keepcrypt.entropy.ffi

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * A reply that is not its layout halts (tasks/todo.md, M5 group 13; rule 3): read past its end, a
 * flag that is neither 0 nor 1, a byte left unread, a QR side no version has, a freshness byte past
 * 2, a refusal code the table does not hold; and Core.decode's own status checks: no status byte,
 * a refusal with no code or a byte after it, a discard with a byte after it, a status wire.rs does
 * not define. Each halts the slot (an op the table does not hold) and throws KcHalt, and the halt
 * latches: every later call halts too. What a decode copied out before the reply proved malformed
 * is zeroed with it (rule 5): a word page read whole before a byte left unread, a confirm choice
 * before a read past the end. Its own process (forkEvery), since the slot stays halted.
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
        for (reply in listOf(byteArrayOf(), byteArrayOf(1), byteArrayOf(1, 2, 0), byteArrayOf(2, 0), byteArrayOf(7))) {
            assertFailsWith<KcHalt>(reply.contentToString()) { Core.decode(reply) { } }
        }
        val pageReader = Body().byte(1).byte(12).byte(1).byte(1).byte(1).u16(1).text("abandon").raw(ByteArray(20)).byte(0).reader()
        val page = pageReader.wordPage()
        assertEquals(listOf(1, 12, 1, 7), listOf(page.position, page.count, page.seedbook, page.word().size))
        assertFailsWith<KcHalt> { pageReader.end() }
        assertEquals(listOf(0, 0, 0, 0), listOf(page.position, page.count, page.seedbook, page.word().size), "the page zeroed")
        val choiceReader = Body().text("fly").byte(4).reader()
        val choice = choiceReader.secretText()
        assertEquals("fly", asciiOf(choice))
        assertFailsWith<KcHalt> { choiceReader.text() }
        assertTrue((0 until choice.size).all { choice[it] == 0.toByte() }, "the choice zeroed")
        assertFailsWith<KcHalt> { Core.selfTest() }
        assertFailsWith<KcHalt> { Core.wipeAll() }
        assertContentEquals(byteArrayOf(Wire.HALTED.toByte()), Native.call(Wire.WIPE_ALL, ByteArray(0)))
    }
}
