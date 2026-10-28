package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Secret
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The pads (tasks/todo.md, M5 group 14): each one's keys in their fixed order, its capacity, and its
 * entry, which holds only its own keys, zeroes what it drops (read through its internal check) and
 * hands over a Secret of exactly what was typed, wiped once the call it was handed to returns or throws.
 */
class PadsTest {
    /** The entry's bytes as text, through its Secret (and the Secret wiped after). */
    private fun taken(entry: PadEntry): String {
        val secret = entry.take()
        val text = buildString {
            for (index in 0 until secret.size) append(Char(secret[index].toInt()))
        }
        secret.wipe()
        return text
    }

    @Test
    fun eachPadHasItsKeysInTheirFixedOrder() {
        assertEquals("123456", DICE_KEYS)
        assertEquals(26, LETTER_KEYS.length)
        for (index in LETTER_KEYS.indices) assertEquals('a' + index, LETTER_KEYS[index])
        // Crockford base32: the digits, then A-Z without I, L, O and U.
        assertEquals(32, CROCKFORD_KEYS.length)
        assertEquals("0123456789", CROCKFORD_KEYS.substring(0, 10))
        var expected = 'A'
        for (key in CROCKFORD_KEYS.substring(10)) {
            while (expected in "ILOU") expected += 1
            assertEquals(expected, key)
            expected += 1
        }
        // Printable ASCII, 0x20 to 0x7E, once each in code order, in three pages of 32, 32 and 31.
        assertEquals(95, ASCII_KEYS.length)
        for (index in ASCII_KEYS.indices) assertEquals(0x20 + index, ASCII_KEYS[index].code)
        assertEquals(listOf(32, 32, 31), (0 until ASCII_PAGES).map { asciiPage(it).length })
        assertEquals(ASCII_KEYS, (0 until ASCII_PAGES).joinToString("") { asciiPage(it) })
        assertEquals(' ', asciiPage(0)[0])
        assertEquals('~', asciiPage(2).last())
        assertFailsWith<IllegalStateException> { asciiPage(3) }
        assertEquals("space", keyLabel(' '))
        assertEquals("a", keyLabel('a'))
    }

    @Test
    fun eachPadTakesItsOwnCapacity() {
        assertEquals(1, dicePadEntry().capacity)
        assertEquals(4, letterPadEntry().capacity)
        assertEquals(8, crockfordPadEntry().capacity)
        assertEquals(100, asciiPadEntry().capacity)
        val entry = crockfordPadEntry()
        for (key in "CF94BCAJ") assertTrue(entry.type(key))
        assertTrue(entry.isFull)
        assertFalse(entry.type('0'), "a ninth symbol is refused")
        assertEquals("CF94BCAJ", taken(entry))
        val passphrase = asciiPadEntry()
        repeat(100) { assertTrue(passphrase.type('~')) }
        assertFalse(passphrase.type(' '))
        assertEquals(100, taken(passphrase).length)
    }

    @Test
    fun anEntryHoldsOnlyItsPadsKeys() {
        val letters = letterPadEntry()
        assertFalse(letters.type('A'), "the letter pad has no capitals")
        assertFalse(letters.type('1'))
        assertTrue(letters.type('a'))
        val code = crockfordPadEntry()
        for (key in "ILOUilou") assertFalse(code.type(key), "not a Crockford symbol")
        val dice = dicePadEntry()
        assertFalse(dice.replace('0'))
        assertFalse(dice.replace('7'))
        assertEquals(0, dice.length)
    }

    @Test
    fun theDicePadsPickIsReplacedNotAppended() {
        val dice = dicePadEntry()
        assertTrue(dice.replace('3'))
        assertTrue(dice.replace('5'))
        assertEquals(1, dice.length)
        assertEquals('5', dice.keyAt(0))
        assertEquals("5", taken(dice))
        assertEquals(0, dice.length)
    }

    @Test
    fun deleteTakeAndWipeLeaveNothingBehind() {
        val letters = letterPadEntry()
        for (key in "abou") letters.type(key)
        letters.delete()
        assertEquals(3, letters.length)
        assertTrue(letters.zeroPastLength(), "the deleted key's byte is zeroed")
        assertFailsWith<IllegalStateException> { letters.keyAt(3) }
        assertEquals("abo", taken(letters))
        assertEquals(0, letters.length, "taking the entry empties it")
        assertTrue(letters.zeroPastLength(), "taking the entry zeroes it")
        letters.delete()
        assertEquals(0, letters.length)
        for (key in "zoo") letters.type(key)
        letters.wipe()
        assertEquals(0, letters.length)
        assertTrue(letters.zeroPastLength(), "the wipe zeroes every byte")
        assertEquals("", taken(letters))
        assertEquals("PadEntry", letters.toString())
    }

    @Test
    fun aHandedOverEntryIsWipedOnceTheCallReturns() {
        val letters = letterPadEntry()
        for (key in "abou") letters.type(key)
        var handed: Secret? = null
        val seen = letters.handOver { secret ->
            handed = secret
            assertEquals(0, letters.length, "the entry is emptied before the call")
            buildString { for (index in 0 until secret.size) append(Char(secret[index].toInt())) }
        }
        assertEquals("abou", seen, "the call is handed exactly what was typed")
        val secret = assertNotNull(handed)
        assertEquals(4, secret.size)
        assertTrue((0 until secret.size).all { secret[it] == 0.toByte() }, "the handed Secret is wiped once the call returns")
        assertEquals(0, letters.length)
        assertTrue(letters.zeroPastLength(), "and the entry is zeroed")
    }

    /**
     * A call that throws (anything but KcHalt, which the model's call catches inside it, passes through
     * handOver): the handed Secret is wiped all the same, and the throw goes on unchanged.
     */
    @Test
    fun aHandedOverEntryIsWipedWhenTheCallThrows() {
        val code = crockfordPadEntry()
        for (key in "0123ABCD") assertTrue(code.type(key))
        val thrown = IllegalStateException("the call failed")
        var handed: Secret? = null
        val caught = assertFailsWith<IllegalStateException> {
            code.handOver<Unit> { secret ->
                handed = secret
                assertEquals(8, secret.size, "the call is handed all 8 symbols")
                throw thrown
            }
        }
        assertTrue(caught === thrown, "the call's own throw goes on, unchanged")
        val secret = assertNotNull(handed)
        assertTrue((0 until secret.size).all { secret[it] == 0.toByte() }, "the handed Secret is wiped though the call threw")
        assertEquals(0, code.length)
        assertTrue(code.zeroPastLength(), "and the entry is zeroed")
    }
}
