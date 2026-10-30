package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Words
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The pads' presses through the model (tasks/todo.md, Stage U's commit U3e; lead decision M5-72): a
 * key, Delete and a page of keys reach the model's padKey, padDelete, nextPage and previousPage, which act
 * only through pressOn, as every other control's press does. So a key under the privacy cover, the idle
 * warning or a privacy gate, or left over from a screen that has gone, types nothing, and a key typed is
 * input for the idle timer and the 30 s cover, whether a touch or an accessibility service's click made
 * it (the screens' pointer handler sees only touches). Over the real slot through Core and the host
 * library; each test leaves the slot at home.
 */
class PadPressTest {
    @AfterTest
    fun emptyTheSlot() {
        assertTrue(Core.wipeAll() is Reply.Done)
    }

    @Test
    fun aDiceKeyUnderTheCoverOrTheWarningPicksNothingAndAKeyPickedIsInput() {
        val rig = Rig().toHome().begin(Mode.DiceOnly, Words.Twelve)
        assertEquals(Screen.Dice, rig.screen)
        rig.model.padKey('3')
        rig.model.padKey('5')
        assertEquals("5", picked(rig), "a face replaces the pick")
        rig.model.padDelete()
        assertEquals("5", picked(rig), "the dice pad has no Delete")
        rig.model.appLeft()
        rig.model.appReturned()
        assertEquals(Overlay.Cover, rig.model.state.value.overlay, "left on a Public screen, the cover")
        rig.model.padKey('2')
        assertEquals("5", picked(rig), "a key under the cover picked nothing")
        rig.model.dismissOverlay()
        rig.clock.now = 100_000
        rig.model.padKey('1')
        rig.clock.now = 100_000 + Timers.WARN_MILLIS - 1
        rig.model.tick()
        assertNull(rig.model.state.value.overlay, "the key started the idle time again")
        rig.clock.now = 100_000 + Timers.WARN_MILLIS
        rig.model.tick()
        assertEquals(Overlay.Warning, rig.model.state.value.overlay)
        rig.model.padKey('4')
        assertEquals("1", picked(rig), "a key under the warning picked nothing")
        rig.clock.now = 100_000 + Timers.WIPE_MILLIS
        rig.model.tick()
        assertEquals(Notice.Idle, rig.model.state.value.notice, "nor was it input")
    }

    @Test
    fun theAsciiPadsKeysTypeOnlyPastTheGateAndOnlyFromThePageOnShowWhichTheModelKeeps() {
        val rig = Rig().toHome().toSummary(DICE_50)
        rig.model.summaryDone()
        rig.model.skipBackup()
        rig.model.showWatchOnly()
        rig.model.withBip39Passphrase()
        assertEquals(Screen.Bip39Entry, rig.screen)
        assertTrue(rig.model.state.value.gate)
        rig.model.padKey('!')
        rig.model.nextPage()
        assertEquals(0, rig.model.bip39Letters.length, "a key behind the gate typed nothing")
        assertEquals(0, rig.model.state.value.page, "Next keys behind the gate did nothing")
        rig.model.passGate()
        rig.model.padKey('x')
        assertEquals(0, rig.model.bip39Letters.length, "x is on page 3, not on page 1")
        rig.model.padKey('!')
        rig.model.nextPage()
        rig.model.nextPage()
        rig.model.nextPage()
        assertEquals(ASCII_PAGES - 1, rig.model.state.value.page, "Next keys stops at the last page")
        rig.model.padKey('x')
        rig.model.previousPage()
        assertEquals(1, rig.model.state.value.page)
        rig.model.padKey('A')
        assertEquals("!xA", typed(rig.model.bip39Letters), "each from the page it is on, the passphrase kept")
        rig.model.padDelete()
        assertEquals("!x", typed(rig.model.bip39Letters))
        val at = rig.clock.now + Timers.COVER_MILLIS - 1
        rig.clock.now = at
        rig.model.padKey('B')
        rig.clock.now = at + Timers.COVER_MILLIS - 1
        rig.model.tick()
        assertNull(rig.model.state.value.overlay, "the key started the 30 s again")
        rig.clock.now = at + Timers.COVER_MILLIS
        rig.model.tick()
        assertEquals(Overlay.Cover, rig.model.state.value.overlay)
        rig.model.padKey('C')
        rig.model.padDelete()
        rig.model.previousPage()
        assertEquals("!xB", typed(rig.model.bip39Letters), "a key or Delete under the cover did nothing")
        assertEquals(1, rig.model.state.value.page, "nor did Previous keys")
        rig.model.dismissOverlay()
        rig.model.back()
        assertEquals(Screen.Bip39Ask, rig.screen)
        assertEquals(0, rig.model.bip39Letters.length)
        rig.model.withBip39Passphrase()
        rig.model.passGate()
        assertEquals(0, rig.model.state.value.page, "the entry opens on page 1 of the keys again")
    }

    @Test
    fun aLetterLeftOverFromTheReadbackOrPressedAfterItsMatchTypesNothing() {
        val rig = Rig().toHome().toSkippedResult(DICE_50).toWords()
        val words = kcrWords(DICE_50)
        repeat(words.size - 1) { rig.model.nextPage() }
        rig.model.padKey('a')
        assertEquals(0, rig.model.readbackLetters.length, "the words page offers no pad")
        rig.model.startReadback()
        for (letter in words[0].take(4)) rig.model.padKey(letter)
        rig.model.readbackTyped()
        assertTrue(rig.model.state.value.matched)
        rig.model.padKey('a')
        rig.model.padDelete()
        assertEquals(0, rig.model.readbackLetters.length, "after the match the pad is gone")
        rig.model.readbackNext()
        rig.model.padKey('q')
        rig.model.padDelete()
        rig.model.padKey('z')
        assertEquals("z", typed(rig.model.readbackLetters), "insert 2's entry types and deletes")
    }

    /** The dice pad's pick as typed, or none. */
    private fun picked(rig: Rig): String = typed(rig.model.dicePick)

    /** What entry holds, read in-process (test values only, never printed). */
    private fun typed(entry: PadEntry): String = buildString { for (index in 0 until entry.length) append(entry.keyAt(index)) }

    private companion object {
        const val DICE_50 = "dice-50-words12"
    }
}
