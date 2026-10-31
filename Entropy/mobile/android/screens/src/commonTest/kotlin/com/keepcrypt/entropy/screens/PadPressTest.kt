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
 * only through pressOn, as every other control's press does, and a key or Delete names the screen and page
 * it was made on. So a key under the privacy cover, the idle warning or a privacy gate, or left over from
 * a screen or page that has gone (the read-back's insert, the confirm's question), types nothing, and a
 * key typed is input for the idle timer and the 30 s cover, whether a touch or an accessibility service's
 * click made it (the screens' pointer handler sees only touches). Over the real slot through Core and the
 * host library; each test leaves the slot at home.
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
        rig.press('3')
        rig.press('5')
        assertEquals("5", picked(rig), "a face replaces the pick")
        rig.pressDelete()
        assertEquals("5", picked(rig), "the dice pad has no Delete")
        rig.model.appLeft()
        rig.model.appReturned()
        assertEquals(Overlay.Cover, rig.model.state.value.overlay, "left on a Public screen, the cover")
        rig.press('2')
        assertEquals("5", picked(rig), "a key under the cover picked nothing")
        rig.model.dismissOverlay()
        rig.clock.now = 100_000
        rig.press('1')
        rig.clock.now = 100_000 + Timers.WARN_MILLIS - 1
        rig.model.tick()
        assertNull(rig.model.state.value.overlay, "the key started the idle time again")
        rig.clock.now = 100_000 + Timers.WARN_MILLIS
        rig.model.tick()
        assertEquals(Overlay.Warning, rig.model.state.value.overlay)
        rig.press('4')
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
        rig.press('!')
        rig.model.nextPage()
        assertEquals(0, rig.model.bip39Letters.length, "a key behind the gate typed nothing")
        assertEquals(0, rig.model.state.value.page, "Next keys behind the gate did nothing")
        rig.model.passGate()
        rig.model.previousPage()
        assertEquals(0, rig.model.state.value.page, "Previous keys stops at the first page")
        rig.press('x')
        assertEquals(0, rig.model.bip39Letters.length, "x is on page 3, not on page 1")
        rig.press('!')
        rig.model.nextPage()
        rig.model.nextPage()
        rig.model.nextPage()
        assertEquals(ASCII_PAGES - 1, rig.model.state.value.page, "Next keys stops at the last page")
        rig.press('x')
        rig.model.previousPage()
        assertEquals(1, rig.model.state.value.page)
        rig.press('A')
        assertEquals("!xA", typed(rig.model.bip39Letters), "each from the page it is on, the passphrase kept")
        rig.pressDelete()
        assertEquals("!x", typed(rig.model.bip39Letters))
        val at = rig.clock.now + Timers.COVER_MILLIS - 1
        rig.clock.now = at
        rig.press('B')
        rig.clock.now = at + Timers.COVER_MILLIS - 1
        rig.model.tick()
        assertNull(rig.model.state.value.overlay, "the key started the 30 s again")
        rig.clock.now = at + Timers.COVER_MILLIS
        rig.model.tick()
        assertEquals(Overlay.Cover, rig.model.state.value.overlay)
        rig.press('C')
        rig.pressDelete()
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
    fun aKeyLeftOverFromAScreenOrAPageThatHasGoneOrPressedAfterTheMatchTypesNothing() {
        val rig = Rig().toHome().toSkippedResult(DICE_50).toWords()
        val words = kcrWords(DICE_50)
        repeat(words.size - 1) { rig.model.nextPage() }
        rig.press('a')
        assertEquals(0, rig.model.readbackLetters.length, "the words page offers no pad")
        rig.model.startReadback()
        rig.press(words[0].take(4))
        rig.model.readbackTyped()
        assertTrue(rig.model.state.value.matched)
        rig.press('a')
        assertEquals(0, rig.model.readbackLetters.length, "after the match the pad is gone")
        rig.model.readbackNext()
        assertEquals(1, rig.model.state.value.page)
        rig.model.padKey(Screen.ReadbackEntry, 0, 'q')
        assertEquals(0, rig.model.readbackLetters.length, "a key made on insert 1's entry typed on insert 2's")
        rig.model.padKey(Screen.CodeEntry, 1, 'q')
        assertEquals(0, rig.model.readbackLetters.length, "a key made on another screen typed here")
        rig.press("qz")
        rig.model.padDelete(Screen.ReadbackEntry, 0)
        assertEquals("qz", typed(rig.model.readbackLetters), "a Delete made on insert 1's entry deleted on insert 2's")
        rig.pressDelete()
        assertEquals("q", typed(rig.model.readbackLetters), "insert 2's entry types and deletes")
    }

    @Test
    fun theCodeEntrysPadTypesAndDeletesOnlyUncoveredAndTheDiceAt256RollsPicksNothing() {
        val rig = Rig().toHome().begin(Mode.DiceOnly, Words.Twelve)
        rig.roll(MAX_ROLLS)
        assertEquals(MAX_ROLLS, rig.model.state.value.dice?.rolls)
        rig.press('1')
        assertEquals(0, rig.model.dicePick.length, "a face picked at 256 rolls, where the pad is disabled")
        rig.model.diceDone()
        rig.worker.run()
        rig.model.checkNow()
        rig.model.showCheckQr()
        rig.model.typeCode()
        assertEquals(Screen.CodeEntry, rig.screen)
        rig.press("PBJ")
        rig.pressDelete()
        assertEquals("PB", typed(rig.model.goAheadCode))
        rig.model.appLeft()
        rig.model.appReturned()
        assertEquals(Overlay.Cover, rig.model.state.value.overlay)
        rig.press('N')
        rig.pressDelete()
        assertEquals("PB", typed(rig.model.goAheadCode), "a key or Delete under the cover acted")
    }

    @Test
    fun theConfirmsLetterPadTypesOnlyOnTheQuestionItWasPressedOn() {
        val rig = Rig().toHome().toSummary(DICE_50)
        val passphrase = rig.toConfirm()
        val confirm = rig.model.state.value
        assertEquals(Screen.BackupConfirm, confirm.screen)
        val question = checkNotNull(confirm.challenge).questions[0]
        rig.answer(passphrase[question.position - 1])
        assertEquals(1, rig.model.state.value.page, "question 2")
        rig.model.padKey(Screen.BackupConfirm, 0, 'a')
        rig.model.padDelete(Screen.BackupConfirm, 0)
        assertEquals(0, rig.model.backupLetters.length, "a key made on question 1 typed on question 2")
        rig.press("ab")
        rig.pressDelete()
        assertEquals("a", typed(rig.model.backupLetters), "question 2's pad types and deletes")
    }

    /** The dice pad's pick as typed, or none. */
    private fun picked(rig: Rig): String = typed(rig.model.dicePick)

    /** What entry holds, read in-process (test values only, never printed). */
    private fun typed(entry: PadEntry): String = buildString { for (index in 0 until entry.length) append(entry.keyAt(index)) }

    private companion object {
        const val DICE_50 = "dice-50-words12"
    }
}
