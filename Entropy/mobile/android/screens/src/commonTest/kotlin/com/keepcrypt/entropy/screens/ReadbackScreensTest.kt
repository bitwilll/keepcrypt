package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Verdict
import com.keepcrypt.entropy.ffi.WordPage
import com.keepcrypt.entropy.ffi.Words
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The CeremonyModel transitions of the read-back, the summary and Finish (tasks/todo.md, M5 group 17;
 * docs/mobile-apps.md, steps 11, 12 and 17; docs/seal-watchonly-braille.md, "Read-back from the
 * metal", mandatory, and "Before you walk away"), over the real slot through Core and the host library:
 * the last insert's "Start the read-back", insert 1's entry with no gate (Protected to Protected); the
 * faces typed shown in order; Done only at three or four letters, the letters handed to core and wiped;
 * a match showing the whole word and Next the next insert, every insert in turn, then the read-back's
 * end once core says every insert has matched; an e/i misread named a mirror misread on its face, the
 * insert shown again (its one way on back to its read-back) and read again; a wrong letter's missing
 * and extra dots (its line written out for one pair), a missed fourth letter and a letter on a blank
 * fourth face named face by face; Back doing nothing on the read-back, its end, the summary and the
 * checklist; the wallet summary core's, its Next the encrypted backup's offer (commit 20), whose Skip
 * leads to the checklist; the checklist for 12 and 24 words, and Finish ending the session
 * in core and returning Home with the slot empty; leaving the app on the entry or the mismatch
 * discarding at once with the letters, the page and the verdicts wiped, the Public screens after it
 * covered and wiped after 60 s away; and wipeAll. The seeds are vectors/kcr.json's dice-50-words12 and,
 * for 24 words, dice-99-words24 (their words, public vectors, compared and never printed). Each test
 * leaves the slot at home.
 */
class ReadbackScreensTest {
    @AfterTest
    fun emptyTheSlot() {
        assertTrue(Core.wipeAll() is Reply.Done)
    }

    private fun <T> done(reply: Reply<T>, what: String): T = when (reply) {
        is Reply.Done -> reply.value
        else -> fail(what + " was not done")
    }

    private fun assertNoSession(message: String) {
        assertTrue(Core.selfTest() is Reply.Done, message)
    }

    private val words: List<String> by lazy { kcrWords(DICE_50) }

    private fun insert(rig: Rig): WordPage = assertNotNull(rig.model.state.value.insert, "the insert on show")

    /** A new model past Skip's result to the last insert's page. */
    private fun atLastInsert(): Rig {
        val rig = Rig().toHome().toSkippedResult(DICE_50).toWords()
        repeat(words.size - 1) { rig.model.nextPage() }
        assertEquals(words.size - 1, rig.model.state.value.page)
        return rig
    }

    /** Types letters on the entry's letter pad, each one a key. */
    private fun type(rig: Rig, letters: String) {
        for (letter in letters) assertTrue(rig.model.readbackLetters.type(letter))
    }

    /** On the entry of insert index + 1: its first four letters (all of a three-letter word's), Done, then Next. */
    private fun readBack(rig: Rig, index: Int) {
        type(rig, words[index].take(4))
        rig.model.readbackTyped()
        assertTrue(rig.model.state.value.matched, "insert " + (index + 1) + " matched")
        rig.model.readbackNext()
    }

    /** The word with its face-th letter (1-4) read as its mirror partner (e/i, d/f, h/j, r/w). */
    private fun mirrored(word: String, face: Int): String {
        val partner = when (word[face - 1]) {
            'e' -> 'i'
            'i' -> 'e'
            'd' -> 'f'
            'f' -> 'd'
            'h' -> 'j'
            'j' -> 'h'
            'r' -> 'w'
            'w' -> 'r'
            else -> fail("no mirror letter on that face")
        }
        return word.take(4).substring(0, face - 1) + partner + word.take(4).substring(face)
    }

    @Test
    fun theReadbackStartsOnTheLastInsertAndEachMatchShowsTheWholeWordUntilCoreSaysAllMatched() {
        val rig = atLastInsert()
        val last = insert(rig)
        rig.model.startReadback()
        val entry = rig.model.state.value
        assertEquals(Screen.ReadbackEntry, entry.screen)
        assertTrue(isProtected(Screen.ReadbackEntry))
        assertFalse(entry.gate, "from the Protected words to the Protected entry: no gate")
        assertEquals(0, entry.page)
        assertTrue(wiped(last), "the last page was wiped")
        for (index in words.indices) {
            val state = rig.model.state.value
            val what = "insert " + (index + 1)
            assertEquals(Screen.ReadbackEntry, state.screen, what)
            assertEquals(index, state.page, what)
            assertFalse(state.matched, what)
            val shown = insert(rig)
            assertEquals(index + 1, shown.position, what)
            // Done does nothing below three letters, and the letters stay.
            type(rig, words[index].take(2))
            rig.model.readbackTyped()
            assertEquals(2, rig.model.readbackLetters.length, what + ": Done below three letters")
            assertFalse(rig.model.state.value.matched)
            rig.model.back()
            assertSame(state, rig.model.state.value, what + ": Back does nothing on the read-back")
            rig.model.readbackLetters.wipe()
            type(rig, words[index].take(4))
            val faces = typedFaces(rig.model.readbackLetters)
            assertTrue(faces == words[index].take(4).padEnd(4, '-'), what + ": the faces typed, in order, then a dash for each to come")
            rig.model.readbackTyped()
            val matched = rig.model.state.value
            assertEquals(Screen.ReadbackEntry, matched.screen, what)
            assertTrue(matched.matched, what + " matched")
            assertSame(shown, matched.insert, what + ": the match shows the same insert's whole word")
            assertTrue(sameWord(shown, words[index]), what + " is not the vector's word")
            assertEquals(0, rig.model.readbackLetters.length, what + ": the letters were handed to core, the entry emptied (their copy's wipe is PadsTest's)")
            assertTrue(rig.model.readbackLetters.zeroPastLength())
            assertEquals(index + 1 == words.size, matched.complete, what + ": core says every insert matched only at the last")
            type(rig, "abc")
            rig.model.readbackTyped()
            assertSame(matched, rig.model.state.value, what + ": after a match Done does nothing, only Next")
            rig.model.readbackLetters.wipe()
            rig.model.readbackNext()
            if (index + 1 < words.size) assertTrue(wiped(shown), what + "'s page was wiped as the next came")
        }
        assertEquals(Screen.ReadbackDone, rig.screen, "every insert matched: the read-back's end")
        assertFalse(isProtected(Screen.ReadbackDone))
        assertNull(rig.model.state.value.insert)
        rig.model.back()
        assertEquals(Screen.ReadbackDone, rig.screen, "Back does nothing at the read-back's end")
        assertEquals(0, rig.worker.waiting, "the read-back's calls are short calls")
    }

    @Test
    fun anEOrIMisreadIsNamedAMirrorMisreadAndTheInsertCanBeShownAndReadAgain() {
        val rig = atLastInsert()
        rig.model.startReadback()
        val index = words.indexOfFirst { word -> word.take(4).any { it == 'e' || it == 'i' } }
        assertTrue(index >= 0, "the gate seed has an e or an i among a word's first four letters")
        for (before in 0 until index) readBack(rig, before)
        val face = words[index].take(4).indexOfFirst { it == 'e' || it == 'i' } + 1
        val entryInsert = insert(rig)
        type(rig, mirrored(words[index], face))
        rig.model.readbackTyped()
        val state = rig.model.state.value
        assertEquals(Screen.ReadbackMismatch, state.screen)
        assertTrue(isProtected(Screen.ReadbackMismatch))
        assertFalse(state.gate)
        assertSame(entryInsert, state.insert, "the mismatch names the same insert")
        val mismatch = assertNotNull(state.mismatch)
        for (n in 1..4) {
            val verdict = mismatch.face(n)
            if (n == face) {
                assertEquals(Verdict.MirrorMisread, verdict.verdict, "the e/i face is named a mirror misread")
                assertEquals("Face " + n + ": mirror misread", verdictLine(n, verdict))
            } else {
                assertEquals(Verdict.Ok, verdict.verdict)
                assertEquals("Face " + n + ": ok", verdictLine(n, verdict))
            }
        }
        assertEquals("Insert " + (index + 1).toString().padStart(2, '0') + " does not match · device 1 of 1", mismatchHeader(entryInsert))
        assertEquals(0, rig.model.readbackLetters.length, "the misread letters were wiped")
        rig.model.back()
        assertSame(state, rig.model.state.value, "Back does nothing on the mismatch")
        // Show the insert: its page, reviewed, whose one way on is back to its read-back.
        rig.model.reviewInsert()
        val reviewed = rig.model.state.value
        assertEquals(Screen.Words, reviewed.screen)
        assertTrue(reviewed.reviewing)
        assertFalse(reviewed.gate)
        assertSame(entryInsert, reviewed.insert)
        assertTrue(sameWord(entryInsert, words[index]), "the reviewed insert is not the vector's word")
        assertTrue((1..4).all { mismatch.face(it).verdict == Verdict.Ok }, "the verdicts were wiped as the mismatch went")
        rig.model.nextPage()
        rig.model.previousPage()
        rig.model.back()
        rig.model.toOverview()
        rig.model.startReadback()
        assertSame(reviewed, rig.model.state.value, "the reviewed insert offers only its way back")
        rig.model.backToReadback()
        assertEquals(Screen.ReadbackEntry, rig.screen)
        assertEquals(index, rig.model.state.value.page)
        assertFalse(rig.model.state.value.matched)
        // A second misread, then Read it again: the same insert's entry, the verdicts wiped.
        type(rig, mirrored(words[index], face))
        rig.model.readbackTyped()
        val again = assertNotNull(rig.model.state.value.mismatch)
        rig.model.readbackAgain()
        assertEquals(Screen.ReadbackEntry, rig.screen)
        assertSame(entryInsert, rig.model.state.value.insert)
        assertNull(rig.model.state.value.mismatch)
        assertEquals(Verdict.Ok, again.face(face).verdict, "the verdicts were wiped")
        readBack(rig, index)
        assertEquals(index + 1, rig.model.state.value.page, "read correctly, the next insert")
    }

    @Test
    fun aWrongLetterAndAMissedFourthLetterAreNamedFaceByFace() {
        val rig = atLastInsert()
        rig.model.startReadback()
        val first = insert(rig)
        val trueFirst = first.face(1)
        // Another letter on face 1: one that is no mirror partner of the word's, so a wrong letter.
        val other = "zqxy".first { it != words[0][0] && it != trueFirst.mirrorPartner }
        type(rig, other + words[0].take(4).drop(1))
        rig.model.readbackTyped()
        val mismatch = assertNotNull(rig.model.state.value.mismatch)
        val wrong = mismatch.face(1)
        assertEquals(Verdict.WrongLetter, wrong.verdict)
        val typed = brailleDots(other)
        assertTrue(wrong.missingDots == (trueFirst.dots and typed.inv()), "the dots the letter read lacks")
        assertTrue(wrong.extraDots == (typed and trueFirst.dots.inv()), "the dots it has too many")
        val line = verdictLine(1, wrong)
        assertTrue(line.startsWith("Face 1: wrong letter: missing ") && line.contains(", extra "))
        assertTrue((2..4).all { mismatch.face(it).verdict == Verdict.Ok })
        rig.model.readbackAgain()
        // The line written out for one pair, so the dots' order and which list is which are the
        // test's, not dotsText's: the gate seed's u (dots 1 3 6) read as q (dots 1 2 3 4 5) lacks dot 6
        // and has 2, 4 and 5 too many.
        assertTrue(words[0].startsWith("u"), "the line below is written for the gate seed's first letter")
        type(rig, "q" + words[0].substring(1, 4))
        rig.model.readbackTyped()
        val q = assertNotNull(rig.model.state.value.mismatch)
        assertEquals("Face 1: wrong letter: missing 6, extra 2 4 5", verdictLine(1, q.face(1)))
        rig.model.readbackAgain()
        // Three letters of a word of four or more: the fourth face should have a letter.
        assertTrue(words[0].length >= 4)
        type(rig, words[0].take(3))
        rig.model.readbackTyped()
        val missed = assertNotNull(rig.model.state.value.mismatch)
        assertEquals(Verdict.ShouldHaveLetter, missed.face(4).verdict)
        assertEquals("Face 4: should have a letter", verdictLine(4, missed.face(4)))
        assertTrue((1..3).all { missed.face(it).verdict == Verdict.Ok })
    }

    @Test
    fun aLetterTypedOnABlankFourthFaceIsNamedShouldBeBlank() {
        val rig = Rig().toHome().toSkippedResult(DICE_99_24).toWords()
        val words24 = kcrWords(DICE_99_24)
        repeat(INSERTS_PER_DEVICE) { rig.model.nextPage() }
        rig.model.swapDone()
        rig.model.passGate()
        repeat(words24.size - INSERTS_PER_DEVICE - 1) { rig.model.nextPage() }
        rig.model.startReadback()
        val index = words24.indexOfFirst { it.length == 3 }
        assertTrue(index >= 0, "the 24-word gate seed has a three-letter word, whose fourth face is blank")
        for (before in 0 until index) {
            type(rig, words24[before].take(4))
            rig.model.readbackTyped()
            assertTrue(rig.model.state.value.matched)
            rig.model.readbackNext()
        }
        type(rig, words24[index] + "a")
        rig.model.readbackTyped()
        val mismatch = assertNotNull(rig.model.state.value.mismatch)
        assertEquals(Verdict.ShouldBeBlank, mismatch.face(4).verdict)
        assertEquals("Face 4: should be blank", verdictLine(4, mismatch.face(4)))
        assertTrue((1..3).all { mismatch.face(it).verdict == Verdict.Ok })
    }

    @Test
    fun theSummaryIsCoresAndFinishEndsTheSessionInCoreAndReturnsHome() {
        val rig = atLastInsert()
        rig.model.startReadback()
        for (index in words.indices) readBack(rig, index)
        assertEquals(Screen.ReadbackDone, rig.screen)
        rig.model.showSummary()
        val wallet = rig.model.state.value
        assertEquals(Screen.Wallet, wallet.screen)
        assertFalse(isProtected(Screen.Wallet), "the wallet summary is Public, as the Pi's (Q29)")
        assertFalse(wallet.gate)
        val summary = assertNotNull(wallet.summary)
        val core = done(Core.summary(), "the summary, while the words are available")
        assertContentEquals(core.fingerprint, summary.fingerprint)
        assertEquals(core.firstAddress, summary.firstAddress)
        assertEquals(8, fingerprintHex(summary.fingerprint).length)
        assertTrue(fingerprintHex(summary.fingerprint).all { it in "0123456789abcdef" })
        assertTrue(summary.firstAddress.startsWith("bc1q"), "BIP-84's first receive address")
        rig.model.back()
        assertSame(wallet, rig.model.state.value, "Back does nothing on the summary")
        rig.model.summaryDone()
        assertEquals(Screen.BackupOffer, rig.screen, "the summary's Next offers the encrypted backup (commit 20)")
        rig.model.skipBackup()
        rig.skipExports()
        val checklist = rig.model.state.value
        assertEquals(Screen.Checklist, checklist.screen)
        assertFalse(isProtected(Screen.Checklist))
        assertFalse(checklist.twoDevices, "a 12-word seed is on one device")
        assertEquals(6, CHECKLIST.size)
        rig.model.back()
        assertSame(checklist, rig.model.state.value, "Back does nothing on the checklist")
        rig.model.finishCeremony()
        assertEquals(Screen.Home, rig.screen, "Finish returns Home")
        assertNull(rig.model.state.value.notice, "with nothing to say: the session ended, nothing was wiped away")
        assertNoSession("Finish ended the session in core (end)")
        // With no session held, the timers neither warn nor wipe, and the next seed is a new one.
        rig.clock.now += Timers.WIPE_MILLIS
        rig.model.tick()
        assertEquals(Screen.Home, rig.screen)
        assertNull(rig.model.state.value.overlay)
        rig.begin(Mode.DiceOnly, Words.Twelve)
        val dice = assertNotNull(rig.model.state.value.dice)
        assertEquals(50, dice.minimum, "a new ceremony at the normal minimum")
    }

    @Test
    fun aTwentyFourWordSeedsChecklistSaysWhichDeviceHoldsWords1To12() {
        val rig = Rig().toHome().toSkippedResult(DICE_99_24).toWords()
        val words24 = kcrWords(DICE_99_24)
        repeat(INSERTS_PER_DEVICE) { rig.model.nextPage() }
        rig.model.swapDone()
        rig.model.passGate()
        repeat(words24.size - INSERTS_PER_DEVICE - 1) { rig.model.nextPage() }
        rig.model.startReadback()
        for ((index, word) in words24.withIndex()) {
            assertEquals(index + 1, insert(rig).position)
            assertEquals(if (index < INSERTS_PER_DEVICE) 1 else 2, insert(rig).device, "the read-back names each insert's device")
            type(rig, word.take(4))
            rig.model.readbackTyped()
            assertTrue(rig.model.state.value.matched)
            rig.model.readbackNext()
        }
        assertEquals(Screen.ReadbackDone, rig.screen)
        rig.model.showSummary()
        rig.model.summaryDone()
        rig.model.skipBackup()
        rig.skipExports()
        assertEquals(Screen.Checklist, rig.screen)
        assertTrue(rig.model.state.value.twoDevices, "the checklist names device 1 of 2's words")
        rig.model.finishCeremony()
        assertEquals(Screen.Home, rig.screen)
        assertNoSession("Finish ended the session")
    }

    @Test
    fun leavingTheAppOnTheEntryOrTheMismatchDiscardsAtOnceWithItsLettersPageAndVerdictsWiped() {
        val rig = atLastInsert()
        rig.model.startReadback()
        val shown = insert(rig)
        type(rig, words[0].take(3))
        rig.model.appLeft()
        assertEquals(Screen.GoOffline, rig.screen, "leaving the Protected entry discards at once")
        assertEquals(Notice.Left, rig.model.state.value.notice)
        assertEquals(0, rig.model.readbackLetters.length, "the letters typed are wiped")
        assertTrue(rig.model.readbackLetters.zeroPastLength())
        assertTrue(wiped(shown))
        assertNoSession("the discard took the slot home")
        rig.model.appReturned()
        rig.model.dismissOverlay()
        rig.model.startOffline()
        rig.toSkippedResult(DICE_50).toWords()
        repeat(words.size - 1) { rig.model.nextPage() }
        rig.model.startReadback()
        type(rig, "zzzz")
        rig.model.readbackTyped()
        val page = insert(rig)
        val mismatch = assertNotNull(rig.model.state.value.mismatch)
        assertEquals(Screen.ReadbackMismatch, rig.screen)
        rig.model.appLeft()
        assertEquals(Screen.GoOffline, rig.screen, "leaving the Protected mismatch discards at once")
        assertTrue(wiped(page))
        assertTrue((1..4).all { mismatch.face(it).verdict == Verdict.Ok && mismatch.face(it).missingDots == 0 }, "the verdicts are wiped")
        assertNoSession("the discard took the slot home")
    }

    @Test
    fun thePublicScreensAfterTheReadbackTakeTheCoverAndThe60SecondWipe() {
        val rig = atLastInsert()
        rig.model.startReadback()
        for (index in words.indices) readBack(rig, index)
        for (screen in listOf(
            Screen.ReadbackDone, Screen.Wallet, Screen.BackupOffer, Screen.WatchOffer, Screen.RegisterOffer, Screen.Checklist,
        )) {
            assertEquals(screen, rig.screen)
            rig.model.appLeft()
            assertEquals(screen, rig.screen, screenId(screen) + ": leaving a Public screen keeps the session")
            assertEquals(Overlay.Cover, rig.model.state.value.overlay)
            rig.clock.now += Timers.BACKGROUND_MILLIS - 1
            rig.model.appReturned()
            assertEquals(screen, rig.screen, screenId(screen) + ": 59.999 s away keeps it")
            rig.model.dismissOverlay()
            when (screen) {
                Screen.ReadbackDone -> rig.model.showSummary()
                Screen.Wallet -> rig.model.summaryDone()
                Screen.BackupOffer -> rig.model.skipBackup()
                Screen.WatchOffer -> rig.model.skipWatchOnly()
                Screen.RegisterOffer -> rig.model.skipRegistration()
                else -> {}
            }
        }
        rig.model.appLeft()
        rig.clock.now += Timers.BACKGROUND_MILLIS
        rig.model.tick()
        assertEquals(Screen.GoOffline, rig.screen, "60 s away from the checklist wipes")
        assertEquals(Notice.Background, rig.model.state.value.notice)
        assertNoSession("the background wipe took the slot home")
    }

    @Test
    fun wipeAllWipesTheTypedLettersThePageAndTheVerdicts() {
        val rig = atLastInsert()
        rig.model.startReadback()
        val shown = insert(rig)
        type(rig, words[0].take(2))
        rig.model.wipeAll()
        assertEquals(0, rig.model.readbackLetters.length, "wipeAll wipes the letters typed")
        assertTrue(rig.model.readbackLetters.zeroPastLength())
        assertTrue(wiped(shown), "and the page on show")
        assertNoSession("wipeAll emptied the slot")
        val second = atLastInsert()
        second.model.startReadback()
        type(second, "zzzz")
        second.model.readbackTyped()
        val mismatch = assertNotNull(second.model.state.value.mismatch)
        second.model.wipeAll()
        assertTrue((1..4).all { mismatch.face(it).verdict == Verdict.Ok }, "wipeAll wipes the verdicts on show")
    }

    private companion object {
        /** vectors/kcr.json's dice gate seeds. */
        const val DICE_50 = "dice-50-words12"
        const val DICE_99_24 = "dice-99-words24"
    }
}
