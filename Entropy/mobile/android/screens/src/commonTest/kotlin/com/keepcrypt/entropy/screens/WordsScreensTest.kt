package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.WordPage
import com.keepcrypt.entropy.ffi.Words
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The CeremonyModel transitions of the words (tasks/todo.md, M5 group 17; docs/mobile-apps.md, step
 * 10; docs/seal-watchonly-braille.md, "Braille backup" and "24-word seeds"), over the real slot through
 * Core and the host library: the check result's Show words, through the privacy gate (behind which no
 * press on the words takes), from Skip's result, a scanned proof's and a loaded snapshot's; each insert
 * page core's, equal to vectors/kcr.json's gate seed's word and braille.json's insert of it, the page it
 * leaves wiped as it goes; Previous, the system Back and Next, which does nothing on the last page; the
 * overview's four words a page and its way back to insert view; a 24-word seed's pages marked device 1
 * of 2 and 2 of 2, with the device swap (Public, so the gate comes again) before word 13 in either
 * view and none paging back; and the Protected rules on the words: the 30 s cover, the recording flag,
 * leaving the app and going online discarding at once with the pages wiped, and wipeAll. The words are
 * public vectors, compared and never printed. Each test leaves the slot at home (wipeAll after it).
 */
class WordsScreensTest {
    @AfterTest
    fun emptyTheSlot() {
        assertTrue(Core.wipeAll() is Reply.Done)
    }

    /** The slot is at home and empty: no session, nothing waiting at a restart. */
    private fun assertNoSession(message: String) {
        assertTrue(Core.selfTest() is Reply.Done, message)
    }

    private fun insert(rig: Rig): WordPage = assertNotNull(rig.model.state.value.insert, "the insert on show")

    /** The words page shows insert index + 1 of words, past the gate, as core's page and braille.json's insert of the word. */
    private fun assertPage(rig: Rig, words: List<String>, index: Int, device: Int, devices: Int) {
        val state = rig.model.state.value
        val what = "insert " + (index + 1)
        assertEquals(Screen.Words, state.screen, what)
        assertFalse(state.gate, what + " past the gate")
        assertEquals(index, state.page, what)
        val insert = insert(rig)
        assertEquals(index + 1, insert.position, what)
        assertEquals(words.size, insert.count, what)
        assertEquals(device, insert.device, what + "'s device")
        assertEquals(devices, insert.devices, what + "'s devices")
        assertEquals(index % INSERTS_PER_DEVICE + 1, insert.sequence, what + "'s sequence on face 6")
        assertTrue(sameWord(insert, words[index]), what + " is not the vector's word")
        assertInsertOf(insert, words[index], what)
    }

    @Test
    fun skipsResultShowsTheFirstInsertThroughThePrivacyGateBehindWhichNoPressTakes() {
        val rig = Rig().toHome().toSkippedResult(DICE_50)
        assertEquals(Screen.CheckResult, rig.screen)
        assertTrue(rig.model.state.value.skipped)
        rig.model.nextPage()
        rig.model.back()
        assertEquals(Screen.CheckResult, rig.screen, "the result's Back does nothing, and Next is the words'")
        rig.model.showWords()
        val gated = rig.model.state.value
        assertEquals(Screen.Words, gated.screen)
        assertTrue(gated.gate, "the words are Protected, entered from the Public result through the privacy gate")
        assertTrue(isProtected(Screen.Words) && !isProtected(Screen.CheckResult))
        val first = assertNotNull(gated.insert, "core's page of insert 1, behind the gate")
        // Behind the gate no press on the words takes: Next, Overview, Back and the read-back stay put.
        rig.model.nextPage()
        rig.model.toOverview()
        rig.model.back()
        rig.model.startReadback()
        rig.model.showWords()
        assertSame(gated, rig.model.state.value, "a press behind the gate reaches nothing")
        rig.model.passGate()
        assertFalse(rig.model.state.value.gate)
        assertSame(first, rig.model.state.value.insert)
        assertPage(rig, kcrWords(DICE_50), 0, 1, 1)
        assertFalse(rig.model.state.value.twoDevices)
        rig.model.showWords()
        assertSame(first, rig.model.state.value.insert, "Show words is the result's, so a press of it on the words does nothing")
    }

    @Test
    fun everyInsertPageIsTheVectorsWordAndThePageItLeavesIsWiped() {
        val rig = Rig().toHome().toSkippedResult(DICE_50).toWords()
        val words = kcrWords(DICE_50)
        var left: WordPage? = null
        for (index in words.indices) {
            assertPage(rig, words, index, 1, 1)
            val shown = insert(rig)
            left?.let { assertTrue(wiped(it), "insert " + index + "'s page was wiped as it went") }
            if (index + 1 < words.size) {
                rig.model.startReadback()
                assertSame(shown, rig.model.state.value.insert, "the read-back starts on the last insert only")
                rig.model.nextPage()
            }
            left = shown
        }
        // Next on the last page does nothing; Previous and the system Back go back one page each.
        val last = insert(rig)
        rig.model.nextPage()
        assertSame(last, rig.model.state.value.insert, "Next on the last insert")
        rig.model.previousPage()
        assertPage(rig, words, 10, 1, 1)
        assertTrue(wiped(last))
        rig.model.back()
        assertPage(rig, words, 9, 1, 1)
        repeat(9) { rig.model.back() }
        assertPage(rig, words, 0, 1, 1)
        val first = insert(rig)
        rig.model.back()
        rig.model.previousPage()
        assertSame(first, rig.model.state.value.insert, "Back and Previous on the first insert do nothing")
        assertEquals(0, rig.worker.waiting, "the pages are short calls")
    }

    @Test
    fun theOverviewShowsFourWordsAPageAndItsInsertViewThePagesFirstInsert() {
        val rig = Rig().toHome().toSkippedResult(DICE_50).toWords()
        val words = kcrWords(DICE_50)
        repeat(5) { rig.model.nextPage() }
        val fromPage = insert(rig)
        rig.model.toOverview()
        fun assertOverview(page: Int) {
            val state = rig.model.state.value
            assertEquals(Screen.WordsOverview, state.screen)
            assertFalse(state.gate, "Protected to Protected: no gate")
            assertEquals(page, state.page)
            assertNull(state.insert)
            val inserts = assertNotNull(state.overview)
            assertEquals(OVERVIEW_WORDS, inserts.size)
            for ((at, insert) in inserts.withIndex()) {
                val index = page * OVERVIEW_WORDS + at
                assertEquals(index + 1, insert.position)
                assertTrue(sameWord(insert, words[index]), "overview insert " + (index + 1) + " is not the vector's word")
                assertInsertOf(insert, words[index], "overview insert " + (index + 1))
            }
            val first = page * OVERVIEW_WORDS + 1
            assertEquals(
                "Words " + first.toString().padStart(2, '0') + "-" + (first + 3).toString().padStart(2, '0') + " · device 1 of 1",
                overviewHeader(inserts.first(), inserts.last()),
            )
        }
        assertOverview(1)
        assertTrue(wiped(fromPage), "the insert view's page was wiped")
        val second = assertNotNull(rig.model.state.value.overview)
        rig.model.nextPage()
        assertOverview(2)
        assertTrue(second.all { wiped(it) }, "the overview page it left was wiped")
        val third = assertNotNull(rig.model.state.value.overview)
        rig.model.nextPage()
        assertSame(third, rig.model.state.value.overview, "Next on the last overview page does nothing")
        rig.model.startReadback()
        rig.model.toOverview()
        assertSame(third, rig.model.state.value.overview, "the overview starts no read-back and has no Overview")
        rig.model.previousPage()
        assertOverview(1)
        rig.model.back()
        assertOverview(0)
        val zeroth = assertNotNull(rig.model.state.value.overview)
        rig.model.back()
        assertSame(zeroth, rig.model.state.value.overview, "Back on the first overview page does nothing")
        rig.model.nextPage()
        rig.model.toInsertView()
        assertPage(rig, words, 4, 1, 1)
        assertTrue(assertNotNull(zeroth).all { wiped(it) })
    }

    @Test
    fun twentyFourWordsAreMarkedForTwoDevicesWithTheDeviceSwapBeforeWord13InEitherView() {
        val rig = Rig().toHome().toSkippedResult(DICE_99_24).toWords()
        val words = kcrWords(DICE_99_24)
        assertTrue(rig.model.state.value.twoDevices, "a 24-word seed is on two devices")
        for (index in 0 until INSERTS_PER_DEVICE) {
            assertPage(rig, words, index, 1, 2)
            if (index + 1 < INSERTS_PER_DEVICE) rig.model.nextPage()
        }
        val twelfth = insert(rig)
        rig.model.nextPage()
        val swap = rig.model.state.value
        assertEquals(Screen.DeviceSwap, swap.screen, "past word 12, the device swap first")
        assertFalse(isProtected(Screen.DeviceSwap))
        assertFalse(swap.gate)
        assertNull(swap.insert)
        assertTrue(wiped(twelfth))
        assertEquals(Screen.Words, swap.swapTo)
        rig.model.back()
        rig.model.nextPage()
        assertSame(swap, rig.model.state.value, "Back and Next on the device swap do nothing")
        rig.model.swapDone()
        assertEquals(Screen.Words, rig.screen)
        assertTrue(rig.model.state.value.gate, "the swap is Public, so word 13 comes through the gate again")
        rig.model.nextPage()
        assertTrue(rig.model.state.value.gate)
        rig.model.passGate()
        for (index in INSERTS_PER_DEVICE until words.size) {
            assertPage(rig, words, index, 2, 2)
            if (index + 1 < words.size) rig.model.nextPage()
        }
        // Paging back passes no swap: every page names its device.
        repeat(words.size - INSERTS_PER_DEVICE) { rig.model.previousPage() }
        assertPage(rig, words, 11, 1, 2)
        rig.model.nextPage()
        assertEquals(Screen.DeviceSwap, rig.screen)
        rig.model.swapDone()
        rig.model.passGate()
        assertPage(rig, words, 12, 2, 2)
        // The overview: from word 13's page, words 13-16; back to 9-12, no swap; on again, the swap first.
        rig.model.toOverview()
        assertEquals(3, rig.model.state.value.page)
        var inserts = assertNotNull(rig.model.state.value.overview)
        assertEquals("Words 13-16 · device 2 of 2", overviewHeader(inserts.first(), inserts.last()))
        rig.model.previousPage()
        assertEquals(Screen.WordsOverview, rig.screen)
        inserts = assertNotNull(rig.model.state.value.overview)
        assertEquals("Words 09-12 · device 1 of 2", overviewHeader(inserts.first(), inserts.last()))
        rig.model.nextPage()
        val overviewSwap = rig.model.state.value
        assertEquals(Screen.DeviceSwap, overviewSwap.screen)
        assertEquals(Screen.WordsOverview, overviewSwap.swapTo)
        assertTrue(inserts.all { wiped(it) })
        rig.model.swapDone()
        assertEquals(Screen.WordsOverview, rig.screen)
        assertTrue(rig.model.state.value.gate)
        rig.model.passGate()
        assertEquals(3, rig.model.state.value.page)
        for (page in 3 until 6) {
            inserts = assertNotNull(rig.model.state.value.overview)
            for ((at, insert) in inserts.withIndex()) {
                val index = page * OVERVIEW_WORDS + at
                assertEquals(2, insert.device)
                assertTrue(sameWord(insert, words[index]), "overview insert " + (index + 1) + " is not the vector's word")
            }
            rig.model.nextPage()
        }
        assertEquals(5, rig.model.state.value.page, "Next on the last overview page does nothing")
    }

    @Test
    fun aScannedProofsAndALoadedSnapshotsResultLeadToTheWordsToo() {
        // A scanned go-ahead QR: kcr.json's clear-empty-bucket for dice-99-words12.
        val scanned = Rig().toHome()
        scanned.begin(Mode.DiceOnly, Words.Twelve)
        for (face in kcrRolls(DICE_99_12)) {
            scanned.model.dicePick.replace(face)
            scanned.model.confirmRoll()
        }
        scanned.model.diceDone()
        scanned.worker.run()
        scanned.model.checkNow()
        scanned.model.showCheckQr()
        scanned.model.scanQr()
        scanned.model.onGoAheadText(kcrProofUr("clear-empty-bucket").uppercase())
        scanned.worker.run()
        assertEquals(Screen.CheckResult, scanned.screen)
        assertTrue(scanned.model.state.value.proof)
        scanned.toWords()
        assertPage(scanned, kcrWords(DICE_99_12), 0, 1, 1)
        assertTrue(Core.wipeAll() is Reply.Done)
        // A loaded snapshot without the seal: current-day-30, against dice-50-words12.
        val loaded = Rig().toHome().loadSnapshot("current-day-30")
        loaded.begin(Mode.DiceOnly, Words.Twelve)
        for (face in kcrRolls(DICE_50)) {
            loaded.model.dicePick.replace(face)
            loaded.model.confirmRoll()
        }
        loaded.model.diceDone()
        loaded.worker.run()
        loaded.model.checkNow()
        assertEquals(Screen.CheckResult, loaded.screen)
        assertNotNull(loaded.model.state.value.registry)
        loaded.toWords()
        assertPage(loaded, kcrWords(DICE_50), 0, 1, 1)
    }

    @Test
    fun aWordsPageIsCoveredAfter30SecondsAndHiddenWhileARecordingIsReported() {
        val rig = Rig().toHome().toSkippedResult(DICE_50).toWords()
        val shown = insert(rig)
        rig.clock.now += Timers.COVER_MILLIS - 1
        rig.model.tick()
        assertNull(rig.model.state.value.overlay)
        rig.clock.now += 1
        rig.model.tick()
        assertEquals(Overlay.Cover, rig.model.state.value.overlay, "30 s without input covers a Protected screen")
        rig.model.nextPage()
        assertSame(shown, rig.model.state.value.insert, "a press under the cover reaches nothing")
        rig.model.dismissOverlay()
        assertNull(rig.model.state.value.overlay)
        assertSame(shown, rig.model.state.value.insert, "the tap only uncovers it: the session and the page stay")
        assertFalse(wiped(shown))
        rig.model.recordingChanged(true)
        assertTrue(rig.model.state.value.recording, "the Protected wrapper draws its placeholder instead of the page")
        rig.model.nextPage()
        assertTrue(rig.model.state.value.recording, "and keeps it on the next page")
        rig.model.recordingChanged(false)
        assertEquals(1, rig.model.state.value.page)
    }

    @Test
    fun leavingTheAppOnTheWordsOrTheOverviewDiscardsAtOnceAndWipesTheirPages() {
        val rig = Rig().toHome().toSkippedResult(DICE_50).toWords()
        rig.model.nextPage()
        val shown = insert(rig)
        rig.model.appLeft()
        val away = rig.model.state.value
        rig.assertDiscarded(Notice.Left, "leaving a Protected screen discards at once (Q57 (b))")
        assertNull(away.insert)
        assertTrue(wiped(shown), "the page on show is wiped")
        assertNoSession("the discard took the slot home")
        rig.model.appReturned()
        rig.model.dismissOverlay()
        rig.model.startOffline()
        rig.toSkippedResult(DICE_50).toWords()
        rig.model.toOverview()
        val inserts = assertNotNull(rig.model.state.value.overview)
        rig.model.appLeft()
        rig.assertDiscarded(Notice.Left, "leaving the overview")
        assertTrue(inserts.all { wiped(it) }, "the overview's pages are wiped")
        assertNoSession("the discard took the slot home")
    }

    @Test
    fun goingOnlineOnTheWordsDiscardsAndWipeAllWipesThePagesOnShow() {
        val rig = Rig().toHome().toSkippedResult(DICE_50).toWords()
        val shown = insert(rig)
        rig.offline.set(false)
        rig.assertDiscarded(Notice.Offline)
        assertTrue(wiped(shown))
        assertNoSession("going online discarded the session")
        rig.offline.set(true)
        rig.model.startOffline()
        rig.toSkippedResult(DICE_50).toWords()
        val page = insert(rig)
        rig.model.wipeAll()
        assertTrue(wiped(page), "wipeAll wipes the page on show")
        assertNoSession("wipeAll emptied the slot")
        val second = Rig().toHome().toSkippedResult(DICE_50).toWords()
        second.model.toOverview()
        val inserts = assertNotNull(second.model.state.value.overview)
        second.model.wipeAll()
        assertTrue(inserts.all { wiped(it) }, "wipeAll wipes the overview's pages")
    }

    @Test
    fun theInsertViewsTextsAreThePis() {
        val rig = Rig().toHome().toSkippedResult(DICE_99_24).toWords()
        val first = insert(rig)
        assertEquals("Insert 01 · device 1 of 2", insertHeader(first))
        assertEquals("Read back insert 01 · device 1 of 2", readbackHeader(first))
        assertEquals("Insert 01 does not match · device 1 of 2", mismatchHeader(first))
        assertEquals("Face 6: the engraved number 01", faceSixText(first.sequence))
        assertTrue(seedbookText(first.seedbook) == "SeedBook " + brailleInsert(kcrWords(DICE_99_24)[0]).number.toString().padStart(4, '0'))
        val line = overviewLine(first)
        assertTrue(line.length == 16 && line.startsWith("01 ") && line.endsWith(seedbookText(first.seedbook).removePrefix("SeedBook ")))
        // The SeedBook cross-check numbers (CLAUDE.md: ABANDON 0001, ACT 0020, ACTION 0021, METAL 1121, WIRE 2018, ZOO 2048).
        for ((word, number) in listOf("abandon" to 1, "act" to 20, "action" to 21, "metal" to 1121, "wire" to 2018, "zoo" to 2048)) {
            assertEquals(number, brailleInsert(word).number, word)
            assertEquals("SeedBook " + number.toString().padStart(4, '0'), seedbookText(number))
        }
        val act = brailleInsert("act")
        assertEquals(listOf('a', 'c', 't', null, null), act.faces, "act: a c t and two blank faces")
        repeat(12) { rig.model.nextPage() }
        rig.model.swapDone()
        rig.model.passGate()
        assertEquals("Insert 13 · device 2 of 2", insertHeader(insert(rig)))
        assertEquals("Face 6: the engraved number 01", faceSixText(insert(rig).sequence))
    }

    private companion object {
        /** vectors/kcr.json's dice gate seeds. */
        const val DICE_50 = "dice-50-words12"
        const val DICE_99_12 = "dice-99-words12"
        const val DICE_99_24 = "dice-99-words24"
    }
}
