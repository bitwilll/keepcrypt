package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Freshness
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.QrMatrix
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Words
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Every CeremonyModel transition of the collision check (tasks/todo.md, M5 group 16; lead decisions
 * M5-48, M5-54 and M5-55), over the real slot through Core and the host library, long calls held on the
 * test's worker: the dice's Done at the minimum (finish behind "Working...", then the prompt, whose
 * state holds no seal); Skip, Match found and Cannot check each confirmed on its own screen, and Back
 * there keeping the check; Check now's seal card with its seal, its next page the check QR with the
 * checker's answers and Back between them keeping the same check QR; a wrong typed code refused
 * with the check, its nonce and the actions kept; Match found to the collision result with the
 * destroyed seed's seal (Back doing nothing there), the report QR behind the privacy gate and "Add
 * fresh entropy" at 99 rolls; Cannot check to "Start again" at the normal minimum, and at 99 when the
 * session was itself the restart after a collision; leaving the app on the report (the first Protected
 * screen) discarding at once; the model's end (wipeAll) wiping the typed code and the QR codes on show;
 * and with a loaded snapshot the automatic check, a short call with nothing on the worker, its result
 * at once after Check now with the seal: its collision before any words, and each freshness warning on
 * vectors/kcr.json's own date. The seed is kcr.json's public gate seed dice-50-words12 (the snapshot
 * with-dice-50 holds its seal; the others do not), its rolls picked on the pad as the dice screen does.
 * The right typed code needs the check QR read, which the emulator's CheckTest does with ZXing. Where
 * the slot is, is read from the slot itself: the seal is offered once sealed, the check QR only while
 * checking, a word page once the words are available, the collision report only at the restart after a
 * collision, and the self-test only at home (each other call halts, which would fail every later
 * check). Each test leaves the slot at home (wipeAll after it).
 */
class CheckScreensTest {
    @AfterTest
    fun emptyTheSlot() {
        assertTrue(Core.wipeAll() is Reply.Done)
    }

    private fun <T> done(reply: Reply<T>, what: String): T = when (reply) {
        is Reply.Done -> reply.value
        else -> fail(what + " was not done")
    }

    /** The slot is at home and empty: no session, nothing waiting at a restart. */
    private fun assertNoSession(message: String) {
        assertTrue(Core.selfTest() is Reply.Done, message)
    }

    /** The words are available: a word page is offered (the page wiped at once). */
    private fun assertWordsAvailable(message: String) {
        done(Core.wordPage(1), message).wipe()
    }

    /** Whether a and b hold the same modules (the same text: the same T and nonce for a check QR). */
    private fun sameModules(a: QrMatrix, b: QrMatrix): Boolean =
        a.side == b.side && (0 until a.side).all { y -> (0 until a.side).all { x -> a.isDark(x, y) == b.isDark(x, y) } }

    /** Whether matrix was wiped: no dark module left. */
    private fun blank(matrix: QrMatrix): Boolean = (0 until matrix.side).all { y -> (0 until matrix.side).none { x -> matrix.isDark(x, y) } }

    private fun diceLine(rig: Rig): String {
        val dice = assertNotNull(rig.model.state.value.dice, "the dice screen's counts")
        return diceText(dice.rolls, dice.minimum, dice.millibits)
    }

    /** On the dice: rolls (each a face 1-6) picked on the pad and confirmed, then Done and its long call: the check prompt. */
    private fun finishDice(rig: Rig, rolls: String) {
        for (face in rolls) {
            assertTrue(rig.model.dicePick.replace(face))
            rig.model.confirmRoll()
        }
        rig.model.diceDone()
        assertEquals(Screen.Working, rig.screen, "finish, a long call behind Working")
        rig.worker.run()
        assertEquals(Screen.CheckPrompt, rig.screen)
    }

    /** From Home: a dice-only seed of 12 words with dice-50-words12's rolls, through Done to the check prompt. */
    private fun sealed(rig: Rig): Rig {
        rig.begin(Mode.DiceOnly, Words.Twelve)
        finishDice(rig, DICE_50_ROLLS)
        return rig
    }

    /** A new model through Done and Check now, with no snapshot loaded: the seal card. */
    private fun atSealCard(): Rig {
        val rig = sealed(Rig().toHome())
        rig.model.checkNow()
        assertEquals(Screen.SealCard, rig.screen)
        return rig
    }

    /** A new model through Done, Check now and the seal card's Show check QR: the check QR and its actions. */
    private fun atCheckQr(): Rig {
        val rig = atSealCard()
        rig.model.showCheckQr()
        assertEquals(Screen.CheckQr, rig.screen)
        return rig
    }

    /** From the check QR: Match found, confirmed, then the report past its gate. */
    private fun toReport(rig: Rig) {
        rig.model.matchFound()
        rig.model.matchFoundConfirmed()
        assertEquals(Screen.Collision, rig.screen)
        rig.model.showReport()
        assertEquals(Screen.CollisionReport, rig.screen)
    }

    @Test
    fun doneFinishesAtTheMinimumBehindWorkingThenThePromptHoldsNoSeal() {
        val rig = Rig().toHome().begin(Mode.DiceOnly, Words.Twelve)
        for (face in DICE_50_ROLLS.dropLast(1)) {
            rig.model.dicePick.replace(face)
            rig.model.confirmRoll()
        }
        assertEquals("49 / 50 rolls, 126.6 bits", diceLine(rig))
        rig.model.diceDone()
        assertEquals(Screen.Dice, rig.screen, "Done below the minimum does nothing (core would halt)")
        assertEquals(0, rig.worker.waiting)
        assertTrue(Core.diceProgress() is Reply.Done, "still rolling")
        rig.model.dicePick.replace(DICE_50_ROLLS.last())
        rig.model.confirmRoll()
        rig.model.diceDone()
        assertEquals(Screen.Working, rig.screen, "finish, a long call")
        assertEquals(1, rig.worker.waiting)
        rig.worker.run()
        assertEquals(Screen.CheckPrompt, rig.screen)
        assertNull(rig.model.state.value.seal, "the prompt shows no seal: the Seal ID shows from Check now on (M5-55)")
        val seal = done(Core.seal(), "the seal, once sealed")
        assertEquals(DICE_50_SEAL_ID, seal.sealId, "the rolls picked on the pad made dice-50-words12's seed")
        assertNull(rig.model.state.value.dice, "the counts leave with the dice screen")
        // A press left over from the dice does nothing.
        rig.model.diceDone()
        assertEquals(Screen.CheckPrompt, rig.screen)
        assertEquals(0, rig.worker.waiting)
    }

    @Test
    fun skipIsConfirmedOnItsOwnScreenWhoseBackKeepsThePrompt() {
        val rig = sealed(Rig().toHome())
        rig.model.skip()
        assertEquals(Screen.SkipConfirm, rig.screen)
        assertNull(rig.model.state.value.seal, "Skip's confirm shows no seal")
        rig.model.back()
        assertEquals(Screen.CheckPrompt, rig.screen, "Back on Skip's confirm (its button or the system's)")
        assertNull(rig.model.state.value.seal, "the prompt shows no seal")
        assertEquals(DICE_50_SEAL_ID, done(Core.seal(), "the seal, still sealed").sealId)
        rig.model.skip()
        rig.model.skipConfirmed()
        val state = rig.model.state.value
        assertEquals(Screen.CheckResult, state.screen)
        assertTrue(state.skipped, "the result says the check was skipped")
        assertNull(state.seal, "Skip's result names no seal: the Seal ID shows from Check now on")
        assertNull(state.registry)
        assertWordsAvailable("Skip made the words available")
        rig.model.back()
        rig.model.checkNow()
        assertEquals(Screen.CheckResult, rig.screen, "nothing leaves the result before the words come (commit 19)")
    }

    @Test
    fun checkNowWithNoSnapshotShowsTheSealCardWithTheCheckRequest() {
        val rig = atSealCard()
        assertEquals(0, rig.worker.waiting, "no long call without a snapshot")
        val state = rig.model.state.value
        assertEquals(DICE_50_SEAL_ID, state.seal?.sealId, "the seal card shows the seal, from Check now on")
        val request = assertNotNull(state.checkRequest, "the check QR")
        val core = done(Core.checkRequest(), "the check request, while checking")
        assertTrue(sameModules(request, core), "the card shows core's check request")
        core.wipe()
        // The check binds: Back does nothing, and Skip is gone.
        rig.model.back()
        rig.model.skip()
        assertEquals(Screen.SealCard, rig.screen)
        assertTrue(Core.checkRequest() is Reply.Done, "still checking")
    }

    @Test
    fun theCheckQrIsTheSealCardsNextPageWhoseBackKeepsTheSameCheckQr() {
        val rig = atSealCard()
        val request = assertNotNull(rig.model.state.value.checkRequest, "the seal card holds the check QR")
        // The checker's answers are the check QR's, not the seal card's: each does nothing here.
        rig.model.scanQr()
        rig.model.typeCode()
        rig.model.matchFound()
        rig.model.cannotCheck()
        assertEquals(Screen.SealCard, rig.screen, "the seal card offers none of the checker's answers")
        rig.model.showCheckQr()
        val page = rig.model.state.value
        assertEquals(Screen.CheckQr, page.screen, "Show check QR: the seal card's next page")
        assertSame(request, page.checkRequest, "the check QR page draws the seal card's check QR")
        assertEquals(DICE_50_SEAL_ID, page.seal?.sealId, "and keeps the seal for the page before")
        rig.model.showCheckQr()
        assertEquals(Screen.CheckQr, rig.screen, "Show check QR off the seal card does nothing")
        rig.model.back()
        val back = rig.model.state.value
        assertEquals(Screen.SealCard, back.screen, "Back on the check QR: the seal card")
        assertSame(request, back.checkRequest, "the same check QR")
        assertEquals(DICE_50_SEAL_ID, back.seal?.sealId)
        assertFalse(blank(request), "and whole")
        rig.model.showCheckQr()
        assertSame(request, rig.model.state.value.checkRequest, "the same check QR again")
        // Each of its actions opens its screen, whose Back returns to the check QR with the same check QR.
        val actions = listOf(
            Triple("Scan go-ahead QR", rig.model::scanQr, Screen.Scan),
            Triple("Type go-ahead code", rig.model::typeCode, Screen.CodeEntry),
            Triple("Match found", rig.model::matchFound, Screen.MatchFoundConfirm),
            Triple("Cannot check", rig.model::cannotCheck, Screen.CannotCheckConfirm),
        )
        for ((name, press, screen) in actions) {
            press()
            assertEquals(screen, rig.screen, name)
            assertSame(request, rig.model.state.value.checkRequest, name + " keeps the check QR")
            rig.model.back()
            assertEquals(Screen.CheckQr, rig.screen, "Back from " + name + "'s screen")
            assertSame(request, rig.model.state.value.checkRequest, "the same check QR after " + name)
        }
        assertFalse(blank(request), "the check QR is whole after every page")
        val core = done(Core.checkRequest(), "the check, still open")
        assertTrue(sameModules(request, core), "no page made a core call: the same check and nonce")
        core.wipe()
        assertEquals(0, rig.worker.waiting, "and no long call")
    }

    @Test
    fun aWrongTypedCodeIsRefusedAndTheCheckItsNonceAndActionsStay() {
        val rig = atCheckQr()
        val request = assertNotNull(rig.model.state.value.checkRequest)
        rig.model.typeCode()
        assertEquals(Screen.CodeEntry, rig.screen)
        assertSame(request, rig.model.state.value.checkRequest, "the code entry keeps the check QR")
        rig.press("0000000")
        assertEquals(7, rig.model.goAheadCode.length)
        rig.model.codeDone()
        assertEquals(Screen.CodeEntry, rig.screen)
        assertFalse(rig.model.state.value.codeRefused, "Done with 7 symbols does nothing")
        assertEquals(7, rig.model.goAheadCode.length)
        rig.press('0')
        assertEquals(8, rig.model.goAheadCode.length)
        rig.model.codeDone()
        val refused = rig.model.state.value
        assertEquals(Screen.CodeEntry, refused.screen, "a wrong code returns to its screen")
        assertTrue(refused.codeRefused, "the code entry says it was refused")
        assertEquals(0, rig.model.goAheadCode.length, "the refused code was handed to core, the entry emptied (its copy's wipe is PadsTest's)")
        assertTrue(rig.model.goAheadCode.zeroPastLength(), "and its bytes zeroed")
        val core = done(Core.checkRequest(), "the check, still open")
        assertTrue(sameModules(request, core), "the same check and nonce in core")
        core.wipe()
        rig.model.back()
        val back = rig.model.state.value
        assertEquals(Screen.CheckQr, back.screen)
        assertFalse(back.codeRefused)
        assertSame(request, back.checkRequest, "the same check QR")
        assertFalse(blank(request), "and whole")
        rig.model.matchFound()
        assertEquals(Screen.MatchFoundConfirm, rig.screen, "the check QR's actions stay")
    }

    @Test
    fun backOnEachConfirmScreenAndTheCodeEntryKeepsTheCheck() {
        val rig = atCheckQr()
        val request = assertNotNull(rig.model.state.value.checkRequest)
        rig.model.matchFound()
        assertEquals(Screen.MatchFoundConfirm, rig.screen)
        rig.model.back()
        assertEquals(Screen.CheckQr, rig.screen, "Back on Match found's confirm")
        rig.model.cannotCheck()
        assertEquals(Screen.CannotCheckConfirm, rig.screen)
        rig.model.back()
        assertEquals(Screen.CheckQr, rig.screen, "Back on Cannot check's confirm")
        rig.model.typeCode()
        rig.press("ABC")
        rig.model.back()
        assertEquals(Screen.CheckQr, rig.screen, "Back on the code entry")
        assertEquals(0, rig.model.goAheadCode.length, "the typed code is wiped")
        assertTrue(rig.model.goAheadCode.zeroPastLength())
        assertSame(request, rig.model.state.value.checkRequest)
        assertFalse(blank(request))
        val core = done(Core.checkRequest(), "the check, still open")
        assertTrue(sameModules(request, core), "no Back made a core call: the same check and nonce")
        core.wipe()
    }

    @Test
    fun matchFoundWipesTheSeedUnseenThenTheReportBehindTheGateThenAddFreshEntropyNeeds99Rolls() {
        val rig = atCheckQr()
        val request = assertNotNull(rig.model.state.value.checkRequest)
        rig.model.matchFound()
        rig.model.matchFoundConfirmed()
        val collision = rig.model.state.value
        assertEquals(Screen.Collision, collision.screen)
        assertEquals(DICE_50_SEAL_ID, collision.seal?.sealId, "the collision result draws the destroyed seed's seal")
        assertNull(collision.registry, "Match found, no snapshot")
        assertNull(collision.checkRequest)
        assertTrue(blank(request), "the check QR is wiped when the check ends")
        rig.model.back()
        assertEquals(Screen.Collision, rig.screen, "Back does nothing on the collision result")
        done(Core.collisionReport(), "the report, at the restart after a collision").wipe()
        rig.model.showReport()
        val gated = rig.model.state.value
        assertEquals(Screen.CollisionReport, gated.screen)
        assertTrue(gated.gate, "the privacy gate stands before the Protected report")
        val report = assertNotNull(gated.report)
        val core = done(Core.collisionReport(), "the report")
        assertTrue(sameModules(report, core), "the screen shows core's report")
        core.wipe()
        rig.model.addFreshEntropy()
        assertEquals(0, rig.worker.waiting, "behind the gate, Add fresh entropy reaches nothing")
        rig.model.passGate()
        assertFalse(rig.model.state.value.gate)
        rig.model.back()
        assertEquals(Screen.CollisionReport, rig.screen, "Back does nothing on the report")
        rig.model.addFreshEntropy()
        assertEquals(Screen.Working, rig.screen, "core's start from the kept Wiped, a long call")
        rig.worker.run()
        assertEquals(Screen.Dice, rig.screen, "the same length and mode: dice-only opens the dice")
        assertEquals("0 / 99 rolls, 0.0 bits", diceLine(rig), "99 rolls after a collision")
        assertTrue(blank(report), "the report QR is wiped when its screen leaves")
    }

    @Test
    fun cannotCheckStartsAgainAtTheNormalMinimumOrAt99WhenItWasTheRestartAfterACollision() {
        val rig = atCheckQr()
        rig.model.cannotCheck()
        rig.model.cannotCheckConfirmed()
        assertEquals(Screen.Working, rig.screen, "the seed wiped, core's start from the kept Wiped")
        rig.worker.run()
        assertEquals(Screen.Dice, rig.screen)
        assertEquals("0 / 50 rolls, 0.0 bits", diceLine(rig), "after Cannot check, the normal minimum")
        // Now a collision, its restart, and Cannot check on that restart: 99 rolls again.
        finishDice(rig, DICE_50_ROLLS)
        rig.model.checkNow()
        rig.model.showCheckQr()
        toReport(rig)
        rig.model.passGate()
        rig.model.addFreshEntropy()
        rig.worker.run()
        assertEquals("0 / 99 rolls, 0.0 bits", diceLine(rig))
        rig.roll(99)
        rig.model.diceDone()
        rig.worker.run()
        rig.model.checkNow()
        rig.model.showCheckQr()
        rig.model.cannotCheck()
        rig.model.cannotCheckConfirmed()
        rig.worker.run()
        assertEquals(Screen.Dice, rig.screen)
        assertEquals("0 / 99 rolls, 0.0 bits", diceLine(rig), "the restart after a collision could not be checked: 99 stays")
    }

    @Test
    fun leavingTheAppOnTheReportDiscardsAtOnceAndTheNextSeedStillNeeds99Rolls() {
        val rig = atCheckQr()
        toReport(rig)
        val report = assertNotNull(rig.model.state.value.report)
        rig.model.appLeft()
        val away = rig.model.state.value
        rig.assertDiscarded(Notice.Left, "leaving a Protected screen discards at once (Q57 (b))")
        assertEquals(Overlay.Cover, away.overlay)
        assertTrue(blank(report), "the report QR is wiped")
        assertNoSession("the discard took the slot home")
        rig.model.appReturned()
        rig.model.dismissOverlay()
        rig.model.startOffline()
        rig.begin(Mode.DiceOnly, Words.Twelve)
        assertEquals("0 / 99 rolls, 0.0 bits", diceLine(rig), "the kept Wiped outlived the discard")
    }

    @Test
    fun wipeAllWipesTheTypedCodeAndTheQrCodesOnShow() {
        // The holder's end on the code entry, with symbols typed: the typed code and the check QR it holds.
        val rig = atCheckQr()
        val request = assertNotNull(rig.model.state.value.checkRequest)
        rig.model.typeCode()
        rig.press("PBJ")
        assertEquals(3, rig.model.goAheadCode.length)
        rig.model.wipeAll()
        assertEquals(0, rig.model.goAheadCode.length, "wipeAll wipes the typed go-ahead code")
        assertTrue(rig.model.goAheadCode.zeroPastLength(), "and zeroes its bytes")
        assertTrue(blank(request), "wipeAll wipes the check QR on show")
        assertNoSession("wipeAll emptied the slot")
        // And past the report's gate: the collision-report QR, which carries the destroyed seed's seal code.
        val second = atCheckQr()
        toReport(second)
        second.model.passGate()
        val report = assertNotNull(second.model.state.value.report)
        second.model.wipeAll()
        assertTrue(blank(report), "wipeAll wipes the collision-report QR on show")
        assertNoSession("wipeAll emptied the slot at its restart")
    }

    @Test
    fun aLoadedSnapshotsCheckIsAShortCallThatFindsTheCollisionAtOnceBeforeAnyWords() {
        val rig = Rig().toHome().loadSnapshot("with-dice-50")
        sealed(rig)
        val ran = rig.worker.ran
        rig.model.checkNow()
        assertEquals(0, rig.worker.waiting, "nothing on the worker: the check is a short call on the main thread (M5-54)")
        assertEquals(ran, rig.worker.ran)
        val state = rig.model.state.value
        assertEquals(Screen.Collision, state.screen, "the collision at once after Check now, before any words")
        assertEquals(DICE_50_SEAL_ID, state.seal?.sealId, "the collision result draws the destroyed seed's seal")
        val registry = assertNotNull(state.registry, "the result shows the snapshot")
        assertEquals("Snapshot No. 4, dated 2026-03-01, 7 entries.", snapshotLine(registry))
        assertEquals(Freshness.Current, registry.freshness, "on kcr.json's own date")
        assertNull(freshnessWarning(registry.freshness))
        done(Core.collisionReport(), "the report: the slot waits at the restart, the words never made available").wipe()
    }

    @Test
    fun theAutomaticChecksResultShowsEachFreshnessWarningOnAFixedDate() {
        val cases = listOf(
            Triple("current-day-30", Freshness.Current, null),
            Triple("stale-day-31", Freshness.Stale, STALE_WARNING),
            Triple("future-day-1", Freshness.Future, FUTURE_WARNING),
        )
        for ((name, freshness, warning) in cases) {
            assertTrue(Core.wipeAll() is Reply.Done)
            val rig = Rig().toHome().loadSnapshot(name)
            sealed(rig)
            rig.model.checkNow()
            assertEquals(0, rig.worker.waiting, name + ": nothing on the worker (M5-54)")
            val state = rig.model.state.value
            assertEquals(Screen.CheckResult, state.screen, name + " does not hold the seal: the result at once after Check now")
            assertFalse(state.skipped)
            val registry = assertNotNull(state.registry, name)
            assertEquals(freshness, registry.freshness, name)
            assertEquals(warning, freshnessWarning(registry.freshness), name)
            assertEquals(
                "No collision for seal " + DICE_50_SEAL_ID + " as of " + registryDate(registry.date) + ".",
                clearText(assertNotNull(state.seal, name + ": the result names the Seal ID").sealId, registry),
                name,
            )
            assertWordsAvailable(name + "'s go-ahead made the words available")
            if (name == "stale-day-31") assertEquals("Snapshot No. 6, dated 2026-01-29, 6 entries.", snapshotLine(registry))
        }
    }

    @Test
    fun theResultTextsAndTheCodeAsShown() {
        assertEquals("2026-03-01", registryDate(20260301))
        assertEquals("0999-12-31", registryDate(9991231))
        assertEquals(
            "No collision for seal " + DICE_50_SEAL_ID + ", as of the date your checker showed.",
            clearText(DICE_50_SEAL_ID, null),
        )
        val code = crockfordPadEntry()
        assertEquals("____-____", codeShown(code))
        for (key in "PBJN") code.type(key)
        assertEquals("PBJN-____", codeShown(code))
        for (key in "YZY5") code.type(key)
        assertEquals("PBJN-YZY5", codeShown(code), "kcr.json's dice-50-words12 go-ahead, as the checker groups it")
    }

    private companion object {
        /** vectors/kcr.json's dice-50-words12: 50 rolls, 123456 repeated, and its Seal ID (StartScreensTest's too). */
        const val DICE_50_ROLLS = "12345612345612345612345612345612345612345612345612"
        const val DICE_50_SEAL_ID = "YVM9CPP3"
    }
}
