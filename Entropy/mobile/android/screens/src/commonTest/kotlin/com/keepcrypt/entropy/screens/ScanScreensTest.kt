package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Freshness
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.QrMatrix
import com.keepcrypt.entropy.ffi.Refusal
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
 * The scan screen and a scanned go-ahead QR through the CeremonyModel (tasks/todo.md, M5 group 16,
 * commit 18; lead decisions M5-54 and M5-55), over the real slot through Core and the host library, long
 * calls held on the test's worker. The scanner is the platform's (camera/GoAheadScanner.kt, whose frame
 * code :app's GoAheadFrameTest runs on canned frames), so its reports come here as the scan screen hands
 * them on: its text to onGoAheadText, a stop to scanStopped. The seal card's "Scan go-ahead QR" opens the
 * scan screen with the seal and the same check QR, and Back and "Type go-ahead code" leave it with no
 * core call; a stop is said on the scan screen alone. vectors/kcr.json's two go-ahead QR texts (their ur
 * fields, upper case as the P4 PNGs carry them, lead decision M5-42): clear-empty-bucket's passes
 * dice-99-words12's check behind "Working...", its result naming the Seal ID with the proof's date, the
 * entries in the seal's bucket (0) and, on a day in M5, the Stale warning, the words made available;
 * collision-dice-50's destroys dice-50-words12's seed unseen, the collision result with its bucket's 1
 * entry and the seal, then the report and 99 rolls. A text core refuses (no UR, another seal's bucket)
 * returns to the scan screen with the refusal and the same check, which a later text still answers; a
 * text off the scan screen does nothing. A loaded snapshot's result is no proof. Each test leaves the
 * slot at home (wipeAll after it).
 */
class ScanScreensTest {
    @AfterTest
    fun emptyTheSlot() {
        assertTrue(Core.wipeAll() is Reply.Done)
    }

    private fun <T> done(reply: Reply<T>, what: String): T = when (reply) {
        is Reply.Done -> reply.value
        else -> fail(what + " was not done")
    }

    /** Whether a and b hold the same modules (the same text: the same T and nonce for a check QR). */
    private fun sameModules(a: QrMatrix, b: QrMatrix): Boolean =
        a.side == b.side && (0 until a.side).all { y -> (0 until a.side).all { x -> a.isDark(x, y) == b.isDark(x, y) } }

    /** Whether matrix was wiped: no dark module left. */
    private fun blank(matrix: QrMatrix): Boolean = (0 until matrix.side).all { y -> (0 until matrix.side).none { x -> matrix.isDark(x, y) } }

    /** From Home: a dice-only seed of 12 words with rolls (each a face 1-6), its Done and Check now: the seal card. */
    private fun atSealCard(rig: Rig, rolls: String): Rig {
        rig.begin(Mode.DiceOnly, Words.Twelve)
        for (face in rolls) {
            assertTrue(rig.model.dicePick.replace(face))
            rig.model.confirmRoll()
        }
        rig.model.diceDone()
        rig.worker.run()
        assertEquals(Screen.CheckPrompt, rig.screen)
        rig.model.checkNow()
        assertEquals(Screen.SealCard, rig.screen)
        return rig
    }

    /** From the seal card: the scan screen, its scanner reporting nothing yet. */
    private fun toScan(rig: Rig): Rig {
        rig.model.scanQr()
        assertEquals(Screen.Scan, rig.screen)
        return rig
    }

    @Test
    fun scanGoAheadQrOpensTheScanScreenWithTheCheckKeptAndBackAndTypeCodeLeaveIt() {
        val rig = atSealCard(Rig().toHome(), DICE_50_ROLLS)
        val request = assertNotNull(rig.model.state.value.checkRequest)
        toScan(rig)
        val scan = rig.model.state.value
        assertEquals(DICE_50_SEAL_ID, scan.seal?.sealId, "the scan screen keeps the seal")
        assertSame(request, scan.checkRequest, "and the check QR: the same check and nonce")
        assertNull(scan.scanStop)
        assertNull(scan.scanRefusal)
        assertEquals(SCANNING, scanLine(scan))
        assertEquals(0, rig.worker.waiting, "opening the scan screen calls no core")
        rig.model.back()
        assertEquals(Screen.SealCard, rig.screen, "Back on the scan screen (its button or the system's)")
        assertSame(request, rig.model.state.value.checkRequest)
        assertFalse(blank(request), "the check QR is whole")
        toScan(rig)
        rig.model.typeCode()
        assertEquals(Screen.CodeEntry, rig.screen, "the scan screen's Type go-ahead code")
        assertSame(request, rig.model.state.value.checkRequest)
        rig.model.back()
        assertEquals(Screen.SealCard, rig.screen, "the code entry's Back goes to the seal card")
        val core = done(Core.checkRequest(), "the check, still open")
        assertTrue(sameModules(request, core), "no core call: the same check and nonce")
        core.wipe()
    }

    @Test
    fun theScannersStopIsSaidOnTheScanScreenOnly() {
        val rig = atSealCard(Rig().toHome(), DICE_50_ROLLS)
        rig.model.scanStopped(ScanStop.Refused)
        assertEquals(Screen.SealCard, rig.screen)
        assertNull(rig.model.state.value.scanStop, "a stop off the scan screen says nothing")
        toScan(rig)
        rig.model.scanStopped(ScanStop.Missing)
        assertEquals(ScanStop.Missing, rig.model.state.value.scanStop)
        assertEquals(SCAN_MISSING, scanLine(rig.model.state.value))
        rig.model.scanStopped(ScanStop.Failed)
        assertEquals(ScanStop.Missing, rig.model.state.value.scanStop, "the first stop is said: the scan ended there")
        rig.model.back()
        assertNull(rig.model.state.value.scanStop, "Back leaves the stop behind")
        toScan(rig)
        assertNull(rig.model.state.value.scanStop, "a new scan screen scans again (its scanner asks for the camera again)")
        rig.model.scanStopped(ScanStop.Refused)
        assertEquals(SCAN_REFUSED, scanLine(rig.model.state.value))
        rig.model.typeCode()
        assertEquals(Screen.CodeEntry, rig.screen, "a refusal leaves the typed code")
    }

    @Test
    fun theScannedClearEmptyBucketQrPassesTheCheckWithItsDateItsBucketsEntriesAndTheStaleWarning() {
        val rig = toScan(atSealCard(Rig().toHome(), DICE_99_ROLLS))
        assertEquals(DICE_99_SEAL_ID, rig.model.state.value.seal?.sealId)
        val request = assertNotNull(rig.model.state.value.checkRequest)
        rig.date.day = M5_DAY
        rig.model.onGoAheadText(kcrProofUr("clear-empty-bucket").uppercase())
        assertEquals(Screen.Working, rig.screen, "the proof's check, a long call behind Working")
        assertEquals(1, rig.worker.waiting)
        rig.worker.run()
        val state = rig.model.state.value
        assertEquals(Screen.CheckResult, state.screen)
        assertTrue(state.proof, "the result's header is the proof's")
        assertFalse(state.skipped)
        val registry = assertNotNull(state.registry)
        assertEquals(2UL, registry.number)
        assertEquals(20260301, registry.date)
        assertEquals(0L, registry.count, "the entries in this seal's bucket, not the snapshot's seals")
        assertEquals(Freshness.Stale, registry.freshness, "a snapshot dated 2026-03-01, on a day in M5")
        assertEquals(STALE_WARNING, freshnessWarning(registry.freshness))
        assertEquals("Proof from snapshot No. 2, dated 2026-03-01: 0 entries in this seal's bucket.", proofLine(registry))
        assertEquals(
            "No collision for seal " + DICE_99_SEAL_ID + " as of 2026-03-01.",
            clearText(assertNotNull(state.seal, "the result names the Seal ID").sealId, registry),
        )
        assertTrue(blank(request), "the check QR is wiped when the check ends")
        done(Core.wordPage(1), "a word page: the go-ahead made the words available").wipe()
    }

    @Test
    fun theScannedCollisionDice50QrDestroysTheSeedUnseenAndTheRestartNeeds99Rolls() {
        val rig = toScan(atSealCard(Rig().toHome(), DICE_50_ROLLS))
        rig.model.onGoAheadText(kcrProofUr("collision-dice-50").uppercase())
        assertEquals(Screen.Working, rig.screen)
        rig.worker.run()
        val state = rig.model.state.value
        assertEquals(Screen.Collision, state.screen, "the collision, before any words")
        assertTrue(state.proof)
        assertEquals(DICE_50_SEAL_ID, state.seal?.sealId, "the collision result draws the destroyed seed's seal")
        val registry = assertNotNull(state.registry)
        assertEquals(4UL, registry.number)
        assertEquals(1L, registry.count, "the one entry in this seal's bucket, its own tag")
        assertEquals(Freshness.Current, registry.freshness, "on kcr.json's own date")
        assertNull(freshnessWarning(registry.freshness))
        assertEquals("Proof from snapshot No. 4, dated 2026-03-01: 1 entry in this seal's bucket.", proofLine(registry))
        done(Core.collisionReport(), "the report: the slot waits at the restart, the words never made available").wipe()
        rig.model.showReport()
        assertEquals(Screen.CollisionReport, rig.screen)
        rig.model.passGate()
        rig.model.addFreshEntropy()
        rig.worker.run()
        assertEquals(Screen.Dice, rig.screen)
        val dice = assertNotNull(rig.model.state.value.dice)
        assertEquals("0 / 99 rolls, 0.0 bits", diceText(dice.rolls, dice.minimum, dice.millibits), "99 rolls after a collision")
    }

    @Test
    fun aTextCoreRefusesReturnsToTheScanScreenWithTheSameCheckAndATextOffItDoesNothing() {
        val rig = atSealCard(Rig().toHome(), DICE_50_ROLLS)
        val request = assertNotNull(rig.model.state.value.checkRequest)
        rig.model.onGoAheadText(kcrProofUr("collision-dice-50").uppercase())
        assertEquals(Screen.SealCard, rig.screen, "a text off the scan screen does nothing")
        assertEquals(0, rig.worker.waiting, "and calls no core")
        toScan(rig)
        rig.model.onGoAheadText("not a ur")
        assertEquals(Screen.Working, rig.screen)
        rig.worker.run()
        val notUr = rig.model.state.value
        assertEquals(Screen.Scan, notUr.screen, "a refused text returns to the scan screen")
        assertEquals(Refusal.NotUr, notUr.scanRefusal)
        assertEquals(SCAN_NOT_ACCEPTED, scanLine(notUr))
        assertSame(request, notUr.checkRequest, "the same check QR")
        assertFalse(blank(request), "whole")
        rig.model.onGoAheadText(kcrProofUr("clear-empty-bucket").uppercase())
        rig.worker.run()
        val wrongBucket = rig.model.state.value
        assertEquals(Screen.Scan, wrongBucket.screen)
        assertEquals(Refusal.WrongBucket, wrongBucket.scanRefusal, "another seal's bucket")
        val core = done(Core.checkRequest(), "the check, still open")
        assertTrue(sameModules(request, core), "the same check and nonce in core")
        core.wipe()
        rig.model.onGoAheadText(kcrProofUr("collision-dice-50").uppercase())
        rig.worker.run()
        assertEquals(Screen.Collision, rig.screen, "the check stayed open for its own go-ahead QR")
    }

    @Test
    fun aLoadedSnapshotsResultIsNoProof() {
        val rig = Rig().toHome()
        rig.model.snapshotLoaded(done(Core.loadSnapshot(rig.date.today(), kcrSnapshot("with-dice-50")), "with-dice-50 loads"))
        checkedNowWithTheSnapshot(rig)
        val state = rig.model.state.value
        assertEquals(Screen.Collision, state.screen)
        assertFalse(state.proof, "a loaded snapshot's count is its seals")
        assertEquals("Snapshot No. 4, dated 2026-03-01, 7 entries.", snapshotLine(assertNotNull(state.registry)))
    }

    @Test
    fun theScanScreensLines() {
        assertEquals(SCANNING, scanLine(UiState(Screen.Scan)))
        assertEquals(SCAN_REFUSED, scanLine(UiState(Screen.Scan, scanStop = ScanStop.Refused)))
        assertEquals(SCAN_MISSING, scanLine(UiState(Screen.Scan, scanStop = ScanStop.Missing)))
        assertEquals(SCAN_FAILED, scanLine(UiState(Screen.Scan, scanStop = ScanStop.Failed)))
        assertEquals(SCAN_NO_REGISTRY_KEY, scanLine(UiState(Screen.Scan, scanRefusal = Refusal.NoRegistryKey)))
        assertEquals(SCAN_NOT_ACCEPTED, scanLine(UiState(Screen.Scan, scanRefusal = Refusal.WrongBucket)))
        assertEquals(SCAN_NOT_ACCEPTED, scanLine(UiState(Screen.Scan, scanStop = ScanStop.Missing, scanRefusal = Refusal.NotUr)))
    }

    /** From Home with a loaded snapshot: dice-50-words12's rolls, Done and Check now, which runs the check at once. */
    private fun checkedNowWithTheSnapshot(rig: Rig) {
        rig.begin(Mode.DiceOnly, Words.Twelve)
        for (face in DICE_50_ROLLS) {
            rig.model.dicePick.replace(face)
            rig.model.confirmRoll()
        }
        rig.model.diceDone()
        rig.worker.run()
        rig.model.checkNow()
    }

    private companion object {
        /** vectors/kcr.json's dice-50-words12 and dice-99-words12: their rolls and Seal IDs. */
        const val DICE_50_ROLLS = "12345612345612345612345612345612345612345612345612"
        const val DICE_50_SEAL_ID = "YVM9CPP3"
        const val DICE_99_ROLLS =
            "654321654321654321654321654321654321654321654321654321654321654321654321654321654321654321654321654"
        const val DICE_99_SEAL_ID = "9FHYMCQA"

        /** A day in M5 (2026-10-17), when kcr.json's proofs, dated 2026-03-01, read Stale (:core-ffi's M5_DAY). */
        const val M5_DAY = 20261017
    }
}
