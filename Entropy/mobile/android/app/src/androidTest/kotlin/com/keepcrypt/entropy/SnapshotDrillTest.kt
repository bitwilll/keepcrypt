package com.keepcrypt.entropy

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Ui.START_SECONDS
import com.keepcrypt.entropy.Ui.await
import com.keepcrypt.entropy.Ui.awaitText
import com.keepcrypt.entropy.Ui.find
import com.keepcrypt.entropy.Ui.grantCamera
import com.keepcrypt.entropy.Ui.on
import com.keepcrypt.entropy.Ui.roll
import com.keepcrypt.entropy.Ui.shown
import com.keepcrypt.entropy.Ui.tap
import com.keepcrypt.entropy.Ui.toHome
import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Freshness
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.screens.COLLISION_FOUND
import com.keepcrypt.entropy.screens.SCAN_MISSING
import com.keepcrypt.entropy.screens.STALE_WARNING
import com.keepcrypt.entropy.screens.ScanStop
import com.keepcrypt.entropy.screens.Screen
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The owner's P4 drill on the phone (tasks/todo.md, M5 group 16), run by scripts/android-instrument.sh
 * on the test-registry app, the only one that trusts the test registry key, in the API 31 and 36 legs,
 * through UI Automator as FlowTest is (Ui).
 *
 * The scanned go-ahead QRs (P4's first and third steps; commit 18): vectors/kcr.json's two go-ahead QR
 * texts, clear-empty-bucket's and collision-dice-50's (their ur fields, upper case as the P4 PNGs carry
 * them, lead decision M5-42), each on a dice-only seed of the gate seed it was made for (dice-99-words12
 * and dice-50-words12): Check now's seal card with its Seal ID, its check QR's "Scan go-ahead QR" with
 * CAMERA granted from the shell (CaptureTest, which runs first, refused the prompt), where the scan screen
 * says the emulator has no camera (its AVD has none), then the text handed to the model's onGoAheadText,
 * where the scanner's first text goes. The check runs behind "Working...": clear-empty-bucket passes it,
 * the result naming the Seal ID with the proof's date, the entries in the seal's bucket (0) and the Stale
 * warning (the proof's snapshot is dated 2026-03-01), with the words made available; collision-dice-50
 * gives the collision result, with the proof's line (1 entry) and the Stale warning and the destroyed
 * seed's Seal ID drawn, before any words, then the report behind the privacy gate and 99 rolls.
 *
 * The duplicate-seed drill with a loaded snapshot (P4's second step): vectors/kcr.json's snapshot
 * with-dice-50, signed by the test registry key, put in Downloads by the shell, is loaded through Home's
 * Load registry snapshot (lead decision M5-48): the system's open-document picker (DocumentsUI) gives it,
 * core verifies it behind "Working...", and its result shows its number, date and count and its Stale
 * warning (the snapshot is dated 2026-03-01), its header handed to the model; Done, and Home names it.
 * Then a dice-only seed of the public gate seed dice-50-words12, whose seal the snapshot holds:
 * the dice's Done, Check now, and the check runs on its own, a short call with no busy screen (lead
 * decision M5-54): the collision result at once, with the snapshot's number, date and its Stale warning
 * (the snapshot is dated 2026-03-01) and the destroyed seed's Seal ID drawn under them (lead decision
 * M5-55: the owner's P4 compares it there), before any words; the privacy gate, the collision-report QR
 * (read in-process: the destroyed seed's registration text), and "Add fresh entropy", whose dice need
 * 99 rolls.
 */
@RunWith(AndroidJUnit4::class)
class SnapshotDrillTest {
    @Test
    fun theScannedClearEmptyBucketQrPassesTheCheckWithItsDateBucketAndStaleWarning() {
        Capture.whileOffline {
            grantCamera()
            val activity = toHome()
            toScan(activity, 99, DICE_99_ROLLS, "99 / 50 rolls, 255.9 bits", DICE_99_SEAL_ID)
            onMain { activity.model.onGoAheadText(Checker.CLEAR_EMPTY_BUCKET_UR.uppercase()) }
            on(activity, Screen.CheckResult, START_SECONDS)
            awaitText("check_result_text", "No collision for seal $DICE_99_SEAL_ID as of 2026-03-01.")
            awaitText("proof_line", "Proof from snapshot No. 2, dated 2026-03-01: 0 entries in this seal's bucket.")
            awaitText("snapshot_warning", STALE_WARNING)
            assertTrue("the result's header is not the proof's", onMain { activity.model.state.value.proof })
            done(Core.wordPage(1), "a word page: the go-ahead made the words available").wipe()
            pass(
                "the scanned clear-empty-bucket QR: dice-99-words12's check passed ($DICE_99_SEAL_ID, as of 2026-03-01), " +
                    "0 entries in this seal's bucket, the Stale warning, the words available",
            )
            finish(activity)
        }
    }

    @Test
    fun theScannedCollisionDice50QrDestroysTheSeedBeforeAnyWordsAndFreshEntropyNeeds99Rolls() {
        Capture.whileOffline {
            grantCamera()
            val activity = toHome()
            toScan(activity, 50, DICE_50_ROLLS, "50 / 50 rolls, 129.2 bits", DICE_50_SEAL_ID)
            onMain { activity.model.onGoAheadText(Checker.COLLISION_DICE_50_UR.uppercase()) }
            on(activity, Screen.Collision, START_SECONDS)
            awaitText("collision_text", COLLISION_FOUND)
            awaitText("proof_line", "Proof from snapshot No. 4, dated 2026-03-01: 1 entry in this seal's bucket.")
            awaitText("snapshot_warning", STALE_WARNING)
            assertTrue("the collision result does not draw dice-50-words12's Seal ID", shown(Screen.Collision, DICE_50_SEAL_ID))
            done(Core.collisionReport(), "the report: the slot waits at the restart, the words never made available").wipe()
            tap("show_report")
            find("privacy_gate")
            tap("pass_gate")
            await("past the gate", 10) { !onMain { activity.model.state.value.gate } }
            on(activity, Screen.CollisionReport)
            tap("add_fresh_entropy")
            on(activity, Screen.Dice, START_SECONDS)
            awaitText("dice_count", "0 / 99 rolls, 0.0 bits")
            pass(
                "the scanned collision-dice-50 QR: the collision before any words, 1 entry in this seal's bucket, the " +
                    "Stale warning and its Seal ID $DICE_50_SEAL_ID; the report behind the gate; Add fresh entropy: 0 / 99",
            )
            finish(activity)
        }
    }

    @Test
    fun aSnapshotLoadedThroughThePickerFindsTheCollisionBeforeAnyWordsAndFreshEntropyNeeds99Rolls() {
        Capture.whileOffline {
            Picker.putInDownloads(Checker.WITH_DICE_50_FILE, Checker.bytes(Checker.WITH_DICE_50_KCR))
            try {
                drillWithTheSnapshotPicked()
            } finally {
                Picker.removeFromDownloads(Checker.WITH_DICE_50_FILE)
            }
        }
    }

    /** The drill of aSnapshotLoadedThroughThePicker...: the snapshot picked from Downloads on Home, then the check that runs on its own. */
    private fun drillWithTheSnapshotPicked() {
        val activity = toHome()
        awaitText("home_snapshot", "No registry snapshot loaded")
        tap("load_snapshot")
        Picker.pick(Checker.WITH_DICE_50_FILE)
        on(activity, Screen.Snapshot, START_SECONDS)
        awaitText("snapshot_result", "Snapshot loaded")
        awaitText("snapshot_line", "Snapshot No. 4, dated 2026-03-01, 7 entries.")
        awaitText("snapshot_warning", STALE_WARNING)
        val header = onMain { activity.model.state.value.loaded } ?: throw AssertionError("the model holds no snapshot after its load")
        assertEquals(4UL, header.number)
        assertEquals(20260301, header.date)
        assertEquals(7L, header.count)
        assertEquals("a snapshot dated 2026-03-01 is Stale on the emulator's date", Freshness.Stale, header.freshness)
        tap("snapshot_done")
        on(activity, Screen.Home)
        awaitText("home_snapshot", "Snapshot No. 4, dated 2026-03-01")
        tap("dice_only_seed")
        on(activity, Screen.Length)
        tap("words_12")
        on(activity, Screen.Dice, START_SECONDS)
        roll(activity, 50, DICE_50_ROLLS)
        awaitText("dice_count", "50 / 50 rolls, 129.2 bits")
        tap("dice_done")
        on(activity, Screen.CheckPrompt, START_SECONDS)
        tap("check_now")
        on(activity, Screen.Collision)
        awaitText("collision_text", COLLISION_FOUND)
        awaitText("snapshot_line", "Snapshot No. 4, dated 2026-03-01, 7 entries.")
        awaitText("snapshot_warning", STALE_WARNING)
        assertTrue("the collision result does not draw dice-50-words12's Seal ID", shown(Screen.Collision, DICE_50_SEAL_ID))
        done(Core.collisionReport(), "the report: the slot waits at the restart, the words never made available").wipe()
        tap("show_report")
        find("privacy_gate")
        assertTrue("the report showed before the privacy gate", onMain { activity.model.state.value.gate })
        tap("pass_gate")
        await("past the gate", 10) { !onMain { activity.model.state.value.gate } }
        on(activity, Screen.CollisionReport)
        val report = onMain { activity.model.state.value.report } ?: throw AssertionError("no collision-report QR")
        assertTrue(
            "the collision-report QR is not dice-50-words12's register text (neither is printed)",
            Checker.read(report) == Checker.ORIGIN + "/register#c=" + DICE_50_SEAL_CODE,
        )
        tap("add_fresh_entropy")
        on(activity, Screen.Dice, START_SECONDS)
        awaitText("dice_count", "0 / 99 rolls, 0.0 bits")
        pass(
            "the snapshot drill: with-dice-50 picked from Downloads through DocumentsUI and loaded (No. 4, dated " +
                "2026-03-01, 7 entries, the Stale warning), Home naming it; dice-50-words12's check ran on its own: the " +
                "collision, its snapshot line and Stale warning and its Seal ID $DICE_50_SEAL_ID, before any words; the " +
                "report QR behind the gate; Add fresh entropy: 0 / 99",
        )
        finish(activity)
    }

    /**
     * From Home: a dice-only seed of 12 words with count rolls of pattern, the dice's Done, Check now's
     * seal card with sealId drawn, its check QR, then its "Scan go-ahead QR": the scan screen, whose
     * scanner, with CAMERA held, finds no camera on the emulator and says so.
     */
    private fun toScan(activity: MainActivity, count: Int, pattern: String, diceLine: String, sealId: String) {
        tap("dice_only_seed")
        on(activity, Screen.Length)
        tap("words_12")
        on(activity, Screen.Dice, START_SECONDS)
        roll(activity, count, pattern)
        awaitText("dice_count", diceLine)
        tap("dice_done")
        on(activity, Screen.CheckPrompt, START_SECONDS)
        tap("check_now")
        on(activity, Screen.SealCard)
        assertTrue("the seal card does not draw the seed's Seal ID", shown(Screen.SealCard, sealId))
        tap("show_check_qr")
        on(activity, Screen.CheckQr)
        tap("scan_qr")
        on(activity, Screen.Scan)
        awaitText("scan_line", SCAN_MISSING)
        assertEquals(ScanStop.Missing, onMain { activity.model.state.value.scanStop })
    }

    /** A Done reply's value; anything else fails the test. */
    private fun <T> done(reply: Reply<T>, what: String): T = when (reply) {
        is Reply.Done -> reply.value
        is Reply.Refused, Reply.Discarded -> throw AssertionError("not done: " + what)
    }

    private companion object {
        /** vectors/kcr.json's dice-50-words12: 123456 repeated, its Seal ID and its seal code as registered. */
        const val DICE_50_ROLLS = "123456"
        const val DICE_50_SEAL_ID = "YVM9CPP3"
        const val DICE_50_SEAL_CODE = "B98KT954NNYSS6APNPZWCYY0VA"

        /** vectors/kcr.json's dice-99-words12: 654321 repeated, and its Seal ID. */
        const val DICE_99_ROLLS = "654321"
        const val DICE_99_SEAL_ID = "9FHYMCQA"
    }
}
