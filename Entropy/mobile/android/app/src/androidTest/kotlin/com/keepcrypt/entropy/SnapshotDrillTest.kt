package com.keepcrypt.entropy

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Ui.START_SECONDS
import com.keepcrypt.entropy.Ui.await
import com.keepcrypt.entropy.Ui.awaitText
import com.keepcrypt.entropy.Ui.find
import com.keepcrypt.entropy.Ui.on
import com.keepcrypt.entropy.Ui.roll
import com.keepcrypt.entropy.Ui.tap
import com.keepcrypt.entropy.Ui.toHome
import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Freshness
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.screens.COLLISION_FOUND
import com.keepcrypt.entropy.screens.STALE_WARNING
import com.keepcrypt.entropy.screens.Screen
import java.time.LocalDate
import java.time.ZoneOffset
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The duplicate-seed drill with a loaded snapshot on the phone (tasks/todo.md, M5 group 16; the
 * owner's P4, second step), run by scripts/android-instrument.sh on the test-registry app in the API 31
 * and 36 legs, through UI Automator as FlowTest is (Ui). vectors/kcr.json's snapshot with-dice-50,
 * signed by the test registry key that only this APK trusts, is loaded through Core and handed to the
 * model, as commit 21's Load registry snapshot will (lead decision M5-48: no Home entry before its
 * screen). Then a dice-only seed of the public gate seed dice-50-words12, whose seal the snapshot holds:
 * the dice's Done, Check now, and the check runs on its own: the collision result, with the snapshot's
 * number, date and its Stale warning (the snapshot is dated 2026-03-01), before any words; the privacy
 * gate, the collision-report QR (read in-process: the destroyed seed's registration text), and "Add
 * fresh entropy", whose dice need 99 rolls.
 */
@RunWith(AndroidJUnit4::class)
class SnapshotDrillTest {
    @Test
    fun aLoadedSnapshotsCheckFindsTheCollisionBeforeAnyWordsAndFreshEntropyNeeds99Rolls() {
        Capture.whileOffline {
            val activity = toHome()
            val today = LocalDate.now(ZoneOffset.UTC).let { it.year * 10_000 + it.monthValue * 100 + it.dayOfMonth }
            val header = when (val loaded = Core.loadSnapshot(today, Checker.bytes(WITH_DICE_50_KCR))) {
                is Reply.Done -> loaded.value
                is Reply.Refused, Reply.Discarded -> throw AssertionError("with-dice-50.kcr did not load in the test-registry APK")
            }
            assertEquals(4UL, header.number)
            assertEquals(20260301, header.date)
            assertEquals(7L, header.count)
            assertEquals("a snapshot dated 2026-03-01 is Stale on the emulator's date", Freshness.Stale, header.freshness)
            onMain { activity.model.snapshotLoaded(header) }
            tap("dice_only_seed")
            on(activity, Screen.Length)
            tap("words_12")
            on(activity, Screen.Dice, START_SECONDS)
            roll(activity, 50, DICE_50_ROLLS)
            awaitText("dice_count", "50 / 50 rolls, 129.2 bits")
            tap("dice_done")
            on(activity, Screen.CheckPrompt, START_SECONDS)
            assertEquals(DICE_50_SEAL_ID, onMain { activity.model.state.value.seal?.sealId })
            tap("check_now")
            on(activity, Screen.Collision, START_SECONDS)
            awaitText("collision_text", COLLISION_FOUND)
            awaitText("snapshot_line", "Snapshot No. 4, dated 2026-03-01, 7 entries.")
            awaitText("snapshot_warning", STALE_WARNING)
            done(Core.collisionReport(), "the report: the slot waits at the restart, the words never made available").wipe()
            tap("show_report")
            find("privacy_gate")
            assertTrue("the report showed before the privacy gate", onMain { activity.model.state.value.gate })
            tap("pass_gate")
            await("past the gate", 10) { !onMain { activity.model.state.value.gate } }
            on(activity, Screen.CollisionReport)
            val report = onMain { activity.model.state.value.report } ?: throw AssertionError("no collision-report QR")
            assertEquals(Checker.ORIGIN + "/register#c=" + DICE_50_SEAL_CODE, Checker.read(report))
            tap("add_fresh_entropy")
            on(activity, Screen.Dice, START_SECONDS)
            awaitText("dice_count", "0 / 99 rolls, 0.0 bits")
            pass(
                "the snapshot drill: with-dice-50 loaded, dice-50-words12's check ran on its own: the collision, its " +
                    "snapshot line and Stale warning, before any words; the report QR behind the gate; Add fresh entropy: 0 / 99",
            )
            finish(activity)
        }
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

        /**
         * vectors/kcr.json's snapshot with-dice-50 (its kcr_hex): No. 4, dated 2026-03-01, 7 entries,
         * dice-50-words12's tag among them, signed by the test registry key. The JVM tests read the same
         * bytes from that file (CheckScreensTest, RegistryTest), and GoAheadPngTest writes them as the P4
         * drill's with-dice-50.kcr.
         */
        const val WITH_DICE_50_KCR =
            "4b43523100010000000000000004013525cd00000000000000073cd2a5fdd97d7455b6ae2c8b38f77a215a9ca209237f4948" +
                "5b12f007183e178540a30ab1ed5068055f67dca3f05f55bbbe0d671d2bc0127c79bf7e24c374c12566afadc472842fc708888e" +
                "95715e2ac14d5ca32b18323ecbbabcdc16c1e4c001000003b6fc1f9b5fffc1c56c263ba53600012b8103c8dd64611df5c8c28b" +
                "8fbf864bffff2b81090b7fd157945acf1ff22896eb67000280000a639f49af784c7a85ebd0bd4e88000380000d8506a789e8fb" +
                "58a21cca8fec260001f6e8965ac3e420f9061e7c1a7e9d829d0001fffff018c5294cb896e60c612c7ea7be0007"
    }
}
