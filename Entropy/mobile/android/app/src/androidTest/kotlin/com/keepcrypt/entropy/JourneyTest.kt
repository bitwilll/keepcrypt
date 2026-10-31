package com.keepcrypt.entropy

import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.uiautomator.By
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Ui.DOT
import com.keepcrypt.entropy.Ui.START_SECONDS
import com.keepcrypt.entropy.Ui.assertInsert
import com.keepcrypt.entropy.Ui.await
import com.keepcrypt.entropy.Ui.awaitText
import com.keepcrypt.entropy.Ui.device
import com.keepcrypt.entropy.Ui.enabled
import com.keepcrypt.entropy.Ui.find
import com.keepcrypt.entropy.Ui.on
import com.keepcrypt.entropy.Ui.sameWord
import com.keepcrypt.entropy.Ui.shown
import com.keepcrypt.entropy.Ui.tap
import com.keepcrypt.entropy.Ui.tapCode
import com.keepcrypt.entropy.Ui.tapRolls
import com.keepcrypt.entropy.Ui.toHome
import com.keepcrypt.entropy.Ui.two
import com.keepcrypt.entropy.Ui.typeLetters
import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.screens.COLLISION_FOUND
import com.keepcrypt.entropy.screens.INSERTS_PER_DEVICE
import com.keepcrypt.entropy.screens.SKIPPED
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.screens.TWO_DEVICES
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * U1's journeys from First launch to Finish through the UI alone (tasks/todo.md, Stage U's U1 and its
 * commit plan's U-4; lead decision M5-72 (a)), run by scripts/android-instrument.sh on the shipping app in
 * the API 31 and 36 journeys jobs. Every input is the user's, made on the screen: UI Automator taps the
 * Public controls by their resource ids, the dice faces are pressed on the Public pad by their
 * accessibility click and confirmed by tap (Ui.tapRolls), the go-ahead code is tapped on the Crockford pad
 * (Ui.tapCode) and the read-back's letters are touched on the Protected letter pad (Ui.typeLetters), so
 * no model call stands in for a press. State is read in-process only to observe it: the check QR the seal
 * card drew (Checker; captures of the app are black), the collision report and registration QRs, and each
 * insert's word, compared with the vector and never printed. Every seed is a vectors/kcr.json gate seed's,
 * its rolls those of the vector. Each journey's pass line names its path and the time each part took,
 * which sizes the journeys jobs' budget (M5-30) and the rest of U-4's plan.
 */
@RunWith(AndroidJUnit4::class)
class JourneyTest {
    /** Elapsed seconds since start (SystemClock's elapsed real time, in ms), one decimal. */
    private fun since(start: Long): String {
        val tenths = (SystemClock.elapsedRealtime() - start) / 100
        return (tenths / 10).toString() + "." + (tenths % 10) + " s"
    }

    /**
     * Match found to Add fresh entropy, then the new seed to Finish (Stage U's U1b; the Pi's step 7,
     * docs/pi-firmware.md:93, and swb's Stop): a dice-only seed of dice-50-words12 by its 50 rolls tapped,
     * Check now's seal card with its Seal ID, the check QR's Match found and its confirm, the collision
     * result with the destroyed seed's Seal ID drawn, the report behind the privacy gate (its QR
     * dice-50-words12's register text), and Add fresh entropy, whose dice need 99 rolls; dice-99-words12's
     * 99 rolls tapped, Check now's seal card with its Seal ID, the go-ahead code a checker builds from the
     * drawn check QR's T and nonce tapped on the pad, the check passed, Show words through the gate, the 12
     * inserts by Next (each the vector's word with its position), the read-back of every insert's first
     * four letters touched on the letter pad, each a match, the summary (core's), the backup's and
     * watch-only's Skip, the registration QR behind its gate (dice-99-words12's register text), the
     * checklist and Finish: Home, with the slot empty.
     */
    @Test
    fun matchFoundRestartsAt99RollsAndTheNewSeedReachesFinishThroughTheUiAlone() {
        Capture.whileOffline {
            val journey = SystemClock.elapsedRealtime()
            val activity = toHome()
            tap("dice_only_seed")
            on(activity, Screen.Length)
            tap("words_12")
            on(activity, Screen.Dice, START_SECONDS)
            val first = SystemClock.elapsedRealtime()
            tapRolls(activity, 50, DICE_50_ROLLS)
            val firstRolls = since(first)
            awaitText("dice_count", "50 / 50 rolls, 129.2 bits")
            tap("dice_done")
            on(activity, Screen.CheckPrompt, START_SECONDS)
            tap("check_now")
            on(activity, Screen.SealCard)
            assertTrue("the seal card does not draw dice-50-words12's Seal ID", shown(Screen.SealCard, DICE_50_SEAL_ID))
            tap("show_check_qr")
            on(activity, Screen.CheckQr)
            tap("match_found")
            on(activity, Screen.MatchFoundConfirm)
            tap("confirm_action")
            on(activity, Screen.Collision)
            awaitText("collision_text", COLLISION_FOUND)
            assertTrue("the collision result does not draw the destroyed seed's Seal ID", shown(Screen.Collision, DICE_50_SEAL_ID))
            tap("show_report")
            find("privacy_gate")
            assertTrue("the report showed before the privacy gate", onMain { activity.model.state.value.gate })
            tap("pass_gate")
            await("past the report's gate", 10) { !onMain { activity.model.state.value.gate } }
            on(activity, Screen.CollisionReport)
            val report = onMain { activity.model.state.value.report } ?: throw AssertionError("no collision-report QR")
            assertTrue(
                "the collision-report QR is not dice-50-words12's register text (neither is printed)",
                Checker.read(report) == Checker.ORIGIN + "/register#c=" + DICE_50_SEAL_CODE,
            )
            tap("add_fresh_entropy")
            on(activity, Screen.Dice, START_SECONDS)
            awaitText("dice_count", "0 / 99 rolls, 0.0 bits")
            val second = SystemClock.elapsedRealtime()
            tapRolls(activity, 98, DICE_99_ROLLS)
            assertFalse("Done one roll below the 99 after a collision", enabled("dice_done"))
            tapRolls(activity, 1, DICE_99_ROLLS[98 % DICE_99_ROLLS.length].toString())
            val secondRolls = since(second)
            awaitText("dice_count", "99 / 99 rolls, 255.9 bits")
            tap("dice_done")
            on(activity, Screen.CheckPrompt, START_SECONDS)
            tap("check_now")
            on(activity, Screen.SealCard)
            assertTrue("the seal card does not draw dice-99-words12's Seal ID", shown(Screen.SealCard, DICE_99_SEAL_ID))
            val request = onMain { activity.model.state.value.checkRequest } ?: throw AssertionError("the seal card has no check QR")
            val (tag, nonce) = Checker.request(Checker.read(request))
            assertEquals("the check QR's T is not dice-99-words12's seal tag", DICE_99_TAG, tag)
            tap("show_check_qr")
            on(activity, Screen.CheckQr)
            tap("type_code")
            on(activity, Screen.CodeEntry)
            tapCode(Checker.goAhead(tag, nonce))
            tap("code_done")
            on(activity, Screen.CheckResult, START_SECONDS)
            awaitText("check_result_text", "No collision for seal $DICE_99_SEAL_ID, as of the date your checker showed.")
            val (readback, _) = wordsToFinish(activity, DICE_99_WORDS, DICE_99_SEAL_CODE)
            pass(
                "the Match found journey through the UI alone: dice-50-words12's 50 rolls tapped ($firstRolls), its seal card " +
                    "($DICE_50_SEAL_ID), Match found confirmed, the collision with its Seal ID, the report QR behind the gate " +
                    "(its register text), Add fresh entropy at 0 / 99, Done disabled at 98; dice-99-words12's 99 rolls tapped " +
                    "($secondRolls), its seal card ($DICE_99_SEAL_ID), the drawn check QR's code tapped: the check passed; the " +
                    "gate, 12 inserts by Next equal to the vector's words, 12 read back by touches on the letter pad " +
                    "($readback), the summary, the registration QR (its register text), the checklist, Finish: Home with " +
                    "the slot empty; the journey " + since(journey),
            )
            finish(activity)
        }
    }

    /**
     * From a check's result with the words available (passed or skipped): Show words through the privacy
     * gate, each insert by Next (each the vector's word with its position and device, in-process), across
     * the device swap and its second gate on a 24-word seed, the read-back of every insert's first four
     * letters touched on the letter pad (each a match, the header naming its device), the summary (core's),
     * the backup's and watch-only's Skip, the registration QR behind its gate (sealCode's register text),
     * the checklist (naming two devices for 24 words, none for 12) and Finish: Home with the slot empty.
     * Returns the read-back's time and the whole stretch's.
     */
    private fun wordsToFinish(activity: MainActivity, words: List<String>, sealCode: String): Pair<String, String> {
        val start = SystemClock.elapsedRealtime()
        val devices = words.size / INSERTS_PER_DEVICE
        fun device(index: Int) = index / INSERTS_PER_DEVICE + 1
        tap("show_words")
        find("privacy_gate")
        assertTrue("the words showed before the privacy gate", onMain { activity.model.state.value.gate })
        tap("pass_gate")
        await("past the words' gate", 10) { !onMain { activity.model.state.value.gate } }
        for (index in words.indices) {
            assertInsert(activity, words, index, device(index), devices)
            if (index + 1 == words.size) break
            tap("next")
            if ((index + 1) % INSERTS_PER_DEVICE == 0) {
                on(activity, Screen.DeviceSwap)
                awaitText("device_swap_text", "Words 13-24 go on device 2 of 2.")
                tap("continue")
                find("privacy_gate")
                assertTrue("device 2's words showed before the privacy gate", onMain { activity.model.state.value.gate })
                tap("pass_gate")
            }
        }
        tap("start_readback")
        on(activity, Screen.ReadbackEntry)
        val readback = SystemClock.elapsedRealtime()
        for (index in words.indices) {
            awaitText("readback_header", "Read back insert " + two(index + 1) + DOT + "device " + device(index) + " of " + devices)
            typeLetters(activity, Screen.ReadbackEntry, words[index].take(4)) { it.readbackLetters }
            tap("letters_done")
            await("insert " + (index + 1) + " matched", 10) { onMain { activity.model.state.value.matched } }
            assertTrue(
                "the match does not show insert " + (index + 1) + "'s word",
                onMain { sameWord(checkNotNull(activity.model.state.value.insert), words[index]) },
            )
            tap("readback_next")
        }
        val readbackTime = since(readback)
        on(activity, Screen.ReadbackDone)
        tap("show_summary")
        on(activity, Screen.Wallet)
        val summary = onMain { checkNotNull(activity.model.state.value.summary) }
        val core = Core.summary()
        assertTrue("the summary is not core's", core is Reply.Done && core.value.firstAddress == summary.firstAddress)
        tap("summary_next")
        on(activity, Screen.BackupOffer)
        tap("skip_backup")
        on(activity, Screen.WatchOffer)
        tap("skip_watch_only")
        on(activity, Screen.RegisterOffer)
        tap("show_registration")
        find("privacy_gate")
        tap("pass_gate")
        await("past the registration QR's gate", 10) { onMain { activity.model.state.value.let { it.screen == Screen.RegisterQr && !it.gate } } }
        val registration = onMain { activity.model.state.value.registration } ?: throw AssertionError("no registration QR")
        assertTrue(
            "the registration QR is not the seed's register text (neither is printed)",
            Checker.read(registration) == Checker.ORIGIN + "/register#c=" + sealCode,
        )
        tap("registration_done")
        on(activity, Screen.Checklist)
        if (devices == 2) {
            assertTrue("the checklist does not say which device holds words 1-12", shown(Screen.Checklist, TWO_DEVICES))
        } else {
            assertFalse("a 12-word seed's checklist names two devices", device.hasObject(By.res("two_devices")))
        }
        tap("finish")
        on(activity, Screen.Home)
        assertTrue("the slot is not at home: Finish did not end the session", Core.selfTest() is Reply.Done)
        return readbackTime to since(start)
    }

    /**
     * A dice-only seed of 24 words to Finish with its check skipped (Stage U's U1c; swb's "24-word seeds"):
     * dice-99-words24's 99 rolls tapped (Done disabled at 98), Skip and its confirm, the result saying the
     * check was skipped, then the 24 words on two devices with the swap and its second gate between them,
     * all 24 read back by touches with each insert's device named, the summary, the registration QR
     * (dice-99-words24's register text), the checklist saying which device holds words 1-12, and Finish.
     */
    @Test
    fun aDiceOnlyTwentyFourWordSeedSkipsItsCheckAndReachesFinishOnTwoDevicesThroughTheUiAlone() {
        Capture.whileOffline {
            val journey = SystemClock.elapsedRealtime()
            val activity = toHome()
            tap("dice_only_seed")
            on(activity, Screen.Length)
            tap("words_24")
            on(activity, Screen.Dice, START_SECONDS)
            awaitText("dice_count", "0 / 99 rolls, 0.0 bits")
            val rolls = SystemClock.elapsedRealtime()
            tapRolls(activity, 98, DICE_99_ROLLS)
            assertFalse("Done one roll below a 24-word seed's 99", enabled("dice_done"))
            tapRolls(activity, 1, DICE_99_ROLLS[98 % DICE_99_ROLLS.length].toString())
            val rollTime = since(rolls)
            awaitText("dice_count", "99 / 99 rolls, 255.9 bits")
            tap("dice_done")
            on(activity, Screen.CheckPrompt, START_SECONDS)
            tap("skip")
            on(activity, Screen.SkipConfirm)
            tap("confirm_action")
            on(activity, Screen.CheckResult)
            awaitText("check_result_text", SKIPPED)
            val (readback, rest) = wordsToFinish(activity, DICE_99_24_WORDS, DICE_99_24_SEAL_CODE)
            pass(
                "the dice-only 24-word journey through the UI alone: dice-99-words24's 99 rolls tapped ($rollTime), Done " +
                    "disabled at 98, Skip confirmed; the gate, 24 inserts by Next equal to the vector's words with the device " +
                    "swap and its gate after insert 12, 24 read back by touches with each insert's device ($readback), the " +
                    "summary, the registration QR (its register text), the checklist naming two devices, Finish: Home with " +
                    "the slot empty ($rest from Show words); the journey " + since(journey),
            )
            finish(activity)
        }
    }

    private companion object {
        /** vectors/kcr.json's dice-50-words12: 123456 repeated, its Seal ID and its seal code as registered (public gate-seed vectors). */
        const val DICE_50_ROLLS = "123456"
        const val DICE_50_SEAL_ID = "YVM9CPP3"
        const val DICE_50_SEAL_CODE = "B98KT954NNYSS6APNPZWCYY0VA"

        /** vectors/kcr.json's dice-99-words12: 654321 repeated, its Seal ID, seal tag T and seal code as registered. */
        const val DICE_99_ROLLS = "654321"
        const val DICE_99_SEAL_ID = "9FHYMCQA"
        const val DICE_99_TAG = "4be3ea32eaee361d4ba6ce2135459510ccd0b7fd869121425c068b4538657f14"
        const val DICE_99_SEAL_CODE = "15ZHX4W7AVW8VRSNJVXZEHQ2SV"

        /** vectors/kcr.json's dice-99-words12's words (its mnemonic field), compared in-process with each page and never printed. */
        val DICE_99_WORDS = listOf(
            "various", "tape", "mercy", "east", "hair", "tragic", "arrest", "together", "day", "tag", "afford", "occur",
        )

        /** vectors/kcr.json's dice-99-words24 (the same 99 rolls): its seal code as registered and its words, compared in-process and never printed. */
        const val DICE_99_24_SEAL_CODE = "C3ER95M4JV2N4TCPBRRG41J74W"
        val DICE_99_24_WORDS = listOf(
            "various", "tape", "mercy", "east", "hair", "tragic", "arrest", "together", "day", "tag", "afford",
            "obvious", "devote", "violin", "coil", "conduct", "salmon", "kidney", "anchor", "monkey", "cruel", "truth",
            "dash", "smart",
        )
    }
}
