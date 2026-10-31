package com.keepcrypt.entropy

import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.GateSeeds.DICE_50_ROLLS
import com.keepcrypt.entropy.Journeys.checklistToFinish
import com.keepcrypt.entropy.Journeys.newSeedToDice
import com.keepcrypt.entropy.Journeys.since
import com.keepcrypt.entropy.Journeys.summaryToWatchOffer
import com.keepcrypt.entropy.Journeys.wordsAndReadBack
import com.keepcrypt.entropy.Ui.START_SECONDS
import com.keepcrypt.entropy.Ui.await
import com.keepcrypt.entropy.Ui.awaitText
import com.keepcrypt.entropy.Ui.device
import com.keepcrypt.entropy.Ui.doubleTap
import com.keepcrypt.entropy.Ui.on
import com.keepcrypt.entropy.Ui.tap
import com.keepcrypt.entropy.Ui.tapRolls
import com.keepcrypt.entropy.Ui.toHome
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.screens.isWorking
import com.keepcrypt.entropy.screens.screenId
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Double taps on the phone (tasks/todo.md, Stage U's U2i; docs/pi-firmware.md, "Confirmations" and the
 * privacy gate), on the shipping app in android-emulator.sh's capture part (lead decision M5-78 (a)): two
 * touches 60 ms apart at one point, injected as a finger makes them (Ui.doubleTap), on each one-way choice
 * and its confirm (Skip, Match found, Cannot check), on Show words and on four privacy gates' buttons (the
 * words', the collision report's, the registration QR's and D's). The second touch lands on whatever the
 * first one's press put under it, so a double tap must take exactly one step: the screen it leads to,
 * with its gate still up where it has one, its first page, no pad typed into. Where it took two, a gate
 * or a confirm was passed unseen, and lead decision M5-72 (f)'s fix follows (a new screen's controls
 * ignore presses for 300 ms after its first frame, in pressOn) with this test as its failing test. The
 * seeds are vectors/kcr.json's dice-50-words12 rolls, dice-only, and a mixed seed of 12 words; state is
 * read in-process only to observe it, and only screen ids, gates and counts are printed.
 */
@RunWith(AndroidJUnit4::class)
class DoubleTapTest {
    /** Skip's choice and its confirm, then Show words and the words' gate, each double tapped. */
    @Test
    fun skipItsConfirmShowWordsAndTheWordsGateEachTakeOneStep() {
        Capture.whileOffline {
            val start = SystemClock.elapsedRealtime()
            val activity = toDice()
            twice(activity, "skip", Screen.CheckPrompt, Screen.SkipConfirm, gate = false)
            twice(activity, "confirm_action", Screen.SkipConfirm, Screen.CheckResult, gate = false)
            twice(activity, "show_words", Screen.CheckResult, Screen.Words, gate = true)
            twice(activity, "pass_gate", Screen.Words, Screen.Words, gate = false)
            assertTrue("past the words' gate, a double tap left the first insert", onMain { activity.model.state.value.page } == 0)
            pass("double taps: Skip, its confirm, Show words and the words' gate each one step, on insert 1; " + since(start))
            finish(activity)
        }
    }

    /** Match found's choice and its confirm, then Show the collision report and the report's gate, each double tapped. */
    @Test
    fun matchFoundItsConfirmAndTheReportsGateEachTakeOneStep() {
        Capture.whileOffline {
            val start = SystemClock.elapsedRealtime()
            val activity = toCheckQr()
            twice(activity, "match_found", Screen.CheckQr, Screen.MatchFoundConfirm, gate = false)
            twice(activity, "confirm_action", Screen.MatchFoundConfirm, Screen.Collision, gate = false)
            twice(activity, "show_report", Screen.Collision, Screen.CollisionReport, gate = true)
            twice(activity, "pass_gate", Screen.CollisionReport, Screen.CollisionReport, gate = false)
            pass("double taps: Match found, its confirm, Show the collision report and its gate each one step; " + since(start))
            finish(activity)
        }
    }

    /** Cannot check's choice and its confirm (a new ceremony at 0 rolls, no face picked), each double tapped. */
    @Test
    fun cannotCheckAndItsConfirmEachTakeOneStep() {
        Capture.whileOffline {
            val start = SystemClock.elapsedRealtime()
            val activity = toCheckQr()
            twice(activity, "cannot_check", Screen.CheckQr, Screen.CannotCheckConfirm, gate = false)
            twice(activity, "confirm_action", Screen.CannotCheckConfirm, Screen.Dice, gate = false)
            awaitText("dice_count", "0 / 50 rolls, 0.0 bits")
            assertTrue("a double tap on Cannot check's confirm picked a face on the new dice", onMain { activity.model.dicePick.length } == 0)
            pass("double taps: Cannot check and its confirm each one step, the new dice at 0 rolls with no face picked; " + since(start))
            finish(activity)
        }
    }

    /**
     * A mixed seed of 12 words skipped to its words, read back (Journeys'), to the registration's offer:
     * Show registration QR and its gate, then Show D and its gate, each double tapped; then Finish.
     */
    @Test
    fun theRegistrationQrsGateAndDsGateEachTakeOneStep() {
        Capture.whileOffline {
            val start = SystemClock.elapsedRealtime()
            val activity = toHome()
            newSeedToDice(activity, "words_12", 50)
            tapRolls(activity, 50, DICE_50_ROLLS)
            tap("dice_done")
            on(activity, Screen.CheckPrompt, START_SECONDS)
            tap("skip")
            on(activity, Screen.SkipConfirm)
            tap("confirm_action")
            on(activity, Screen.CheckResult)
            wordsAndReadBack(activity, null, 12)
            summaryToWatchOffer(activity)
            tap("skip_watch_only")
            on(activity, Screen.RegisterOffer)
            twice(activity, "show_registration", Screen.RegisterOffer, Screen.RegisterQr, gate = true)
            twice(activity, "pass_gate", Screen.RegisterQr, Screen.RegisterQr, gate = false)
            tap("registration_done")
            on(activity, Screen.RevealDOffer)
            twice(activity, "show_d", Screen.RevealDOffer, Screen.RevealD, gate = true)
            twice(activity, "pass_gate", Screen.RevealD, Screen.RevealD, gate = false)
            tap("d_done")
            checklistToFinish(activity, 1)
            pass("double taps: Show registration QR, its gate, Show D and its gate each one step; Finish; " + since(start))
            finish(activity)
        }
    }

    /** From Home: a dice-only seed of 12 words, dice-50-words12's 50 rolls tapped, Done: the check's prompt. */
    private fun toDice(): MainActivity {
        val activity = toHome()
        tap("dice_only_seed")
        on(activity, Screen.Length)
        tap("words_12")
        on(activity, Screen.Dice, START_SECONDS)
        tapRolls(activity, 50, DICE_50_ROLLS)
        awaitText("dice_count", "50 / 50 rolls, 129.2 bits")
        tap("dice_done")
        on(activity, Screen.CheckPrompt, START_SECONDS)
        return activity
    }

    /** toDice, then Check now and the seal card's Show check QR: the check QR page, the check open. */
    private fun toCheckQr(): MainActivity {
        val activity = toDice()
        tap("check_now")
        on(activity, Screen.SealCard)
        tap("show_check_qr")
        on(activity, Screen.CheckQr)
        return activity
    }

    /**
     * On from (its gate down), a double tap on control tag (Ui.doubleTap); once any long call it started
     * is over and a moment has passed for a late press to land, the app must show to, with its privacy gate
     * up where gate says so: one step, never two. Only screen ids and the gate are printed.
     */
    private fun twice(activity: MainActivity, tag: String, from: Screen, to: Screen, gate: Boolean) {
        val what = "a double tap on $tag on " + screenId(from)
        assertTrue("$what: not on " + screenId(from) + " past its gate", onMain { activity.model.state.value.let { it.screen == from && !it.gate } })
        doubleTap(tag)
        await("$what: no long call running", START_SECONDS) { onMain { !isWorking(activity.model.state.value.screen) } }
        device.waitForIdle()
        SystemClock.sleep(SETTLE_MS)
        val (screen, gated) = onMain { activity.model.state.value.let { it.screen to it.gate } }
        assertTrue(
            "$what took more than one step or none: it shows " + screenId(screen) + (if (gated) " behind its gate" else "") +
                ", not " + screenId(to) + (if (gate) " behind its gate" else ""),
            screen == to && gated == gate,
        )
        on(activity, to)
    }

    private companion object {
        /** How long a late second press gets to land after the app settles. */
        const val SETTLE_MS = 1_000L
    }
}
