package com.keepcrypt.entropy

import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.launch
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Capture.probe
import com.keepcrypt.entropy.Capture.shellText
import com.keepcrypt.entropy.GateSeeds.DICE_50_ROLLS
import com.keepcrypt.entropy.Ui.await
import com.keepcrypt.entropy.Ui.device
import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Words
import com.keepcrypt.entropy.screens.Notice
import com.keepcrypt.entropy.screens.Overlay
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.screens.screenId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Leaving the app by other ways than Home (tasks/todo.md, Stage U's U2k), on the shipping app in
 * android-emulator.sh's registry part: the screen turning off (KEYCODE_SLEEP, then KEYCODE_WAKEUP and the
 * keyguard dismissed) on a words page, a Protected screen, which is discarded at once, and on the dice, a
 * Public screen, which is covered and kept (under the 60 s rule); and the back gesture (gesture navigation switched
 * on through the system's gestural overlay for the test and three-button navigation put back after; a swipe in
 * from the left edge, or KEYCODE_BACK where the switch does not take, named so) doing what the model's back does.
 * The activity destroyed while away is LifecycleTest's finish and KillTest's process deaths (lead decision M5-81
 * (d): the shell's always_finish_activities is not applied by the activity manager). Setup goes
 * through the model's entry points, as LifecycleTest's does (an edge test; the journeys are the UI's alone), with
 * vectors/kcr.json's dice-50-words12 rolls; only screen ids, notices, counts and times are printed.
 */
@RunWith(AndroidJUnit4::class)
class AwayTest {

    @Test
    fun theScreenTurningOffOnAWordsPageDiscardsTheSessionAtOnce() {
        Capture.whileOffline {
            val activity = toDice()
            val page = onMain {
                val model = activity.model
                for (roll in ROLLS_50) {
                    model.dicePick.replace(roll)
                    model.confirmRoll()
                }
                model.diceDone()
                model
            }.let { model ->
                await("the check prompt", Ui.START_SECONDS) { onMain { model.state.value.screen } == Screen.CheckPrompt }
                onMain {
                    model.skip()
                    model.skipConfirmed()
                    model.showWords()
                    model.passGate()
                    model.nextPage()
                    model.state.value.let { if (it.screen == Screen.Words && it.page == 1) it.insert else null }
                } ?: throw AssertionError("not on insert 2's page")
            }
            val begun = SystemClock.elapsedRealtime()
            device.sleep()
            await("the activity stopped with the screen off", 30) { stage(activity) == Stage.STOPPED }
            val away = onMain { activity.model.state.value }
            probe("words page: the screen off; the stop seen after " + (SystemClock.elapsedRealtime() - begun) + " ms, the screen then " + screenId(away.screen))
            assertEquals("the screen turning off on a words page did not discard at once", Screen.GoOffline, away.screen)
            assertEquals(Notice.Left, away.notice)
            assertTrue("the page on show was not wiped", onMain { page.position == 0 && page.word().size == 0 })
            assertTrue("the slot is not at home: the session was not discarded", Core.selfTest() is Reply.Done)
            wake(activity)
            assertEquals("back with the screen on, not the start screen", Screen.GoOffline, onMain { activity.model.state.value.screen })
            pass("the screen off on a words page: discarded at once (by the stop), the page wiped, the session gone; back on, Go offline says why")
            finish(activity)
        }
    }

    @Test
    fun theScreenTurningOffOnTheDiceCoversItAndKeepsTheSession() {
        Capture.whileOffline {
            val activity = toDice()
            roll(activity, ROLLS)
            device.sleep()
            await("the activity stopped with the screen off", 30) { stage(activity) == Stage.STOPPED }
            val left = SystemClock.elapsedRealtime()
            SystemClock.sleep(AWAY_MS)
            val held = onMain { activity.model.state.value }
            assertEquals("the screen off on the dice wiped the session", Screen.Dice, held.screen)
            assertEquals(Overlay.Cover, held.overlay)
            wake(activity)
            val back = SystemClock.elapsedRealtime() - left
            assertTrue("the return came after the 60 s rule's time ($back ms), so it proves nothing", back < 60_000)
            val kept = onMain { activity.model.state.value }
            assertEquals("back with the screen on, the session not kept", Screen.Dice, kept.screen)
            assertEquals(null, kept.notice)
            assertEquals(Overlay.Cover, kept.overlay)
            assertEquals("the rolls", ROLLS, done(Core.diceProgress()).rolls)
            onMain { activity.model.dismissOverlay() }
            pass("the screen off on the dice: covered and kept, back on after $back ms under the cover with its $ROLLS rolls")
            finish(activity)
        }
    }

    @Test
    fun theBackGestureDoesWhatBackDoes() {
        val before = shellText("settings get secure navigation_mode")
        if (before != GESTURE) shellText("cmd overlay enable-exclusive --category $GESTURAL")
        val gesture = waitFor(GESTURE)
        if (!gesture) probe("gesture navigation did not come on (navigation_mode " + shellText("settings get secure navigation_mode") + "): the Back key is tested")
        // SystemUI takes up the gestural navigation bar after the setting reads it (run 41275381593: a swipe made at
        // once brought no Back on either level).
        if (gesture && before != GESTURE) SystemClock.sleep(SETTLE_GESTURE_MS)
        try {
            backGesture(gesture)
        } finally {
            if (before != GESTURE) {
                shellText("cmd overlay enable-exclusive --category $THREE_BUTTON")
                waitFor(before)
            }
        }
    }

    /** The back test proper: Back by the gesture where gesture navigation is on, by the key otherwise. */
    private fun backGesture(gesture: Boolean) {
        Capture.whileOffline {
            val activity = toDice()
            roll(activity, ROLLS)
            back(gesture)
            settle()
            assertEquals("Back on the dice left it", Screen.Dice, onMain { activity.model.state.value.screen })
            assertEquals("Back on the dice changed its rolls", ROLLS, done(Core.diceProgress()).rolls)
            onMain {
                val model = activity.model
                for (roll in ROLLS_50.drop(ROLLS)) {
                    model.dicePick.replace(roll)
                    model.confirmRoll()
                }
                model.diceDone()
            }
            await("the check prompt", Ui.START_SECONDS) { onMain { activity.model.state.value.screen } == Screen.CheckPrompt }
            onMain { activity.model.checkNow() }
            await("the seal card", 10) { onMain { activity.model.state.value.screen } == Screen.SealCard }
            onMain { activity.model.showCheckQr() }
            await("the check QR", 10) { onMain { activity.shownScreen } == Screen.CheckQr }
            val how = back(gesture)
            val sealCard = { onMain { activity.model.state.value.screen } == Screen.SealCard }
            if (!gesture) {
                await("Back from the check QR to the seal card by " + how, 10, sealCard)
            } else if (!within(BACK_SECONDS, sealCard)) {
                // Runs 41275381593 and 41279169126: the shell's swipe brought no Back on either level, the settle
                // and pace notwithstanding. SystemUI's own record of the gesture is gathered (lessons.md,
                // 2026-11-01), then a swipe through UiAutomation's injected touches, so the next change rests on both.
                probe("no Back from the check QR by " + how + "; SystemUI's back gesture handler: " + edgeBackFacts())
                val y = device.displayHeight / 2
                device.swipe(2, y, device.displayWidth / 3, y, SWIPE_STEPS)
                val other = within(BACK_SECONDS, sealCard)
                throw AssertionError(
                    "timed out: Back from the check QR to the seal card by " + how + "; then a swipe through UiAutomation (" +
                        SWIPE_STEPS + " steps) " + (if (other) "brought it" else "brought none either") + " (SystemUI's facts in the probe line)",
                )
            }
            back(gesture)
            settle()
            assertEquals("Back on the seal card left it", Screen.SealCard, onMain { activity.model.state.value.screen })
            pass("the system Back by " + (if (gesture) "the gesture (a swipe from the left edge)" else "the key (three-button navigation)") +
                ": nothing on the dice and the seal card, the check QR back to the seal card")
            finish(activity)
        }
    }

    /** Whether navigation_mode reads mode within 10 s. */
    private fun waitFor(mode: String): Boolean {
        val end = SystemClock.elapsedRealtime() + 10_000
        while (shellText("settings get secure navigation_mode") != mode) {
            if (SystemClock.elapsedRealtime() > end) return false
            SystemClock.sleep(200)
        }
        return true
    }

    /** A new MainActivity through First launch's Continue (the self-test) and Go offline's Start, to the dice of a dice-only 12-word seed. */
    private fun toDice(): MainActivity {
        val activity = launch()
        await("First launch", 10) { onMain { activity.shownScreen } == Screen.FirstLaunch }
        onMain { activity.model.firstLaunchDone() }
        await("Go offline: the start-up self-test passed", Ui.START_SECONDS) { onMain { activity.shownScreen } == Screen.GoOffline }
        await("the app reads airplane mode on and Wi-Fi off", 30) { onMain { activity.model.state.value.offline } }
        onMain {
            activity.model.startOffline()
            activity.model.chooseMode(Mode.DiceOnly)
            activity.model.chooseLength(Words.Twelve)
        }
        await("the dice", Ui.START_SECONDS) { onMain { activity.model.state.value.screen } == Screen.Dice }
        return activity
    }

    /** The first count of dice-50-words12's rolls, through the model's pick and confirm, as the pad and Confirm call them. */
    private fun roll(activity: MainActivity, count: Int) {
        onMain {
            for (roll in ROLLS_50.take(count)) {
                activity.model.dicePick.replace(roll)
                activity.model.confirmRoll()
            }
        }
    }

    /** The display woken and the keyguard dismissed: the activity back in front, resumed. */
    private fun wake(activity: MainActivity) {
        device.wakeUp()
        shellText("wm dismiss-keyguard")
        await("back in the app with the screen on", 30) { stage(activity) == Stage.RESUMED }
    }

    /**
     * The system Back: under gesture navigation a swipe in from the left edge at mid-height to a third of the width,
     * over SWIPE_MS through the shell's input (a deliberate thumb's pace), the Back key otherwise. Returns what was
     * done, for a failure's message.
     */
    private fun back(gesture: Boolean): String {
        if (!gesture) {
            device.pressBack()
            return "the Back key"
        }
        val y = device.displayHeight / 2
        val x = device.displayWidth / 3
        shellText("input swipe 1 $y $x $y $SWIPE_MS")
        return "a swipe from (1, $y) to ($x, $y) over $SWIPE_MS ms, navigation_mode " + shellText("settings get secure navigation_mode")
    }

    /** Whether condition holds within seconds, polled; no failure of its own. */
    private fun within(seconds: Long, condition: () -> Boolean): Boolean {
        val end = SystemClock.elapsedRealtime() + seconds * 1_000
        while (!condition()) {
            if (SystemClock.elapsedRealtime() > end) return false
            SystemClock.sleep(200)
        }
        return true
    }

    /**
     * The facts SystemUI's dump gives about its back gesture handler (EdgeBackGestureHandler, on both levels): whether it
     * is enabled and attached, its edge widths and insets, the regions excluded and its log of recent gestures with
     * why each was or was not taken. System state only: nothing of the app's.
     */
    private fun edgeBackFacts(): String {
        val dump = shellText("dumpsys activity service com.android.systemui").lines()
        val start = dump.indexOfFirst { "EdgeBackGestureHandler" in it }
        if (start < 0) return "no EdgeBackGestureHandler in SystemUI's dump (" + dump.size + " lines)"
        return dump.drop(start).take(EDGE_DUMP_LINES).map { it.trim() }
            .filter { line -> EDGE_FACTS.any { it in line } }
            .joinToString("; ")
    }

    /** A moment for a Back that must do nothing to land. */
    private fun settle() {
        device.waitForIdle()
        SystemClock.sleep(1_000)
    }

    private fun stage(activity: MainActivity): Stage =
        onMain { ActivityLifecycleMonitorRegistry.getInstance().getLifecycleStageOf(activity) }

    private fun <T> done(reply: Reply<T>): T = (reply as? Reply.Done)?.value ?: throw AssertionError("core refused the call (its reply is not printed)")

    private companion object {
        /** How long SystemUI is given to take up gesture navigation once the setting reads it. */
        const val SETTLE_GESTURE_MS = 3_000L

        /** The back swipe's length in time, and the same through UiAutomation (5 ms a step). */
        const val SWIPE_MS = 300
        const val SWIPE_STEPS = 60

        /** How long a back gesture's Back is waited for before SystemUI's facts are gathered. */
        const val BACK_SECONDS = 5L

        /** How much of SystemUI's dump after the handler's heading is read, and the fields kept from it. */
        const val EDGE_DUMP_LINES = 80
        val EDGE_FACTS = listOf(
            "mIsEnabled", "mIsAttached", "mIsGesturalModeEnabled", "mIsBackGestureAllowed", "mAllowGesture", "mDisabledForQuickstep",
            "mIsNavBarShownTransiently", "mEdgeWidth", "mLeftInset", "mRightInset", "mExcludeRegion", "mUnrestrictedExcludeRegion",
            "mInRejectedExclusion", "mIsInPip", "mPredictiveBack", "mUseMLModel", "Gesture [", "mGestureLog",
        )

        /** navigation_mode's gesture navigation, and the system's overlays that switch it. */
        const val GESTURE = "2"
        const val GESTURAL = "com.android.internal.systemui.navbar.gestural"
        const val THREE_BUTTON = "com.android.internal.systemui.navbar.threebutton"

        /** dice-50-words12's 50 rolls: its pattern repeated. */
        val ROLLS_50 = DICE_50_ROLLS.repeat(9).take(50)

        /** Rolls made before leaving. */
        const val ROLLS = 10

        /** How long the screen stays off on the dice: well under the 60 s rule. */
        const val AWAY_MS = 5_000L
    }
}
