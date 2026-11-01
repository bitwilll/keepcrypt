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
 * Public screen, which is covered and kept (under the 60 s rule); the activity destroyed while away (Android's
 * "Don't keep activities", always_finish_activities, put back in a finally); and the back gesture (a swipe from
 * the left edge under gesture navigation, KEYCODE_BACK otherwise) doing what the model's back does. Setup goes
 * through the model's entry points, as LifecycleTest's does (an edge test; the journeys are the UI's alone), with
 * vectors/kcr.json's dice-50-words12 rolls; only screen ids, notices, counts and times are printed.
 */
@RunWith(AndroidJUnit4::class)
class AwayTest {
    private val component get() = Capture.instrumentation.targetContext.packageName + "/com.keepcrypt.entropy.MainActivity"

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
    fun theActivityDestroyedWhileAwayLeavesNoSession() {
        val before = shellText("settings get global always_finish_activities")
        try {
            shellText("settings put global always_finish_activities 1")
            Capture.whileOffline {
                val activity = toDice()
                roll(activity, ROLLS)
                val model = activity.model
                device.pressHome()
                await("the activity destroyed while away", 30) { onMain { activity.isDestroyed } }
                val heldAway = onMain { model.held.value }
                shellText("am start -n $component")
                var next: MainActivity? = null
                await("a new MainActivity resumed", 30) {
                    next = onMain {
                        ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(Stage.RESUMED)
                            .filterIsInstance<MainActivity>().firstOrNull { it !== activity }
                    }
                    next != null
                }
                val back = checkNotNull(next)
                await("the new activity's first screen", 10) { onMain { back.shownScreen } != null }
                val shown = onMain { back.shownScreen }
                val home = Core.selfTest() is Reply.Done
                probe(
                    "the activity destroyed while away: the old model held " + (if (heldAway) "a session" else "nothing") +
                        " once destroyed; the new activity has " + (if (onMain { back.model } === model) "the same model" else "a new model") +
                        ", shows " + (shown?.let(::screenId) ?: "nothing") + ", the slot " + (if (home) "at home" else "not at home"),
                )
                assertTrue("the old activity's model still holds the session after its activity was destroyed", !heldAway)
                assertTrue("the slot is not at home: the session outlived its activity", home)
                assertEquals("the return does not show the first screen", Screen.FirstLaunch, shown)
                pass("the activity destroyed while away: its model's end emptied the slot; back, a new activity on First launch")
                finish(back)
            }
        } finally {
            shellText("settings put global always_finish_activities " + if (before == "1") "1" else "0")
        }
    }

    @Test
    fun theBackGestureDoesWhatBackDoes() {
        val gesture = shellText("settings get secure navigation_mode") == "2"
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
            back(gesture)
            await("Back from the check QR to the seal card", 10) { onMain { activity.model.state.value.screen } == Screen.SealCard }
            back(gesture)
            settle()
            assertEquals("Back on the seal card left it", Screen.SealCard, onMain { activity.model.state.value.screen })
            pass("the system Back by " + (if (gesture) "the gesture (a swipe from the left edge)" else "the key (three-button navigation)") +
                ": nothing on the dice and the seal card, the check QR back to the seal card")
            finish(activity)
        }
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

    /** The system Back: a swipe in from the left edge under gesture navigation, the Back key otherwise. */
    private fun back(gesture: Boolean) {
        if (gesture) {
            val y = device.displayHeight / 2
            device.swipe(1, y, device.displayWidth / 2, y, 20)
        } else {
            device.pressBack()
        }
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
        /** dice-50-words12's 50 rolls: its pattern repeated. */
        val ROLLS_50 = DICE_50_ROLLS.repeat(9).take(50)

        /** Rolls made before leaving. */
        const val ROLLS = 10

        /** How long the screen stays off on the dice: well under the 60 s rule. */
        const val AWAY_MS = 5_000L
    }
}
