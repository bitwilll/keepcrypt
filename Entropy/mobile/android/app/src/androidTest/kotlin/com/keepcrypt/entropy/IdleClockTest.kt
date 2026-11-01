package com.keepcrypt.entropy

import android.os.Build
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.launch
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Capture.probe
import com.keepcrypt.entropy.GateSeeds.DICE_50_ROLLS
import com.keepcrypt.entropy.Ui.await
import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Words
import com.keepcrypt.entropy.screens.Notice
import com.keepcrypt.entropy.screens.Overlay
import com.keepcrypt.entropy.screens.Screen
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The idle rules on the phone's real clock (tasks/todo.md, Stage U's U2l; docs/pi-firmware.md, "Protected screens
 * and idle"; docs/mobile-apps.md, "Session lifetime"), once, on API 36 (the registry part's API 36 job; on any
 * other level it passes at once, saying so): a words page, a Protected screen holding a session, left untouched.
 * The cover must come at 30 s, the warning at 9 minutes and the wipe at 10, each measured on SystemClock's elapsed
 * real time (the model's clock) from the last input (the model's last press, nextPage, as its screens call it);
 * the wipe lands on Go offline with the Idle notice and the slot at home. The window keeps the screen on while
 * the session is held (M5-72 (b)), so the display does not sleep through the ten minutes. The JVM's IdleTest and
 * TimersTest hold every boundary on a fake clock; this run holds the phone's clock and the model's tick (1 s).
 */
@RunWith(AndroidJUnit4::class)
class IdleClockTest {
    @Test
    fun aWordsPageLeftUntouchedIsCoveredAt30sWarnedAt9MinutesAndWipedAt10() {
        if (Build.VERSION.SDK_INT != IDLE_API) {
            pass("the idle run on the real clock is API $IDLE_API's (U2l's one run); not made at API " + Build.VERSION.SDK_INT)
            return
        }
        Capture.whileOffline {
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
            onMain {
                for (roll in DICE_50_ROLLS.repeat(9).take(50)) {
                    activity.model.dicePick.replace(roll)
                    activity.model.confirmRoll()
                }
                activity.model.diceDone()
            }
            await("the check prompt", Ui.START_SECONDS) { onMain { activity.model.state.value.screen } == Screen.CheckPrompt }
            val lastInput = onMain {
                val model = activity.model
                model.skip()
                model.skipConfirmed()
                model.showWords()
                model.passGate()
                model.nextPage()
                SystemClock.elapsedRealtime()
            }
            assertTrue("not on insert 2's page", onMain { activity.model.state.value.let { it.screen == Screen.Words && it.page == 1 } })
            var cover = -1L
            var warning = -1L
            var wipe = -1L
            val end = lastInput + LIMIT_MS
            while (wipe < 0 && SystemClock.elapsedRealtime() < end) {
                val (state, at) = onMain { activity.model.state.value to SystemClock.elapsedRealtime() - lastInput }
                if (cover < 0 && state.overlay == Overlay.Cover) cover = at
                if (warning < 0 && state.overlay == Overlay.Warning) warning = at
                if (state.screen == Screen.GoOffline) wipe = at
                SystemClock.sleep(POLL_MS)
            }
            probe("idle on a words page, from the last input: the cover at ${cover} ms, the warning at ${warning} ms, the wipe at ${wipe} ms")
            assertTrue("the cover did not come at 30 s (${cover} ms)", cover in 30_000L..30_000L + LATE_MS)
            assertTrue("the warning did not come at 9 minutes (${warning} ms)", warning in 540_000L..540_000L + LATE_MS)
            assertTrue("the wipe did not come at 10 minutes (${wipe} ms)", wipe in 600_000L..600_000L + LATE_MS)
            assertTrue("the wipe's start screen does not say Idle", onMain { activity.model.state.value.notice } == Notice.Idle)
            assertTrue("the slot is not at home after the idle wipe", Core.selfTest() is Reply.Done)
            pass("idle on a words page on the real clock: covered at $cover ms, warned at $warning ms, wiped at $wipe ms (Go offline, Idle), the slot at home")
            finish(activity)
        }
    }

    private companion object {
        /** The one level the run is made on. */
        const val IDLE_API = 36

        /** How late a step may be seen: the model's 1 s tick and this test's poll. */
        const val LATE_MS = 2_500L

        /** How often the state is read. */
        const val POLL_MS = 200L

        /** How long the run waits for the wipe before it fails. */
        const val LIMIT_MS = 615_000L
    }
}
