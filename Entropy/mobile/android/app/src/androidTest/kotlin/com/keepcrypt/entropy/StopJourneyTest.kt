package com.keepcrypt.entropy

import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.keepcrypt.entropy.Capture.launch
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Ui.START_SECONDS
import com.keepcrypt.entropy.Ui.awaitText
import com.keepcrypt.entropy.Ui.device
import com.keepcrypt.entropy.Ui.on
import com.keepcrypt.entropy.Ui.stays
import com.keepcrypt.entropy.Ui.tap
import com.keepcrypt.entropy.ffi.HaltReason
import com.keepcrypt.entropy.ffi.KcHalt
import com.keepcrypt.entropy.screens.Screen
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The stop journey to Close app (tasks/todo.md, Stage U's U1g; docs/mobile-apps.md, the stop screen; the
 * Pi's halt), on the shipping app in the ui part, run by scripts/android-instrument.sh's gone: form: First
 * launch's Continue tapped, the start-up self-test passed and Go offline shown; then a halt, raised
 * in-process as core raises one (KcHalt with a health test's reason, through the model's own call path,
 * as CaptureTest's walk does: no input on the screen halts the app, and a real halt would latch this
 * process's slot); the stop screen naming that reason, Back doing nothing there, and its one action,
 * Close app, tapped: the task leaves recents and the process ends (MainActivity.closeApp), so this test
 * never ends by itself. It is judged from the shell: the process ended during the test with no crash,
 * no crash or not-responding window, the crash buffer and DropBox clean. Nothing is offline here, so no
 * phone setting needs putting back after the process has gone.
 */
@RunWith(AndroidJUnit4::class)
class StopJourneyTest {
    @Test
    fun aHaltShowsTheStopScreenWhoseCloseAppEndsTheProcess() {
        val activity = launch()
        on(activity, Screen.FirstLaunch)
        tap("first_launch_continue")
        on(activity, Screen.GoOffline, START_SECONDS)
        onMain { activity.model.work<Unit>({ throw KcHalt(HaltReason.HealthTest) }) {} }
        on(activity, Screen.Stop)
        awaitText("halt_reason", STOP_LINE)
        assertTrue("the stop screen holds something", onMain { !activity.model.held.value })
        device.pressBack()
        stays(activity, Screen.Stop, "Back on the stop screen")
        pass("stop: the halt's stop screen names its reason (a health test's), holds nothing, and Back does nothing; Close app next")
        tap("close_app")
        SystemClock.sleep(WAIT_MS)
        fail("the process still runs 30 s after Close app")
    }

    private companion object {
        /** The stop screen's line for a health test's halt (Screens.kt's stopLine), fixed text. */
        const val STOP_LINE = "An entropy health test failed."

        /** How long the process gets to end. */
        const val WAIT_MS = 30_000L
    }
}
