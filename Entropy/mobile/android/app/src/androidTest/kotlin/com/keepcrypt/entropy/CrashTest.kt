package com.keepcrypt.entropy

import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.keepcrypt.entropy.Capture.launch
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.probe
import com.keepcrypt.entropy.Capture.waitUntil
import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Words
import com.keepcrypt.entropy.screens.Screen
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The crash path on the phone (tasks/todo.md, M5 group 14), the androidTest-only trigger: with a
 * session in the slot, an exception thrown on the main thread reaches the app's handler (KeepCryptApp),
 * which wipes the slot and kills the process, so this test never ends by itself. It is judged from the
 * shell (scripts/android-instrument.sh, as killed:com.keepcrypt.entropy.CrashTest): the process ended
 * during the test and is gone, no crash or not-responding window opened, DropBox gained no
 * data_app_crash entry, and logcat's crash buffer holds exactly one crash of our packages, this one:
 * Android's own pre-handler, which apps cannot replace, logs it before the app's handler runs (Q75, an
 * accepted residual), so the judge requires the exception's fixed text and nothing else of ours.
 * scripts/android-emulator.sh runs it last of the API 31 and 36 legs' instrumented tests (the 16
 * KB-page leg runs NativeTest alone).
 */
@RunWith(AndroidJUnit4::class)
class CrashTest {
    @Test
    fun anUncaughtExceptionWipesAndEndsTheProcessSilently() {
        // The app up on First launch, where the model has made no core call and runs none, so the
        // session started here is the slot's only use (lead decision M5-50).
        val activity = launch()
        waitUntil("the first screen, First launch") { onMain { activity.shownScreen } == Screen.FirstLaunch }
        assertTrue("start", Core.start(Words.Twelve, Mode.DiceOnly) is Reply.Done)
        probe("crash test: a session started; an exception is thrown on the main thread next")
        Handler(Looper.getMainLooper()).post { throw IllegalStateException("KeepCrypt crash test") }
        SystemClock.sleep(WAIT_MS)
        fail("the process still runs 30 s after the uncaught exception")
    }

    private companion object {
        /** How long the process gets to end. */
        const val WAIT_MS = 30_000L
    }
}
