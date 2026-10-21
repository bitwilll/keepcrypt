package com.keepcrypt.entropy

import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.keepcrypt.entropy.Capture.launch
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.probe
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
 * during the test and is gone, no crash or not-responding window opened, logcat's crash buffer names
 * none of our packages and DropBox gained no data_app_crash entry. The exception's text is fixed.
 * scripts/android-emulator.sh runs it last of a leg's instrumented tests.
 */
@RunWith(AndroidJUnit4::class)
class CrashTest {
    @Test
    fun anUncaughtExceptionWipesAndEndsTheProcessSilently() {
        val activity = launch()
        val end = SystemClock.elapsedRealtime() + START_MS
        while (onMain { activity.shownScreen } != Screen.FirstLaunch) {
            if (SystemClock.elapsedRealtime() > end) fail("no first screen within 120 s")
            SystemClock.sleep(100)
        }
        assertTrue("start", Core.start(Words.Twelve, Mode.DiceOnly) is Reply.Done)
        probe("crash test: a session started; an exception is thrown on the main thread next")
        Handler(Looper.getMainLooper()).post { throw IllegalStateException("KeepCrypt crash test") }
        SystemClock.sleep(WAIT_MS)
        fail("the process still runs 30 s after the uncaught exception")
    }

    private companion object {
        /** NativeTest's limit for the start-up self-test. */
        const val START_MS = 120_000L

        /** How long the process gets to end. */
        const val WAIT_MS = 30_000L
    }
}
