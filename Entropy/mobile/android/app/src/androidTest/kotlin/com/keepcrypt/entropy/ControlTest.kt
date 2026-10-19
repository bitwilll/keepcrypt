package com.keepcrypt.entropy

import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.uiautomator.UiDevice
import com.keepcrypt.entropy.Capture.CONTROL_PACKAGE
import com.keepcrypt.entropy.Capture.KNOWN_MIN
import com.keepcrypt.entropy.Capture.KNOWN_MIN_RECENTS
import com.keepcrypt.entropy.Capture.SETTLE_MS
import com.keepcrypt.entropy.Capture.knownPixels
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Capture.probe
import com.keepcrypt.entropy.Capture.screencap
import com.keepcrypt.entropy.Capture.screenshot
import com.keepcrypt.entropy.Capture.startControl
import com.keepcrypt.entropy.Capture.windows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Positive control (a) (tasks/todo.md, M5 group 6): capture-control draws the app's first screen with
 * the same composable and no FLAG_SECURE, so the captures CaptureTest finds black must find its known
 * pixels here, through the same calls; a missing control fails the job. The window parser must also
 * tell its window apart (no SECURE). Run once per emulator, after CaptureTest on both apps (the
 * control's recents thumbnail would otherwise sit beside the app's there). The raw-frame half of the
 * control is scripts/android-emulator.sh's.
 */
@RunWith(AndroidJUnit4::class)
class ControlTest {
    @Test
    fun theSameCapturesShowTheControlsScreen() {
        startControl()
        val inCap = knownPixels(screencap())
        val inShot = knownPixels(screenshot())
        val found = windows(CONTROL_PACKAGE)
        probe("capture control: $inCap known-colour pixels in screencap, $inShot in takeScreenshot; ${found.size} window(s), ${found.count { it.secure }} with SECURE")
        assertTrue("screencap does not show the capture control's screen", inCap >= KNOWN_MIN)
        assertTrue("takeScreenshot does not show the capture control's screen", inShot >= KNOWN_MIN)
        assertTrue("dumpsys window windows lists no window of the capture control", found.isNotEmpty())
        for (w in found) assertTrue("the capture control's window has SECURE: " + w.title, !w.secure)
        pass("control (a): screencap and takeScreenshot show the capture control's screen; its windows lack SECURE")
        UiDevice.getInstance(Capture.instrumentation).pressHome()
    }

    @Test
    fun theRecentsThumbnailShowsTheControlsScreen() {
        startControl()
        val device = UiDevice.getInstance(Capture.instrumentation)
        assertTrue("the recents key was not sent", device.pressRecentApps())
        device.waitForIdle()
        SystemClock.sleep(2 * SETTLE_MS)
        val inCap = knownPixels(screencap())
        device.pressHome()
        probe("capture control in recents: $inCap known-colour pixels in screencap")
        assertTrue("the recents view does not show the capture control's screen", inCap >= KNOWN_MIN_RECENTS)
        pass("control (a): the recents thumbnail shows the capture control's screen")
    }
}
