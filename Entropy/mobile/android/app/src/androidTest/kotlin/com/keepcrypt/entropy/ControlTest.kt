package com.keepcrypt.entropy

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.uiautomator.UiDevice
import com.keepcrypt.entropy.Capture.CONTROL_PACKAGE
import com.keepcrypt.entropy.Capture.KNOWN_MIN
import com.keepcrypt.entropy.Capture.KNOWN_MIN_RECENTS
import com.keepcrypt.entropy.Capture.display
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.knownPixels
import com.keepcrypt.entropy.Capture.launch
import com.keepcrypt.entropy.Capture.litPixels
import com.keepcrypt.entropy.Capture.openRecents
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Capture.probe
import com.keepcrypt.entropy.Capture.proveDrawn
import com.keepcrypt.entropy.Capture.region
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
 * pixels here, through the same calls, and lit pixels over the very region (the app's window, from
 * Capture.region) whose lit-pixel count CaptureTest asserts is 0; a missing control fails the job.
 * The window parser must also tell its window apart (no SECURE). Run once per emulator, after
 * CaptureTest on both apps (the control's recents thumbnail would otherwise sit beside the app's
 * there). The raw-frame half of the control is scripts/android-emulator.sh's.
 */
@RunWith(AndroidJUnit4::class)
class ControlTest {
    @Test
    fun theSameCapturesShowTheControlsScreen() {
        // The region CaptureTest's black assertions read: the app's window, its first screen drawn.
        val app = launch()
        proveDrawn(app, Screen.FirstLaunch)
        val region = region(app)
        val display = display(app)
        finish(app)
        startControl()
        val cap = screencap()
        val shot = screenshot()
        Capture.assertCaptureSize(cap, display, "screencap")
        Capture.assertCaptureSize(shot, display, "takeScreenshot")
        val inCap = knownPixels(cap)
        val inShot = knownPixels(shot)
        val capLit = litPixels(cap, region)
        val shotLit = litPixels(shot, region)
        val found = windows(CONTROL_PACKAGE)
        probe(
            "capture control: $inCap known-colour pixels in screencap, $inShot in takeScreenshot; $capLit and $shotLit lit " +
                "pixels over the app's window $region; ${found.size} window(s), ${found.count { it.secure }} with SECURE",
        )
        assertTrue("screencap does not show the capture control's screen", inCap >= KNOWN_MIN)
        assertTrue("takeScreenshot does not show the capture control's screen", inShot >= KNOWN_MIN)
        assertTrue("screencap has no lit pixel over the app's window region", capLit > 0)
        assertTrue("takeScreenshot has no lit pixel over the app's window region", shotLit > 0)
        assertTrue("dumpsys window windows lists no window of the capture control", found.isNotEmpty())
        assertTrue("no window's owner line names the capture control", found.any { it.byOwner })
        for (w in found) assertTrue("the capture control's window has SECURE: " + w.title, !w.secure)
        pass("control (a): screencap and takeScreenshot show the capture control's screen, lit over the app's window region; its windows lack SECURE")
        UiDevice.getInstance(Capture.instrumentation).pressHome()
    }

    /**
     * In the recents view, proven on screen (Capture.openRecents), the control's thumbnail shows its
     * known colour, and fewer such pixels than its whole screen showed just before: a scaled
     * thumbnail, not the live window left in front.
     */
    @Test
    fun theRecentsThumbnailShowsTheControlsScreen() {
        startControl()
        val full = knownPixels(screencap())
        val device = UiDevice.getInstance(Capture.instrumentation)
        openRecents(device)
        val inCap = knownPixels(screencap())
        device.pressHome()
        probe("capture control in recents: $inCap known-colour pixels in screencap, $full on its whole screen before")
        assertTrue("screencap does not show the capture control's screen", full >= KNOWN_MIN)
        assertTrue("the recents view does not show the capture control's screen", inCap >= KNOWN_MIN_RECENTS)
        assertTrue("the recents view shows the control's whole screen, not a thumbnail", inCap * 10 < full * 9)
        pass("control (a): the recents thumbnail shows the capture control's screen")
    }
}
