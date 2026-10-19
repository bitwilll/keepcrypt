package com.keepcrypt.entropy

import android.os.Build
import android.os.SystemClock
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import com.keepcrypt.entropy.Capture.KNOWN_MIN
import com.keepcrypt.entropy.Capture.KNOWN_MIN_RECENTS
import com.keepcrypt.entropy.Capture.SETTLE_MS
import com.keepcrypt.entropy.Capture.display
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.knownPixels
import com.keepcrypt.entropy.Capture.launch
import com.keepcrypt.entropy.Capture.litPixels
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Capture.probe
import com.keepcrypt.entropy.Capture.proveDrawn
import com.keepcrypt.entropy.Capture.region
import com.keepcrypt.entropy.Capture.report
import com.keepcrypt.entropy.Capture.screencap
import com.keepcrypt.entropy.Capture.screenshot
import com.keepcrypt.entropy.Capture.shell
import com.keepcrypt.entropy.Capture.shellText
import com.keepcrypt.entropy.Capture.waitUntil
import com.keepcrypt.entropy.Capture.windows
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The capture harness on the app (tasks/todo.md, M5 group 6; gate item 1), run once per app APK by
 * scripts/android-instrument.sh. Every capture of the app comes after the drawn-screen proof, so a
 * black capture means the screen was protected, not that it was never drawn. The positive control
 * (a), the same captures finding capture-control's pixels, is ControlTest, which runs after this
 * class so that no task of the control is in the recents list here.
 */
@RunWith(AndroidJUnit4::class)
class CaptureTest {
    private val pkg get() = Capture.instrumentation.targetContext.packageName

    /** Brings screen up. The when is exhaustive: a new screen without a way here fails to compile. */
    private fun show(screen: Screen): MainActivity = when (screen) {
        Screen.FirstLaunch -> launch()
    }

    /**
     * For every screen id: drawn, then black over the app's window in the shell's screencap and in
     * UiAutomation.takeScreenshot(), FLAG_SECURE in the window's own flags, and SECURE on every window
     * of the package in dumpsys window windows.
     */
    @Test
    fun everyScreenIsDrawnAndThenBlackInEveryCapture() {
        for (screen in Screen.entries) {
            val activity = show(screen)
            proveDrawn(activity, screen)
            val region = region(activity)
            val display = display(activity)
            report("kc_region", "${region.left},${region.top},${region.right},${region.bottom}")
            report("kc_display", "${display.width()}x${display.height()}")
            val cap = screencap()
            val shot = screenshot()
            Capture.assertCaptureSize(cap, display, "screencap")
            Capture.assertCaptureSize(shot, display, "takeScreenshot")
            val capLit = litPixels(cap, region)
            val shotLit = litPixels(shot, region)
            val flagged = onMain { activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0 }
            val found = windows(pkg)
            probe("screencap -p: a ${cap.width}x${cap.height} PNG; takeScreenshot(): ${shot.width}x${shot.height}")
            probe("${screenId(screen)}: $capLit lit pixels in screencap, $shotLit in takeScreenshot over the app's window $region")
            assertEquals("lit pixels in screencap over the app's window", 0, capLit)
            assertEquals("lit pixels in takeScreenshot over the app's window", 0, shotLit)
            assertTrue("the window's flags lack FLAG_SECURE", flagged)
            assertTrue("dumpsys window windows lists no window of the app", found.isNotEmpty())
            for (w in found) assertTrue("a window without SECURE: " + w.title, w.secure)
            pass(
                "${screenId(screen)}: drawn, then screencap and takeScreenshot black over the app's window; " +
                    "SECURE on all ${found.size} of its windows",
            )
            finish(activity)
        }
    }

    /**
     * The recents thumbnail is the placeholder: in the recents view, opened from the drawn first
     * screen, no pixel has the known colour of its content (ControlTest finds it in the control's).
     */
    @Test
    fun theRecentsThumbnailIsThePlaceholder() {
        val activity = launch()
        proveDrawn(activity, Screen.FirstLaunch)
        val device = UiDevice.getInstance(Capture.instrumentation)
        assertTrue("the recents key was not sent", device.pressRecentApps())
        device.waitForIdle()
        SystemClock.sleep(2 * SETTLE_MS)
        val inCap = knownPixels(screencap())
        val inShot = knownPixels(screenshot())
        device.pressHome()
        probe("recents: $inCap known-colour pixels in screencap, $inShot in takeScreenshot")
        assertTrue("the recents view shows the app's content", inCap < KNOWN_MIN_RECENTS && inShot < KNOWN_MIN_RECENTS)
        pass("recents: the thumbnail shows none of the app's content")
        finish(activity)
    }

    /**
     * Positive control (c), API 36 only, where the platform reads the setting (Android 15 added it):
     * disable_secure_windows is unset or 0 first; set to 1, the app's own captures (screencap and
     * takeScreenshot) show its screen, both its known colour and lit pixels over the region the
     * black assertions read, so litPixels and region are shown to see a screen that is drawn; back
     * as it was, black again. On API 31 the same steps run as a probe of whether the setting is read
     * there, and only the black-again check is asserted.
     */
    @Test
    fun disableSecureWindowsShowsTheScreenOnlyWhileSet() {
        val enforced = Build.VERSION.SDK_INT >= Build.VERSION_CODES.BAKLAVA
        val before = shellText("settings get secure disable_secure_windows")
        probe("disable_secure_windows: $before before the test; ro.debuggable=${shellText("getprop ro.debuggable")}")
        if (enforced) assertTrue("disable_secure_windows is set before the test", before == "null" || before == "0")
        val activity = launch()
        proveDrawn(activity, Screen.FirstLaunch)
        val region = region(activity)
        val shown = try {
            shell("settings put secure disable_secure_windows 1")
            SystemClock.sleep(2 * SETTLE_MS)
            proveDrawn(activity, Screen.FirstLaunch)
            val cap = screencap()
            val shot = screenshot()
            intArrayOf(knownPixels(cap), knownPixels(shot), litPixels(cap, region), litPixels(shot, region))
        } finally {
            if (before == "null") shell("settings delete secure disable_secure_windows")
            else shell("settings put secure disable_secure_windows " + before)
        }
        val (capKnown, shotKnown, capLit, shotLit) = shown
        val read = capKnown >= KNOWN_MIN && shotKnown >= KNOWN_MIN && capLit > 0 && shotLit > 0
        probe(
            "disable_secure_windows=1: the app's own captures show $capKnown known-colour pixels in screencap, " +
                "$shotKnown in takeScreenshot; $capLit and $shotLit lit pixels over the app's window $region (the setting is read: $read)",
        )
        if (enforced) {
            assertTrue("disable_secure_windows=1: screencap does not show the app's screen", capKnown >= KNOWN_MIN)
            assertTrue("disable_secure_windows=1: takeScreenshot does not show the app's screen", shotKnown >= KNOWN_MIN)
            assertTrue("disable_secure_windows=1: no lit pixel in screencap over the app's window", capLit > 0)
            assertTrue("disable_secure_windows=1: no lit pixel in takeScreenshot over the app's window", shotLit > 0)
        }
        SystemClock.sleep(2 * SETTLE_MS)
        proveDrawn(activity, Screen.FirstLaunch)
        assertEquals("lit pixels in screencap after the setting went back", 0, litPixels(screencap(), region))
        assertEquals("lit pixels in takeScreenshot after the setting went back", 0, litPixels(screenshot(), region))
        assertEquals("disable_secure_windows was not put back", before, shellText("settings get secure disable_secure_windows"))
        if (enforced) {
            pass("control (c): disable_secure_windows unset, then 1 shows the screen in screencap and takeScreenshot, then black again")
        } else {
            pass("disable_secure_windows probe done; black again after it")
        }
        finish(activity)
    }

    /**
     * The empty saved-state Bundle crashes nothing: the activity is recreated from what it saved
     * (SecureActivity clears it, and passes null on), draws its first screen again with FLAG_SECURE,
     * and stays black. A crash would also fail android-instrument.sh's judge.
     */
    @Test
    fun anEmptySavedStateBundleCrashesNothing() {
        val first = launch()
        proveDrawn(first, Screen.FirstLaunch)
        Capture.instrumentation.runOnMainSync { first.recreate() }
        var second: MainActivity? = null
        waitUntil("the recreated activity is resumed") {
            second = onMain {
                ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(Stage.RESUMED)
                    .filterIsInstance<MainActivity>().firstOrNull { it !== first }
            }
            second != null
        }
        val again = second!!
        proveDrawn(again, Screen.FirstLaunch)
        val flagged = onMain { again.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0 }
        assertTrue("the recreated window lacks FLAG_SECURE", flagged)
        assertEquals("lit pixels in screencap after the recreation", 0, litPixels(screencap(), region(again)))
        probe("empty saved-state Bundle: the activity was recreated from it and drew its first screen again, secure; nothing crashed")
        pass("the empty saved-state Bundle: recreated, drawn, black")
        finish(again)
    }

    /**
     * Probe only: whether UiAutomation sees and clicks a node marked accessibility-data sensitive
     * (Android 14+), which decides whether a UI Automator smoke test on a Protected pad can run on
     * API 36 (group 6, Driving). The node is a plain button the test adds to the drawn screen.
     */
    @Test
    fun dataSensitiveNodesProbe() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            probe("data-sensitive nodes: none before Android 14 (API ${Build.VERSION.SDK_INT})")
            return
        }
        val activity = launch()
        proveDrawn(activity, Screen.FirstLaunch)
        val clicked = CountDownLatch(1)
        Capture.instrumentation.runOnMainSync {
            val node = Button(activity)
            node.contentDescription = SENSITIVE_NODE
            node.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
            node.setOnClickListener { clicked.countDown() }
            activity.addContentView(node, ViewGroup.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        }
        Capture.instrumentation.waitForIdleSync()
        val device = UiDevice.getInstance(Capture.instrumentation)
        val seen = device.wait(Until.findObject(By.desc(SENSITIVE_NODE)), 5_000)
        var reached = false
        if (seen != null) {
            seen.click()
            reached = clicked.await(5, TimeUnit.SECONDS)
        }
        probe("data-sensitive nodes on API ${Build.VERSION.SDK_INT}: UiAutomation sees one: ${seen != null}; its click reaches it: $reached")
        finish(activity)
    }

    private companion object {
        const val SENSITIVE_NODE = "kc_probe_data_sensitive"
    }
}
