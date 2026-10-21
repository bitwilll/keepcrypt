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
import com.keepcrypt.entropy.Capture.launch
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.openRecents
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
import com.keepcrypt.entropy.ffi.KcHalt
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Words
import com.keepcrypt.entropy.screens.Overlay
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.screens.screenId
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The capture harness on the app (tasks/todo.md, M5 group 6; gate item 1), run once per app APK by
 * scripts/android-instrument.sh. Every capture of the app comes after the drawn-screen proof, so a
 * black capture means the screen was protected, not that it was never drawn. The positive control
 * (a), the same captures finding capture-control's pixels, is ControlTest, which runs before this
 * class; scripts/android-emulator.sh then clears capture-control's data (pm clear), which takes its
 * tasks out of the recents list, so that none of them is in the recents view here.
 */
@RunWith(AndroidJUnit4::class)
class CaptureTest {
    private val pkg get() = Capture.instrumentation.targetContext.packageName

    /** Holds the long call that keeps the self-test's screen up for its captures; released after them. */
    private val selfTest = CountDownLatch(1)

    /** Holds the long call that keeps "Working..." up for its captures; released after them. */
    private val working = CountDownLatch(1)

    /** The one activity the every-screen pass walks, from First launch to the stop screen. */
    private var walk: MainActivity? = null

    /**
     * Brings screen up in the walk's one activity, from the screen before it in Screen's order (the
     * ceremony's, lead decision M5-50), through the model's entry points as the screens call them. The
     * when is exhaustive: a new screen without a way here fails to compile, and one out of order finds
     * the model on another screen, which ignores the press, so its drawn-screen proof times out. The
     * self-test's screen and "Working..." are long calls held on the worker, as the model makes every
     * long call (the real start-up self-test is over before a capture could start): the held one goes
     * back to First launch when let go, whose Continue then runs the real self-test to Go offline. The
     * stop screen is the halt status as Core throws it, so this process's slot stays live for the tests
     * after it (the model's own tests halt a real one). Home on needs the phone offline, which the pass
     * sees to.
     */
    private fun show(screen: Screen): MainActivity {
        val activity = if (screen == Screen.FirstLaunch) started().also { walk = it } else checkNotNull(walk)
        val model = activity.model
        when (screen) {
            Screen.FirstLaunch -> {}
            Screen.SelfTest -> onMain { model.work({ selfTest.await(); Reply.Done(Unit) }, busy = Screen.SelfTest) {} }
            Screen.GoOffline -> {
                selfTest.countDown()
                waitUntil("First launch again, after the held call") { onMain { activity.shownScreen } == Screen.FirstLaunch }
                onMain { model.firstLaunchDone() }
                waitUntil("the start-up self-test passed", START_SECONDS) { onMain { activity.shownScreen } == Screen.GoOffline }
            }
            Screen.Home -> onMain { model.startOffline() }
            Screen.Length -> onMain { model.chooseMode(Mode.Mixed) }
            Screen.DeviceEntropy -> onMain { model.chooseLength(Words.Twelve) }
            Screen.Commitment -> onMain { model.deviceEntropyDone() }
            Screen.Dice -> onMain { model.commitmentDone() }
            Screen.Working -> onMain { model.work({ working.await(); Reply.Done(Unit) }) {} }
            Screen.Stop -> {
                working.countDown()
                waitUntil("the dice again, after the held call") { onMain { activity.shownScreen } == Screen.Dice }
                onMain { model.work<Unit>({ throw KcHalt() }) {} }
            }
        }
        return activity
    }

    /** A new MainActivity on its first screen, First launch, which shows before any core call. */
    private fun started(): MainActivity {
        val activity = launch()
        waitUntil("the first screen") { onMain { activity.shownScreen } == Screen.FirstLaunch }
        return activity
    }

    /**
     * For every screen id, in one activity walked through the ceremony with the phone offline (group
     * 15): drawn, then black over the app's window in the shell's screencap and in
     * UiAutomation.takeScreenshot(), FLAG_SECURE in the window's own flags, the root view opted out of
     * content capture (read back in-process, group 14), and SECURE on every window of the package in
     * dumpsys window windows, found by its owner line too (the owner line is shown to be read on this
     * image: some window is found by it).
     */
    @Test
    fun everyScreenIsDrawnAndThenBlackInEveryCapture() {
        Capture.whileOffline { walkEveryScreen() }
    }

    private fun walkEveryScreen() {
        for (screen in Screen.entries) {
            val activity = show(screen)
            proveDrawn(activity, screen)
            val region = region(activity)
            val display = display(activity)
            report("kc_region", "${region.left},${region.top},${region.right},${region.bottom}")
            report("kc_display", "${display.width()}x${display.height()}")
            val cap = Capture.screencapOrRefused()
            val shot = Capture.screenshotOrRefused()
            if (cap != null) Capture.assertCaptureSize(cap, display, "screencap")
            if (shot != null) Capture.assertCaptureSize(shot, display, "takeScreenshot")
            val capLit = Capture.litOrRefused(cap, region)
            val shotLit = Capture.litOrRefused(shot, region)
            val flagged = onMain { activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0 }
            val contentCapture = onMain { activity.window.decorView.importantForContentCapture }
            val found = windows(pkg)
            probe("screencap -p: ${Capture.described(cap)}; takeScreenshot(): ${Capture.described(shot)}")
            probe("${screenId(screen)}: $capLit lit pixels in screencap, $shotLit in takeScreenshot over the app's window $region")
            assertEquals("lit pixels in screencap over the app's window", 0, capLit)
            assertEquals("lit pixels in takeScreenshot over the app's window", 0, shotLit)
            assertTrue("the window's flags lack FLAG_SECURE", flagged)
            assertEquals(
                "the root view does not opt out of content capture",
                View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS, contentCapture,
            )
            assertTrue("dumpsys window windows lists no window of the app", found.isNotEmpty())
            assertTrue("no window's owner line names the app: windows are found by title alone", found.any { it.byOwner })
            probe("windows of the app: " + found.joinToString("; ") { "${it.title} (by owner ${it.byOwner}, SECURE ${it.secure})" })
            for (w in found) assertTrue("a window without SECURE: " + w.title, w.secure)
            pass(
                "${screenId(screen)}: drawn, then screencap and takeScreenshot black over the app's window; " +
                    "SECURE on all ${found.size} of its windows; no content capture",
            )
        }
        finish(checkNotNull(walk))
    }

    /**
     * The recents thumbnail is the placeholder: in the recents view, opened from the drawn first
     * screen and proven on screen (Capture.openRecents), no pixel has the known colour of its content
     * (ControlTest finds it in the control's).
     */
    @Test
    fun theRecentsThumbnailIsThePlaceholder() {
        val activity = launch()
        proveDrawn(activity, Screen.FirstLaunch)
        val device = UiDevice.getInstance(Capture.instrumentation)
        openRecents(device)
        val cap = Capture.screencapOrRefused()
        val shot = Capture.screenshotOrRefused()
        val inCap = Capture.knownOrRefused(cap)
        val inShot = Capture.knownOrRefused(shot)
        device.pressHome()
        probe(
            "recents: screencap ${Capture.described(cap)}, $inCap known-colour pixels; " +
                "takeScreenshot ${Capture.described(shot)}, $inShot",
        )
        assertTrue("the recents view shows the app's content", inCap < KNOWN_MIN_RECENTS && inShot < KNOWN_MIN_RECENTS)
        pass("recents: the thumbnail shows none of the app's content")
        finish(activity)
    }

    /**
     * The privacy cover carries the TEST REGISTRY strip in the test-registry APK, as every screen does,
     * and nothing shows one in the shipping APK (Q60, lead decision M5-51). The app is left from its
     * drawn first screen (Home) and brought back (am start, the task to the front, as LifecycleTest
     * returns), so the cover is up; UI Automator then finds the cover by its resource id and, inside
     * it, the strip, or no strip anywhere in the shipping APK. The idle warning draws its strip
     * through the same overlay composable, but no emulator test reaches it (nine minutes without
     * input while a session is held).
     */
    @Test
    fun theCoverCarriesTheStripOnlyInTheTestRegistryApk() {
        val registry = pkg == REGISTRY_PACKAGE
        val activity = launch()
        proveDrawn(activity, Screen.FirstLaunch)
        val device = UiDevice.getInstance(Capture.instrumentation)
        device.pressHome()
        waitUntil("the app left") { stage(activity) == Stage.STOPPED }
        shellText("am start -n $pkg/com.keepcrypt.entropy.MainActivity")
        waitUntil("back in the app, covered") {
            stage(activity) == Stage.RESUMED && onMain { activity.model.state.value.overlay } == Overlay.Cover
        }
        proveDrawn(activity, Screen.FirstLaunch)
        val cover = device.wait(Until.findObject(By.res("cover")), 10_000) ?: throw AssertionError("the cover is not on screen")
        // The cover's tap merges its content into one node: the strip is the cover's when UI Automator
        // finds it under that node, or when the node's own text (its merged label) is the strip's.
        val under = cover.hasObject(By.res(STRIP))
        val label = (cover.text ?: "").contains(STRIP_TEXT)
        val anywhere = device.hasObject(By.res(STRIP)) || device.hasObject(By.text(STRIP_TEXT))
        probe(
            "cover (${if (registry) "test-registry" else "shipping"} APK): the strip under it: $under; its text names the strip: " +
                "$label; a strip on screen: $anywhere",
        )
        if (registry) {
            assertTrue("the cover lacks the TEST REGISTRY strip in the test-registry APK", under || label)
        } else {
            assertFalse("a TEST REGISTRY strip on screen in the shipping APK", anywhere || label)
        }
        cover.click()
        waitUntil("the cover taken away") { onMain { activity.model.state.value.overlay } == null }
        if (registry) {
            pass("the cover carries the TEST REGISTRY strip in the test-registry APK")
        } else {
            pass("no TEST REGISTRY strip on the cover or the screen under it in the shipping APK")
        }
        finish(activity)
    }

    private fun stage(activity: MainActivity): Stage =
        onMain { ActivityLifecycleMonitorRegistry.getInstance().getLifecycleStageOf(activity) }

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
            // Where the platform reads the setting (enforced), the captures must be images; on API 31
            // a refusal is recorded as showing nothing.
            val cap = if (enforced) screencap() else Capture.screencapOrRefused()
            val shot = if (enforced) screenshot() else Capture.screenshotOrRefused()
            intArrayOf(
                Capture.knownOrRefused(cap), Capture.knownOrRefused(shot),
                Capture.litOrRefused(cap, region), Capture.litOrRefused(shot, region),
            )
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
        assertEquals("lit pixels in screencap after the setting went back", 0, Capture.litOrRefused(Capture.screencapOrRefused(), region))
        assertEquals(
            "lit pixels in takeScreenshot after the setting went back", 0,
            Capture.litOrRefused(Capture.screenshotOrRefused(), region),
        )
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
     * and stays black. A crash would also fail android-instrument.sh's judge. The recreation is a
     * configuration change, which is no leaving of the app (group 14): the new activity has the same
     * ceremony model (the ViewModel outlived the change), and that model took no stop for a leave, so
     * no cover is up and nothing was wiped.
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
        assertEquals("lit pixels in screencap after the recreation", 0, Capture.litOrRefused(Capture.screencapOrRefused(), region(again)))
        assertTrue("the recreated activity has another ceremony model", onMain { again.model === first.model })
        val state = onMain { again.model.state.value }
        assertEquals("the configuration change was taken for leaving the app (a cover is up)", null, state.overlay)
        assertEquals("the configuration change wiped the session", null, state.notice)
        probe("empty saved-state Bundle: the activity was recreated from it and drew its first screen again, secure; nothing crashed")
        pass("the empty saved-state Bundle: recreated, drawn, black; the same model, no leaving taken, nothing wiped")
        finish(again)
    }

    /**
     * No content capture of the app (group 14, SecureActivity): with its first screen drawn, `dumpsys
     * content_capture` names the package on no line. The plan asks this only where the image runs a
     * capture service: where it runs none (as the probe found on API 31), the dump is empty or says
     * dumpsys can't find the service, and has nothing to name the app in, so the test passes with a
     * probe line saying it proved nothing here and no pass line. The root's own flag is read back in
     * everyScreenIsDrawnAndThenBlackInEveryCapture.
     */
    @Test
    fun contentCaptureHasNothingOfTheApp() {
        val activity = launch()
        proveDrawn(activity, Screen.FirstLaunch)
        val (out, err) = Capture.shellWithErrors("dumpsys content_capture")
        val dump = String(out, Charsets.UTF_8).lines().filter { it.isNotBlank() }
        val absent = String(err, Charsets.UTF_8).contains(NO_SERVICE) || dump.any { it.contains(NO_SERVICE) }
        val service = dump.isNotEmpty() && !absent
        val naming = dump.filter { it.contains(pkg) }
        probe(
            "dumpsys content_capture: the service ${if (service) "answers" else "is absent"}; ${dump.size} lines, " +
                "${naming.size} naming the app: " + naming.joinToString(" | ") { it.trim() },
        )
        assertTrue("dumpsys content_capture names the app", naming.isEmpty())
        if (service) {
            pass("content capture: the service answers and no line of dumpsys content_capture names the app")
        } else {
            probe("content capture: no content_capture service on this image, so nothing names the app: not proven here")
        }
        finish(activity)
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
        /** The start-up self-test's time limit (a translated library is slower; NativeTest's). */
        const val START_SECONDS = 120

        const val SENSITIVE_NODE = "kc_probe_data_sensitive"

        /** The test-registry APK's package (the withTestRegistry flavour's applicationId). */
        const val REGISTRY_PACKAGE = "com.keepcrypt.entropy.testregistry"

        /** The TEST REGISTRY strip's resource id and text (Kit.kt's TestRegistryStrip). */
        const val STRIP = "test_registry_strip"
        const val STRIP_TEXT = "TEST REGISTRY"

        /** What dumpsys says (on stderr) for a service the image does not run. */
        const val NO_SERVICE = "Can't find service"
    }
}
