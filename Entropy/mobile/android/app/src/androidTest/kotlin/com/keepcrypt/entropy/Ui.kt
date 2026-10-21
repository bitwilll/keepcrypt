package com.keepcrypt.entropy

import android.os.SystemClock
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import androidx.test.uiautomator.By
import androidx.test.uiautomator.Direction
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.UiSelector
import androidx.test.uiautomator.Until
import com.keepcrypt.entropy.Capture.launch
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.screens.screenId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail

/**
 * The flow tests' way through the Public screens (tasks/todo.md, M5 groups 15 and 16), shared by
 * FlowTest, CheckTest and SnapshotDrillTest: UI Automator taps controls by their resource ids (Compose
 * test tags, group 6) as a user would and reads what they show from the accessibility tree; the many
 * rolls a minimum takes go through the model's dice pick and confirmRoll, the entry points the pad and
 * Confirm call (group 6, "Driving").
 */
internal object Ui {
    /** The start-up self-test's and a start's time limit (a translated library is slower; NativeTest's). */
    const val START_SECONDS = 120

    /** How long a press that must do nothing gets to land. */
    private const val SETTLE_MS = 500L

    /** At most this many of shown's scrolls, each about half a text column: more than any screen here holds. */
    private const val SCROLLS = 8

    /** shown's swipe speed in pixels a second: slow, so the column stops about where the swipe lifts. */
    private const val SCROLL_SPEED = 1_000

    val device: UiDevice get() = UiDevice.getInstance(Capture.instrumentation)

    /**
     * A new MainActivity through First launch, the start-up self-test its Continue runs (lead decision
     * M5-50) and Go offline's Start (the phone offline) to Home.
     */
    fun toHome(): MainActivity {
        val activity = launch()
        on(activity, Screen.FirstLaunch)
        tap("first_launch_continue")
        on(activity, Screen.GoOffline, START_SECONDS)
        await("the app reads the phone offline", 30) { onMain { activity.model.state.value.offline } }
        tap("start")
        on(activity, Screen.Home)
        return activity
    }

    /** count rolls through the model's dice pick and confirmRoll, as the pad and Confirm call them, faces in pattern's order. */
    fun roll(activity: MainActivity, count: Int, pattern: String) {
        onMain {
            for (index in 0 until count) {
                activity.model.dicePick.replace(pattern[index % pattern.length])
                activity.model.confirmRoll()
            }
        }
    }

    /** Waits up to seconds for the activity to show screen, then for the screen to settle. */
    fun on(activity: MainActivity, screen: Screen, seconds: Int = 10) {
        await("the app shows " + screenId(screen), seconds) { onMain { activity.shownScreen } == screen }
        device.waitForIdle()
    }

    /** After a press that must do nothing: a moment for it to land, then the same screen. */
    fun stays(activity: MainActivity, screen: Screen, what: String) {
        device.waitForIdle()
        SystemClock.sleep(SETTLE_MS)
        assertEquals(what + " left the screen", screen, onMain { activity.shownScreen })
    }

    /** The control or text with resource id tag, waited for up to 10 s. */
    fun find(tag: String): UiObject2 =
        device.wait(Until.findObject(By.res(tag)), 10_000) ?: throw AssertionError("not on screen: " + tag)

    /**
     * Taps the control tag once it is on screen (find's 10 s), through a selector UI Automator resolves at
     * the click: a UiObject2 found just before Compose redraws the screen goes stale and its click throws
     * (run 39646201443: StaleObjectException on New seed right after Back returned to Home). The click's
     * boolean says only whether an accessibility event followed it in time, which Compose's clicks do not
     * always send (run 39649809912: false on taps that moved the screen on), so it is not read; every tap
     * here is followed by a check of the screen it leads to, which is the proof it landed, and a control
     * gone at the click throws UiObjectNotFoundException.
     */
    fun tap(tag: String) {
        find(tag)
        device.findObject(UiSelector().resourceId(tag)).click()
        device.waitForIdle()
    }

    fun text(tag: String): String = find(tag).text

    fun enabled(tag: String): Boolean = find(tag).isEnabled

    /** Waits up to 10 s for the node tag to show text. */
    fun awaitText(tag: String, text: String) {
        val shown = device.wait(Until.hasObject(By.res(tag).text(text)), 10_000)
        assertTrue(tag + " does not show " + text + " (it shows " + text(tag) + ")", shown == true)
    }

    /**
     * The node of screen (its root found by its id, find's 10 s) whose text is text, its text column
     * scrolled down where the text lies out of view below, since UI Automator sees only what is
     * scrolled into view; null when no node shows it, the column scanned from where it stood to its
     * end. KitScreen's text column is the screen's one scrollable node, and only once its text is
     * taller than the room it has: with none, the whole screen is in view at once. Each scroll is a
     * slow swipe over about half the column (UiObject2.scroll at SCROLL_SPEED), so no fling carries a
     * line past unseen; the scroll's boolean is not read, since UI Automator works it out from scroll
     * events, so the column is scrolled SCROLLS times at most. The root is found afresh each time, as a
     * redraw may replace its node.
     */
    fun shown(screen: Screen, text: String): UiObject2? {
        repeat(SCROLLS) {
            val root = find(screenId(screen))
            root.findObject(By.text(text))?.let { return it }
            val column = root.findObject(By.scrollable(true)) ?: return null
            column.scroll(Direction.DOWN, 0.5f, SCROLL_SPEED)
            device.waitForIdle()
        }
        return find(screenId(screen)).findObject(By.text(text))
    }

    fun stage(activity: MainActivity): Stage =
        onMain { ActivityLifecycleMonitorRegistry.getInstance().getLifecycleStageOf(activity) }

    /** Waits up to seconds for condition, checked every 100 ms. */
    fun await(what: String, seconds: Int, condition: () -> Boolean) {
        val end = SystemClock.elapsedRealtime() + seconds * 1_000L
        while (!condition()) {
            if (SystemClock.elapsedRealtime() > end) fail("timed out: " + what)
            SystemClock.sleep(100)
        }
    }
}
