package com.keepcrypt.entropy

import android.os.SystemClock
import android.view.InputDevice
import android.view.MotionEvent
import android.view.accessibility.AccessibilityNodeInfo
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
import java.util.regex.Pattern
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

    /**
     * Presses the dice pad's key for face, as a tap on it picks the face, without naming the face to UI
     * Automator, which logs the selector of every search and the point of every click (on the pad's fixed
     * grid, a point names its key): a face picked is a roll once confirmed, and no roll goes into a log
     * (lead decision M5-68 (e)). The pad's keys are found by a pattern that names none of them, the face's
     * picked by its resource id in-process, and pressed by its accessibility click, as TalkBack presses it.
     */
    fun pressFace(face: Char) {
        find(screenId(Screen.Dice))
        val key = device.findObjects(By.res(DICE_KEY)).singleOrNull { it.resourceName == "key_" + face }
            ?: throw AssertionError("the dice pad has no single key for the face pressed (it is not printed)")
        assertTrue("the dice pad's key did not take the press", key.accessibilityNodeInfo.performAction(AccessibilityNodeInfo.ACTION_CLICK))
        device.waitForIdle()
    }

    /**
     * Waits up to 10 s for the dice screen's pick, empty before the press, to show a face, by a pattern
     * that names none (the pick's node is drawn anew as it changes, so it is waited for as UI Automator
     * resolves it, never read from a node found before), then compares that face with face in-process:
     * a roll goes into no selector or message.
     */
    fun awaitPick(face: Char) {
        val shown = device.wait(Until.findObject(By.res("dice_pick").text(A_FACE)), 10_000)
            ?: throw AssertionError("the dice screen's pick shows no face after the press")
        assertTrue("the dice screen's pick is not the face pressed (neither is printed)", shown.text == face.toString())
    }

    /** The dice pad's keys' resource ids, key_ and a face, and a face as the pick shows it: patterns that name no face. */
    private val DICE_KEY: Pattern = Pattern.compile("key_[1-6]")
    private val A_FACE: Pattern = Pattern.compile("[1-6]")

    /**
     * Taps key, a Protected pad's key, as a finger does: a touch down and up at the middle of its visible
     * bounds, injected through UiAutomation, never UiObject2.click, which logs the point it taps at debug
     * level ("Clicking on (x, y).") with no isLoggable guard, and on the pad's fixed grid a point names its
     * key: a letter typed goes into no log (lead decision M5-68 (e)). A Protected key's semantics are its
     * role alone (Pads.kt's clearAndSetSemantics drops the clickable's click action too), so a touch is its
     * press, as pressFace's accessibility click is a Public key's; nothing here logs the point.
     */
    fun touch(key: UiObject2) {
        val bounds = key.visibleBounds
        val down = SystemClock.uptimeMillis()
        inject(MotionEvent.ACTION_DOWN, down, down, bounds.exactCenterX(), bounds.exactCenterY())
        inject(MotionEvent.ACTION_UP, down, SystemClock.uptimeMillis(), bounds.exactCenterX(), bounds.exactCenterY())
        device.waitForIdle()
    }

    /** One touch-screen event at (x, y), injected through UiAutomation and handled before this returns. */
    private fun inject(action: Int, downTime: Long, eventTime: Long, x: Float, y: Float) {
        val event = MotionEvent.obtain(downTime, eventTime, action, x, y, 0)
        event.source = InputDevice.SOURCE_TOUCHSCREEN
        try {
            assertTrue("a touch on the pad was not injected", Capture.instrumentation.uiAutomation.injectInputEvent(event, true))
        } finally {
            event.recycle()
        }
    }

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

    /** UI Automator's class name for a node with the button role (Compose's Role.Button). */
    const val BUTTON = "android.widget.Button"

    /**
     * A Public pad keeps its labels (lead decision M5-46's other half; Pads.kt): each of keys is found by
     * its resource id, key_ and the key, clickable, with its key as the text of the node its label draws
     * inside it, which TalkBack reads with the key. Its class name is not read: on kc37 (local) a Public
     * key, whose label is a node under it, reports android.view.View, not BUTTON, which a Protected key
     * (its semantics cleared, so with no node under it) reports.
     */
    fun assertPublicPadLabelled(what: String, keys: String) {
        for (key in keys) {
            val node = find("key_$key")
            val label = node.text == key.toString() || node.hasObject(By.text(key.toString()))
            assertTrue(what + ": key " + key + " shows no label " + key + " (its text: " + node.text + ")", label)
            assertTrue(what + ": key " + key + " is not clickable", node.isClickable)
        }
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
