package com.keepcrypt.entropy

import android.os.SystemClock
import android.view.InputDevice
import android.view.MotionEvent
import android.view.accessibility.AccessibilityNodeInfo
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import androidx.test.uiautomator.By
import androidx.test.uiautomator.Direction
import androidx.test.uiautomator.StaleObjectException
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.UiSelector
import androidx.test.uiautomator.Until
import com.keepcrypt.entropy.Capture.launch
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.ffi.WordPage
import com.keepcrypt.entropy.screens.CeremonyModel
import com.keepcrypt.entropy.screens.INSERTS_PER_DEVICE
import com.keepcrypt.entropy.screens.LETTER_KEYS
import com.keepcrypt.entropy.screens.PadEntry
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.screens.screenId
import java.util.regex.Pattern
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail

/**
 * The flow tests' way through the screens (tasks/todo.md, M5 groups 15 and 16, and Stage U's U1b), shared
 * by FlowTest, CheckTest, JourneyTest and SnapshotDrillTest: UI Automator taps controls by their resource
 * ids (Compose test tags, group 6) as a user would and reads what they show from the accessibility tree.
 * A journey's every input goes through the UI (M5-72 (a)): its rolls pressed and confirmed on the dice pad
 * (tapRolls), its code tapped on the Crockford pad (tapCode) and its letters touched on the Protected
 * letter pad (typeLetters); the edge tests may still make the many rolls a minimum takes through the
 * model's dice pick and confirmRoll, the entry points the pad and Confirm call (roll; group 6,
 * "Driving"). No helper reads a node it found before a wait: each read finds its node afresh (fresh),
 * since a redraw in between replaces it.
 */
internal object Ui {
    /** The start-up self-test's and a start's time limit (a translated library is slower; NativeTest's). */
    const val START_SECONDS = 120

    /** How long a search waits for its node, and fresh tries again on a node a redraw replaced. */
    private const val FIND_MS = 10_000L

    /** The privacy gate's root (Screens.kt's PrivacyGate), which a Protected screen shows first (Capture.nodesOf's too). */
    const val PRIVACY_GATE = "privacy_gate"

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

    /**
     * count rolls through the model's dice pick and confirmRoll, as the pad and Confirm call them, faces in
     * pattern's order: the edge tests' setup, in-process. A journey (JourneyTest; M5-72 (a)) makes its
     * rolls through the UI alone, by tapRolls.
     */
    fun roll(activity: MainActivity, count: Int, pattern: String) {
        onMain {
            for (index in 0 until count) {
                activity.model.dicePick.replace(pattern[index % pattern.length])
                activity.model.confirmRoll()
            }
        }
    }

    /**
     * Waits up to seconds for the activity to show screen, then up to 10 s for UI Automator to see it (its
     * root by the screen's id, or the privacy gate's while the model holds the gate up before it), then
     * for the screen to settle. The activity reports a screen once it is composed, and UI Automator reads
     * the app's nodes through the platform's accessibility cache, which the app's content-change events
     * bring up to date only after that: until then a search can match a node of the screen before, gone
     * from the window. On kc37 at 720x1184 (local) a tap on Home's About just after Back from About so
     * matched the About screen's root, which had the id of Home's About then, and clicked at that root's
     * centre, between two of Home's buttons: run 40681107802's About failure (API 31). When UI Automator does
     * not see the root in time, a probe line says what it does read there (Capture.treeFacts) before the failure.
     */
    fun on(activity: MainActivity, screen: Screen, seconds: Int = 10) {
        await("the app shows " + screenId(screen), seconds) { onMain { activity.shownScreen } == screen }
        val root = if (onMain { activity.model.state.value.gate }) PRIVACY_GATE else screenId(screen)
        val seen = device.wait(Until.hasObject(By.res(root)), FIND_MS)
        if (seen != true) {
            Capture.probe("UI Automator's tree for " + root + ": " + Capture.treeFacts(activity.packageName, root))
            val stage = onMain { ActivityLifecycleMonitorRegistry.getInstance().getLifecycleStageOf(activity) }
            Capture.probe("the activity's stage " + stage + "; " + Capture.windowFacts())
        }
        assertTrue("UI Automator does not see " + root + ", though the app shows " + screenId(screen), seen == true)
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
        device.wait(Until.findObject(By.res(tag)), FIND_MS) ?: throw AssertionError("not on screen: " + tag)

    /**
     * block's value, block run again while a node it found has been replaced by a redraw before it reads
     * it, for up to 10 s. UI Automator reads a node it found (UiObject2) only after waiting for the screen
     * to go idle, and then asks the app for the node again, which throws StaleObjectException once a redraw
     * since the search has replaced it: run 40681107802 (API 31) so read the BIP39 entry's Delete, whose
     * block of keys and buttons is drawn anew with each page of keys, from a search made just before that
     * redraw reached UI Automator. block finds every node it reads itself, so each try reads the screen as
     * it is then, and a node still replaced at every try after 10 s fails, never passes.
     */
    fun <T> fresh(what: String, block: () -> T): T {
        val end = SystemClock.elapsedRealtime() + FIND_MS
        while (true) {
            try {
                return block()
            } catch (stale: StaleObjectException) {
                if (SystemClock.elapsedRealtime() > end) throw AssertionError("replaced by a redraw at every read for 10 s: " + what, stale)
                device.waitForIdle()
            }
        }
    }

    /** read of the control or text with resource id tag, found afresh for each try (find, fresh). */
    fun <T> read(tag: String, read: (UiObject2) -> T): T = fresh(tag) { read(find(tag)) }

    /**
     * Taps the control tag once it is on screen (find's 10 s), through a selector UI Automator resolves at
     * the click: a UiObject2 found just before Compose redraws the screen goes stale and its click throws
     * (run 39646201443: StaleObjectException on New seed right after Back returned to Home). The click's
     * boolean says only whether an accessibility event followed it in time, which Compose's clicks do not
     * always send (run 39649809912: false on taps that moved the screen on), so it is not read; every tap
     * here is followed by a check of the screen it leads to, which is the proof it landed, and a control
     * gone at the click throws UiObjectNotFoundException. The click goes to the bounds UI Automator has for
     * the node, so a tap comes after on() has seen its screen, and no control's id is a screen's id.
     */
    fun tap(tag: String) {
        find(tag)
        device.findObject(UiSelector().resourceId(tag)).click()
        device.waitForIdle()
    }

    fun text(tag: String): String = read(tag) { it.text }

    fun enabled(tag: String): Boolean = read(tag) { it.isEnabled }

    /**
     * Presses the dice pad's key for face, as a tap on it picks the face, without naming the face to UI
     * Automator, which logs the selector of every search and the point of every click (on the pad's fixed
     * grid, a point names its key): a face picked is a roll once confirmed, and no roll goes into a log
     * (lead decision M5-68 (e)). The pad's keys are found by a pattern that names none of them, the face's
     * picked by its resource id in-process, and pressed by its accessibility click, as TalkBack presses it.
     * A key replaced before the press is found again (fresh): the press is the last read of the key found.
     */
    fun pressFace(face: Char) {
        find(screenId(Screen.Dice))
        val pressed = fresh("the dice pad's keys") {
            val key = device.findObjects(By.res(DICE_KEY)).singleOrNull { it.resourceName == "key_" + face }
                ?: throw AssertionError("the dice pad has no single key for the face pressed (it is not printed)")
            key.accessibilityNodeInfo.performAction(AccessibilityNodeInfo.ACTION_CLICK)
        }
        assertTrue("the dice pad's key did not take the press", pressed)
        device.waitForIdle()
    }

    /**
     * Waits up to 10 s for the dice screen's pick, empty before the press, to show a face, by a pattern
     * that names none (its text changes in place, so it is waited for as UI Automator resolves it, and it
     * is found again if a recomposition replaced it before its text is read, never read from a node found
     * before), then compares that face with face in-process: a roll goes into no selector or message.
     */
    fun awaitPick(face: Char) {
        val same = fresh("dice_pick") {
            val shown = device.wait(Until.findObject(By.res("dice_pick").text(A_FACE)), FIND_MS)
                ?: throw AssertionError("the dice screen's pick shows no face after the press")
            shown.text == face.toString()
        }
        assertTrue("the dice screen's pick is not the face pressed (neither is printed)", same)
    }

    /**
     * count rolls through the UI alone, faces in pattern's order (Stage U's U1b, M5-72 (a)): for each, the
     * face's key pressed on the Public dice pad (pressFace, which names no face to UI Automator), Confirm
     * tapped once it is enabled (a face is picked), and the count waited for until it shows one roll more.
     * The count is public and the faces are compared nowhere here: a roll pressed wrong shows in the seed
     * the journey then checks (its Seal ID and words, vectors), and a press lost leaves Confirm disabled,
     * which fails here. The count before each roll is read in-process (to observe), the one after from the
     * screen.
     */
    fun tapRolls(activity: MainActivity, count: Int, pattern: String) {
        for (index in 0 until count) {
            val before = onMain { activity.model.state.value.dice?.rolls } ?: throw AssertionError("not on the dice screen")
            pressFace(pattern[index % pattern.length])
            val picked = device.wait(Until.hasObject(By.res("confirm").enabled(true)), FIND_MS)
            assertTrue("Confirm is not enabled after a face's press (roll " + (before + 1) + ")", picked == true)
            tap("confirm")
            val counted = device.wait(Until.hasObject(By.res("dice_count").textStartsWith((before + 1).toString() + " / ")), FIND_MS)
            assertTrue("the dice count does not show " + (before + 1) + " rolls after Confirm", counted == true)
        }
    }

    /** Taps code on the code entry's Crockford pad, key by key, and waits for it shown in two groups (a go-ahead code is public). */
    fun tapCode(code: String) {
        for (symbol in code) tap("key_" + symbol)
        awaitText("code", Checker.grouped(code))
    }

    /** The dice pad's keys' resource ids, key_ and a face, and a face as the pick shows it: patterns that name no face. */
    private val DICE_KEY: Pattern = Pattern.compile("key_[1-6]")
    private val A_FACE: Pattern = Pattern.compile("[1-6]")

    /**
     * Taps the key that key finds, a Protected pad's key, as a finger does: a touch down and up at the
     * middle of its visible bounds, injected through UiAutomation, never UiObject2.click, which logs the
     * point it taps at debug level ("Clicking on (x, y).") with no isLoggable guard, and on the pad's fixed
     * grid a point names its key: a letter typed goes into no log (lead decision M5-68 (e)). A Protected
     * key's semantics are its role alone (Pads.kt's clearAndSetSemantics drops the clickable's click action
     * too), so a touch is its press, as pressFace's accessibility click is a Public key's; nothing here
     * logs the point. The key is found again when a recomposition replaced it before its bounds were read (fresh).
     */
    fun touch(key: () -> UiObject2) {
        val bounds = fresh("a key of the pad") { key().visibleBounds }
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

    /**
     * The letter pad's keys on screen (the read-back entry, the backup's confirm or Check a backup's
     * entry, lead decision M5-46): the screen's nodes with the button role and no text, description or
     * resource id, which must be its 26, in the pad's order; and no node there has a single letter or a
     * Public key's id (key_ and a letter), so nothing names a key. Found afresh for each key, since a key
     * typed may recompose the actions around the pad (a tap resolves its selector at the click for the
     * same reason), and again when a redraw replaced a node read (fresh).
     */
    fun letterKeys(screen: Screen): List<UiObject2> = fresh("the letter pad's keys") {
        device.waitForIdle()
        val root = find(screenId(screen))
        val keys = root.findObjects(By.clazz(BUTTON)).filter {
            it.text.isNullOrEmpty() && it.contentDescription.isNullOrEmpty() && it.resourceName.isNullOrEmpty()
        }
        assertEquals("the letter pad's keys, each with its button role alone", LETTER_KEYS.length, keys.size)
        assertFalse("a node on " + screenId(screen) + " names a letter", root.hasObject(By.text(Pattern.compile("[a-z]"))))
        assertFalse("a key on " + screenId(screen) + " has a Public key's id", root.hasObject(By.res(Pattern.compile("key_.*"))))
        keys
    }

    /**
     * Types letters on screen's letter pad, a touch on each key (touch, which logs no point: a click's
     * logged point would name the letter on the pad's fixed grid, and which finds the keys again if a
     * redraw replaced the one to touch), and checks in-process that entry, the model's pad entry of
     * screen, holds them after any it held before (compared, never printed).
     */
    fun typeLetters(activity: MainActivity, screen: Screen, letters: String, entry: (CeremonyModel) -> PadEntry) {
        val before = onMain { entry(activity.model).length }
        for (letter in letters) {
            touch { letterKeys(screen)[LETTER_KEYS.indexOf(letter)] }
        }
        device.waitForIdle()
        val held = onMain {
            val pad = entry(activity.model)
            pad.length == before + letters.length && letters.indices.all { pad.keyAt(before + it) == letters[it] }
        }
        assertTrue("the letter pad's taps did not type the letters tapped", held)
    }

    /** Whether insert's word is word, byte by byte, its copy wiped (the words are public vectors, never printed). */
    fun sameWord(insert: WordPage, word: String): Boolean {
        val bytes = insert.word()
        val same = bytes.size == word.length && word.indices.all { bytes[it] == word[it].code.toByte() }
        bytes.wipe()
        return same
    }

    /** The words page shows insert index + 1 of words on device of devices, read in-process (the word compared, never printed) and its header from the screen. */
    fun assertInsert(activity: MainActivity, words: List<String>, index: Int, device: Int, devices: Int) {
        val what = "insert " + (index + 1)
        await(what + " on the words page", 10) {
            onMain { activity.model.state.value.let { it.screen == Screen.Words && it.page == index && !it.gate } }
        }
        val same = onMain {
            val insert = checkNotNull(activity.model.state.value.insert)
            insert.position == index + 1 && insert.count == words.size && insert.device == device &&
                insert.devices == devices && insert.sequence == index % INSERTS_PER_DEVICE + 1 && sameWord(insert, words[index])
        }
        assertTrue(what + ": its page is not the vector's word with its position and device", same)
        awaitText("insert_header", "Insert " + two(index + 1) + DOT + "device " + device + " of " + devices)
    }

    /** Between a header's parts, as WordsScreens.kt (and the Pi) write it: a middle dot. */
    const val DOT = " \u00B7 "

    /** number as two digits, zero first (a position on the words' headers). */
    fun two(number: Int): String = number.toString().padStart(2, '0')

    /** Waits up to 10 s for the node tag to show text. */
    fun awaitText(tag: String, text: String) {
        val shown = device.wait(Until.hasObject(By.res(tag).text(text)), FIND_MS)
        assertTrue(tag + " does not show " + text + " (it shows " + text(tag) + ")", shown == true)
    }

    /**
     * Whether a node of screen (its root found by its id, find's 10 s) has text as its text, its text
     * column scrolled down where the text lies out of view below, since UI Automator sees only what is
     * scrolled into view (Compose leaves a node scrolled out of view out of the accessibility tree);
     * false when no node shows it, the column scanned from where it stood to its end. KitScreen's text
     * column is the screen's one scrollable node, and only once its text is taller than the room it has:
     * with none, the whole screen is in view at once. Each scroll is a slow swipe over about half the
     * column (UiObject2.scroll at SCROLL_SPEED), so no fling carries a line past unseen; the scroll's
     * boolean is not read, since UI Automator works it out from scroll events, so the column is scrolled
     * SCROLLS times at most. Each look finds the root afresh, and looks again when a redraw replaced a
     * node it read (fresh).
     */
    fun shown(screen: Screen, text: String): Boolean {
        val id = screenId(screen)
        repeat(SCROLLS) {
            if (fresh(id) { find(id).hasObject(By.text(text)) }) return true
            val scrolled = fresh(id) { find(id).findObject(By.scrollable(true))?.scroll(Direction.DOWN, 0.5f, SCROLL_SPEED) != null }
            if (!scrolled) return false
            device.waitForIdle()
        }
        return fresh(id) { find(id).hasObject(By.text(text)) }
    }

    /** UI Automator's class name for a node with the button role (Compose's Role.Button). */
    const val BUTTON = "android.widget.Button"

    /**
     * A Public pad keeps its labels (lead decision M5-46's other half; Pads.kt): each of keys is found by
     * its resource id, key_ and the key, clickable, with its key as the text of the node its label draws
     * inside it, which TalkBack reads with the key. Its class name is not read: on kc37 (local) a Public
     * key, whose label is a node under it, reports android.view.View, not BUTTON, which a Protected key
     * (its semantics cleared, so with no node under it) reports. Each key's three reads are of one node,
     * found afresh while a redraw replaces it (fresh).
     */
    fun assertPublicPadLabelled(what: String, keys: String) {
        for (key in keys) {
            val (text, label, clickable) = read("key_$key") { node ->
                Triple(node.text, node.text == key.toString() || node.hasObject(By.text(key.toString())), node.isClickable)
            }
            assertTrue(what + ": key " + key + " shows no label " + key + " (its text: " + text + ")", label)
            assertTrue(what + ": key " + key + " is not clickable", clickable)
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
