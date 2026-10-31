package com.keepcrypt.entropy

import android.graphics.Rect
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
import com.keepcrypt.entropy.Capture.probe
import com.keepcrypt.entropy.Capture.shellText
import com.keepcrypt.entropy.ffi.WordPage
import com.keepcrypt.entropy.screens.ASCII_KEYS
import com.keepcrypt.entropy.screens.ASCII_PAGES
import com.keepcrypt.entropy.screens.ASCII_PAGE_KEYS
import com.keepcrypt.entropy.screens.CeremonyModel
import com.keepcrypt.entropy.screens.INSERTS_PER_DEVICE
import com.keepcrypt.entropy.screens.LETTER_KEYS
import com.keepcrypt.entropy.screens.PadEntry
import com.keepcrypt.entropy.screens.SECRET_TAG
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.screens.asciiPage
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
     * face's key on the Public dice pad and then Confirm, once it is enabled, pressed by their accessibility
     * click (as TalkBack presses them), and the count waited for until it shows one roll more. A press lost
     * leaves Confirm disabled or the count unchanged, which fails here; a face pressed wrong shows in the
     * seed the journey then checks (its Seal ID and words, vectors). The nodes are read and pressed through
     * UiAutomation directly (appNode), not UI Automator's searches: each of those first waits for the
     * accessibility events to be quiet for 500 ms (UiDevice.getWindowRoots' waitForIdle, UI Automator
     * 2.4.0), and a tap's UiObject.click waits up to 3 s for an event after it, so a roll by pressFace and
     * tap took 3.2 to 4.9 s (U1b's run, Entropy Android 41193839334); and nothing here goes into a log, so
     * no face does (M5-68 (e)). The count before each roll is read in-process (to observe), the one after
     * from the screen.
     */
    fun tapRolls(activity: MainActivity, count: Int, pattern: String) {
        for (index in 0 until count) {
            val before = onMain { activity.model.state.value.dice?.rolls } ?: throw AssertionError("not on the dice screen")
            val roll = (before + 1).toString()
            val key = poll("the dice pad's key for roll $roll") { appNode("key_" + pattern[index % pattern.length])?.takeIf { it.isEnabled } }
            assertTrue("the dice pad's key did not take the press (roll $roll)", key.performAction(AccessibilityNodeInfo.ACTION_CLICK))
            val confirm = poll("Confirm enabled after a face's press (roll $roll)") { appNode("confirm")?.takeIf { it.isEnabled } }
            assertTrue("Confirm did not take the press (roll $roll)", confirm.performAction(AccessibilityNodeInfo.ACTION_CLICK))
            poll("the dice count showing $roll rolls after Confirm") {
                appNode("dice_count")?.takeIf { it.text?.toString()?.startsWith("$roll / ") == true }
            }
        }
    }

    /**
     * The app's node with resource id tag, as it is now, or null: found in the app's window roots that
     * UiAutomation reports (a walk of its accessibility nodes, in-process, no idle wait and no log), then
     * refreshed from the app, so its state (enabled, text) is the app's and not the accessibility cache's.
     * Null while no such node is in the tree or the one found has gone.
     */
    private fun appNode(tag: String): AccessibilityNodeInfo? {
        val pkg = Capture.instrumentation.targetContext.packageName
        fun walk(node: AccessibilityNodeInfo): AccessibilityNodeInfo? {
            if (node.viewIdResourceName == tag) return node
            for (index in 0 until node.childCount) node.getChild(index)?.let { child -> walk(child)?.let { return it } }
            return null
        }
        for (window in Capture.instrumentation.uiAutomation.windows) {
            val root = window.root ?: continue
            if (root.packageName?.toString() != pkg) continue
            val node = walk(root) ?: continue
            return if (node.refresh()) node else null
        }
        return null
    }

    /** read's value once it is not null, read every 20 ms for up to 10 s; past that the test fails, naming what. */
    private fun <T : Any> poll(what: String, read: () -> T?): T {
        val end = SystemClock.elapsedRealtime() + FIND_MS
        while (true) {
            read()?.let { return it }
            if (SystemClock.elapsedRealtime() > end) throw AssertionError("timed out after 10 s: " + what)
            SystemClock.sleep(POLL_MS)
        }
    }

    /** poll's interval. */
    private const val POLL_MS = 20L

    /** Taps code on the code entry's Crockford pad, key by key, and waits for it shown in two groups (a go-ahead code is public). */
    fun tapCode(code: String) {
        for (symbol in code) tap("key_" + symbol)
        awaitText("code", Checker.grouped(code))
    }

    /** A single lower-case letter, as a node naming a letter pad's key would show it. */
    private val A_LETTER = Regex("[a-z]")

    /** Any one character, as a node naming an ASCII pad's key would show it. */
    private val ANY_CHARACTER = Regex(".", RegexOption.DOT_MATCHES_ALL)

    /** The dice pad's keys' resource ids, key_ and a face, and a face as the pick shows it: patterns that name no face. */
    private val DICE_KEY: Pattern = Pattern.compile("key_[1-6]")
    private val A_FACE: Pattern = Pattern.compile("[1-6]")

    /**
     * Touches the middle of bounds (a Protected pad's key's, in screen pixels) as a finger does: a touch
     * down and up injected through UiAutomation, never UiObject2.click, which logs the point it taps at
     * debug level ("Clicking on (x, y).") with no isLoggable guard, and on the pad's fixed grid a point names
     * its key: a letter typed goes into no log (lead decision M5-68 (e)). A Protected key's semantics are its
     * role alone (Pads.kt's clearAndSetSemantics drops the clickable's click action too), so a touch is its
     * press, as an accessibility click is a Public key's; nothing here logs the point. The caller checks the
     * press landed (typeLetters reads the pad's entry), so no idle wait follows.
     */
    fun touch(bounds: Rect) {
        val down = SystemClock.uptimeMillis()
        inject(MotionEvent.ACTION_DOWN, down, down, bounds.exactCenterX(), bounds.exactCenterY())
        inject(MotionEvent.ACTION_UP, down, SystemClock.uptimeMillis(), bounds.exactCenterX(), bounds.exactCenterY())
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
     * The keys of the Protected pad on screen, in its order: the nodes under the screen's root with the
     * button role and no text, description or resource id, which must be count; and no node there but the
     * entry's own secret one has a text that names (a key's label) or a Public key's id (key_ and a key), so
     * nothing names a key (lead decision M5-46). The entry's secret node (SECRET_TAG, the typed text the
     * screen shows, under FLAG_SECURE) is left out of the label check: the BIP39 entry shows a passphrase as
     * typed, so after one character it is one character long, which is no key's label (the review of U-4
     * found the check failing there, Entropy Android 41203734694). Read through UiAutomation's own nodes
     * (appNode's walk, in tree order, as UI Automator's search returns them), with no idle wait and no
     * selector logged (Stage U's U1c; U1b2 found a search costs 500 ms of quiet), and read again until the
     * count is there, for up to 10 s.
     */
    private fun padKeys(screen: Screen, count: Int, names: Regex): List<AccessibilityNodeInfo> =
        poll("the pad's $count keys on " + screenId(screen)) {
            val root = appNode(screenId(screen)) ?: return@poll null
            val nodes = ArrayList<AccessibilityNodeInfo>()
            fun walk(node: AccessibilityNodeInfo) {
                nodes.add(node)
                for (index in 0 until node.childCount) node.getChild(index)?.let(::walk)
            }
            walk(root)
            val keys = nodes.filter {
                it.className?.toString() == BUTTON && it.text.isNullOrEmpty() && it.contentDescription.isNullOrEmpty() &&
                    it.viewIdResourceName.isNullOrEmpty()
            }
            if (keys.size != count) return@poll null
            val labels = nodes.filter { it.viewIdResourceName != SECRET_TAG }
            assertFalse("a node on " + screenId(screen) + " names a key", labels.any { it.text?.toString()?.matches(names) == true })
            assertFalse("a key on " + screenId(screen) + " has a Public key's id", nodes.any { it.viewIdResourceName?.startsWith("key_") == true })
            keys
        }

    /** The letter pad's 26 keys on screen (the read-back entry, the backup's confirm or Check a backup's entry), as padKeys reads them. */
    fun letterKeys(screen: Screen): List<AccessibilityNodeInfo> = padKeys(screen, LETTER_KEYS.length, A_LETTER)

    /** The ASCII pad's keys on its page page (the BIP39 passphrase's entry), as padKeys reads them: no node there shows any one character. */
    fun asciiKeys(page: Int): List<AccessibilityNodeInfo> = padKeys(Screen.Bip39Entry, asciiPage(page).length, ANY_CHARACTER)

    /**
     * Touches the key keys() gives at index (read afresh from the app before the touch, its node
     * refreshed and visible) at the middle of the part of it its window shows (its screen bounds cut to
     * the window's, so a key the window clips is touched where it is drawn; touch, which logs no point: a
     * click's logged point would name the key on the pad's fixed grid), then waits in-process, for up to
     * 10 s, until entry, the model's pad entry, holds length keys, so the next touch is on the pad as this
     * one left it.
     */
    private fun touchKey(activity: MainActivity, keys: () -> List<AccessibilityNodeInfo>, index: Int, entry: (CeremonyModel) -> PadEntry, length: Int) {
        val bounds = poll("the pad's key, visible") {
            val key = keys()[index]
            if (!key.refresh() || !key.isVisibleToUser) return@poll null
            val shown = Rect().also(key::getBoundsInScreen)
            val window = key.window?.let { Rect().also(it::getBoundsInScreen) } ?: return@poll null
            shown.takeIf { it.intersect(window) && !it.isEmpty }
        }
        touch(bounds)
        poll("the pad's touch typed (key " + length + ")") { onMain { entry(activity.model).length == length }.takeIf { it } }
    }

    /** Whether entry holds typed after its first from keys (in-process, compared, never printed). */
    private fun holds(activity: MainActivity, entry: (CeremonyModel) -> PadEntry, from: Int, typed: CharSequence): Boolean = onMain {
        val pad = entry(activity.model)
        pad.length == from + typed.length && typed.indices.all { pad.keyAt(from + it) == typed[it] }
    }

    /**
     * The Public control tag pressed by its accessibility click (as TalkBack presses it) once it is
     * enabled, through UiAutomation's own nodes: no UI Automator selector, so what is pressed, and how
     * often, goes into no log (typeAscii's page turns, which follow a passphrase's characters).
     */
    private fun press(tag: String) {
        val node = poll("$tag enabled") { appNode(tag)?.takeIf { it.isEnabled } }
        assertTrue("$tag did not take the press", node.performAction(AccessibilityNodeInfo.ACTION_CLICK))
    }

    /**
     * Types letters on screen's letter pad, a touch on each key (touchKey), and checks entry, the model's
     * pad entry of screen, holds them after any it held before (compared, never printed). letters may be a
     * CharBuffer over an array the caller zeroes after (a secret's letters, JourneyTest).
     */
    fun typeLetters(activity: MainActivity, screen: Screen, letters: CharSequence, entry: (CeremonyModel) -> PadEntry) {
        val before = onMain { entry(activity.model).length }
        for ((at, letter) in letters.withIndex()) {
            touchKey(activity, { letterKeys(screen) }, LETTER_KEYS.indexOf(letter), entry, before + at + 1)
        }
        assertTrue("the letter pad's touches did not type the letters touched", holds(activity, entry, before, letters))
    }

    /**
     * Types text (printable ASCII) on the BIP39 passphrase's ASCII pad, a touch on each key (touchKey), its
     * page of keys first turned by Next keys or Previous keys (Public buttons, pressed by their accessibility
     * click, press) to the one that holds the key, the page's line read from the app until it names it;
     * then checks the model's entry holds text after any it held before (compared, never printed). Nothing
     * here goes through a UI Automator selector, so the pages a passphrase's characters fall on (which
     * would tell its kinds of character) go into no log (the review of U-4); the page is read in-process.
     */
    fun typeAscii(activity: MainActivity, text: CharSequence) {
        val before = onMain { activity.model.bip39Letters.length }
        for ((at, key) in text.withIndex()) {
            val index = ASCII_KEYS.indexOf(key)
            assertTrue("a passphrase character is not on the ASCII pad (it is not printed)", index >= 0)
            val page = index / ASCII_PAGE_KEYS
            while (true) {
                val shown = onMain { activity.model.state.value.page }
                if (shown == page) break
                press(if (shown < page) "keys_next" else "keys_previous")
                await("the ASCII pad's page turned", 10) { onMain { activity.model.state.value.page } != shown }
            }
            val line = "Keys, page " + (page + 1) + " of " + ASCII_PAGES
            poll("the ASCII pad's page line") { appNode("keys_page")?.takeIf { it.text?.toString() == line } }
            touchKey(activity, { asciiKeys(page) }, index % ASCII_PAGE_KEYS, { it.bip39Letters }, before + at + 1)
        }
        assertTrue("the ASCII pad's touches did not type the passphrase touched", holds(activity, { it.bip39Letters }, before, text))
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
        assertInsertAt(activity, index, words.size, device, devices)
        val same = onMain { sameWord(checkNotNull(activity.model.state.value.insert), words[index]) }
        assertTrue("insert " + (index + 1) + ": its page is not the vector's word", same)
    }

    /**
     * The words page shows insert index + 1 of count on device of devices, read in-process (its position,
     * count, device and sequence; not its word, for a seed that is no vector's) and its header from the screen.
     */
    fun assertInsertAt(activity: MainActivity, index: Int, count: Int, device: Int, devices: Int) {
        val what = "insert " + (index + 1)
        await(what + " on the words page", 10) {
            onMain { activity.model.state.value.let { it.screen == Screen.Words && it.page == index && !it.gate } }
        }
        val at = onMain {
            val insert = checkNotNull(activity.model.state.value.insert)
            insert.position == index + 1 && insert.count == count && insert.device == device && insert.devices == devices &&
                insert.sequence == index % INSERTS_PER_DEVICE + 1
        }
        assertTrue(what + ": its page is not that position and device", at)
        awaitText("insert_header", "Insert " + two(index + 1) + DOT + "device " + device + " of " + devices)
    }

    /** Between a header's parts, as WordsScreens.kt (and the Pi) write it: a middle dot. */
    const val DOT = " \u00B7 "

    /** number as two digits, zero first (a position on the words' headers). */
    fun two(number: Int): String = number.toString().padStart(2, '0')

    /**
     * CAMERA granted from the shell (pm grant; dumpsys package reads it back), so the scan screen opens
     * with no prompt and reaches the camera's absence on these emulators (SnapshotDrillTest, JourneyTest).
     */
    fun grantCamera() {
        val pkg = Capture.instrumentation.targetContext.packageName
        val out = shellText("pm grant " + pkg + " " + CAMERA_PERMISSION)
        val facts = Capture.permission(pkg, CAMERA_PERMISSION)
        probe("pm grant $pkg $CAMERA_PERMISSION: '$out'; dumpsys package: ${facts.state}")
        assertTrue("CAMERA is not granted after pm grant", facts.granted)
    }

    /** The permission the scan screen asks for. */
    private const val CAMERA_PERMISSION = "android.permission.CAMERA"

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
