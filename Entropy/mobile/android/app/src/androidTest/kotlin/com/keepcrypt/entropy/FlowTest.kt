package com.keepcrypt.entropy

import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.Until
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.launch
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Capture.probe
import com.keepcrypt.entropy.Capture.shellText
import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.screens.DICE_ONLY
import com.keepcrypt.entropy.screens.MAX_ROLLS
import com.keepcrypt.entropy.screens.Notice
import com.keepcrypt.entropy.screens.SAFE_IF_EITHER
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.screens.screenId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The screens from the start to the dice on the phone (tasks/todo.md, M5 group 15), run by
 * scripts/android-instrument.sh on the shipping app in the API 31 and 36 legs. UI Automator taps the
 * Public screens' controls by their resource ids (Compose test tags, group 6) as a user would, and
 * reads what they show from the accessibility tree; the many rolls a minimum takes go through the
 * model's dice pick and confirmRoll, the entry points the pad and Confirm call (group 6, "Driving"),
 * with a few by tap around them. No seed is made (the dice screen's Done comes with commit 17). The
 * rolls are vectors/kcr.json's public gate seeds' (the new seed's 50 dice-50-words12's, mixed with the
 * phone's D; the dice-only seed's first 99 dice-99-words24's). Each test puts the phone's
 * airplane-mode and Wi-Fi settings back as they were.
 */
@RunWith(AndroidJUnit4::class)
class FlowTest {
    private val device: UiDevice get() = UiDevice.getInstance(Capture.instrumentation)

    /**
     * New seed, 12 words: Home to Length and Back to Home (nothing is lost there), Length's 12 words,
     * Device entropy with MA's sentence (taps on it are touches for the pool) where Back does nothing,
     * Commitment's C as 16 groups of 4 hex digits, then the dice: Confirm and Undo off at first, a face
     * tapped and confirmed, undone, Back doing nothing, and on to the minimum, 50 rolls. Then Wi-Fi comes
     * on during the dice: the session is wiped and Go offline says why.
     */
    @Test
    fun aNewSeedOfTwelveWordsReachesTheDiceMinimumAndWifiOnWipesIt() {
        Capture.whileOffline {
            val activity = toHome()
            tap("new_seed")
            on(activity, Screen.Length)
            device.pressBack()
            on(activity, Screen.Home)
            tap("new_seed")
            on(activity, Screen.Length)
            tap("words_12")
            on(activity, Screen.DeviceEntropy, START_SECONDS)
            assertEquals(SAFE_IF_EITHER, text("device_entropy_sentence"))
            repeat(3) { tap("device_entropy_sentence") }
            device.pressBack()
            stays(activity, Screen.DeviceEntropy, "Back on Device entropy, which holds a session")
            tap("continue")
            on(activity, Screen.Commitment)
            val c = text("commitment_hex")
            assertTrue("C is not 16 groups of 4 hex digits in four rows: " + c.length, HEX_GROUPS.matches(c))
            tap("continue")
            on(activity, Screen.Dice)
            assertEquals("0 / 50 rolls, 0.0 bits", text("dice_count"))
            assertFalse("Confirm with no face picked", enabled("confirm"))
            assertFalse("Undo with no roll", enabled("undo"))
            tap("key_3")
            awaitText("dice_pick", "3")
            assertTrue("Confirm with a face picked", enabled("confirm"))
            tap("confirm")
            awaitText("dice_count", "1 / 50 rolls, 2.5 bits")
            assertEquals("the pick goes with the confirm", "-", text("dice_pick"))
            tap("undo")
            awaitText("dice_count", "0 / 50 rolls, 0.0 bits")
            device.pressBack()
            stays(activity, Screen.Dice, "Back on the dice")
            assertEquals("0 / 50 rolls, 0.0 bits", text("dice_count"))
            roll(activity, 49, DICE_50_ROLLS)
            awaitText("dice_count", "49 / 50 rolls, 126.6 bits")
            assertFalse("the minimum is not reached at 49 rolls", device.hasObject(By.res("dice_minimum")))
            tap("key_2")
            awaitText("dice_pick", "2")
            tap("confirm")
            awaitText("dice_count", "50 / 50 rolls, 129.2 bits")
            find("dice_minimum")
            shellText("cmd wifi set-wifi-enabled enabled")
            on(activity, Screen.GoOffline, 30)
            assertEquals(Notice.Offline, onMain { activity.model.state.value.notice })
            assertEquals("The session was wiped: the phone went online.", text("notice"))
            assertTrue("the slot is not at home: the session was not wiped", Core.selfTest() is Reply.Done)
            pass(
                "new seed, 12 words: Back from Length, Device entropy, C in 16 groups, the dice's pick, confirm, " +
                    "undo and minimum (50 / 50 rolls, 129.2 bits); Wi-Fi on during the dice wiped it, back to Go offline",
            )
            finish(activity)
        }
    }

    /**
     * Dice-only seed, 24 words: from Length straight to the dice, past Device entropy and Commitment
     * (each waits for a tap, and none comes), with the dice-only line; the minimum, 99 rolls; then 256,
     * where Confirm and the pad are disabled and the model refuses a 257th as well, so core, which
     * halts on one, holds 256 still; Back does nothing.
     */
    @Test
    fun aDiceOnlySeedOfTwentyFourWordsSkipsTwoScreensAndStopsAt256Rolls() {
        Capture.whileOffline {
            val activity = toHome()
            tap("dice_only_seed")
            on(activity, Screen.Length)
            tap("words_24")
            on(activity, Screen.Dice, START_SECONDS)
            assertEquals("0 / 99 rolls, 0.0 bits", text("dice_count"))
            assertEquals(DICE_ONLY, text("dice_only"))
            roll(activity, 98, DICE_99_ROLLS)
            awaitText("dice_count", "98 / 99 rolls, 253.3 bits")
            assertFalse("the minimum is not reached at 98 rolls", device.hasObject(By.res("dice_minimum")))
            tap("key_4")
            awaitText("dice_pick", "4")
            tap("confirm")
            awaitText("dice_count", "99 / 99 rolls, 255.9 bits")
            find("dice_minimum")
            roll(activity, MAX_ROLLS - 100, DICE_99_ROLLS)
            awaitText("dice_count", "255 / 99 rolls, 659.1 bits")
            tap("key_5")
            awaitText("dice_pick", "5")
            tap("confirm")
            awaitText("dice_count", "256 / 99 rolls, 661.7 bits")
            find("dice_cap")
            assertFalse("Confirm at 256 rolls", enabled("confirm"))
            assertFalse("the pad at 256 rolls", enabled("key_1"))
            tap("key_1")
            assertEquals("a disabled key picks nothing", "-", text("dice_pick"))
            onMain {
                activity.model.dicePick.replace('1')
                activity.model.confirmRoll()
            }
            val progress = Core.diceProgress()
            assertTrue("core does not hold 256 rolls", progress is Reply.Done && progress.value.rolls == MAX_ROLLS)
            device.pressBack()
            stays(activity, Screen.Dice, "Back on the dice")
            assertEquals("256 / 99 rolls, 661.7 bits", text("dice_count"))
            pass("dice-only seed, 24 words: straight to the dice, the dice-only line, the minimum (99), and no 257th roll")
            finish(activity)
        }
    }

    /**
     * Go offline online: both states shown, Start disabled and a tap on it doing nothing; the button
     * opens the system's airplane-mode settings over the app (Back returns, to the privacy cover, since
     * the app was left); offline, Start is enabled and leads Home; Wi-Fi on at Home, with nothing held,
     * returns to Go offline with nothing wiped.
     */
    @Test
    fun startStaysDisabledOnlineAndTheButtonOpensTheAirplaneModeSettings() {
        val airplane = Capture.globalSetting("airplane_mode_on")
        val wifi = Capture.globalSetting("wifi_on")
        probe("before the test: airplane_mode_on=$airplane, wifi_on=$wifi")
        try {
            shellText("cmd connectivity airplane-mode disable")
            shellText("cmd wifi set-wifi-enabled enabled")
            val activity = launch()
            on(activity, Screen.FirstLaunch, START_SECONDS)
            tap("first_launch_continue")
            on(activity, Screen.GoOffline)
            await("the app reads the phone online", 30) { !onMain { activity.model.state.value.offline } }
            awaitText("airplane_mode", "Airplane mode: off")
            awaitText("wifi", "Wi-Fi: on")
            assertFalse("Start online", enabled("start"))
            tap("start")
            stays(activity, Screen.GoOffline, "Start, disabled online")
            tap("airplane_settings")
            await("the settings over the app", 30) { stage(activity) == Stage.STOPPED }
            val focus = shellText("dumpsys window").lines().filter { it.contains("mCurrentFocus=") }.joinToString("; ") { it.trim() }
            probe("airplane-mode settings: $focus")
            assertTrue("the settings' window is not in focus: " + focus, focus.contains("com.android.settings"))
            device.pressBack()
            await("back in the app", 30) { stage(activity) == Stage.RESUMED }
            tap("cover")
            shellText("cmd connectivity airplane-mode enable")
            shellText("cmd wifi set-wifi-enabled disabled")
            await("the app reads the phone offline", 30) { onMain { activity.model.state.value.offline } }
            awaitText("airplane_mode", "Airplane mode: on")
            awaitText("wifi", "Wi-Fi: off")
            assertTrue("Start offline", enabled("start"))
            tap("start")
            on(activity, Screen.Home)
            shellText("cmd wifi set-wifi-enabled enabled")
            on(activity, Screen.GoOffline, 30)
            assertEquals("nothing was held, so nothing was wiped", null, onMain { activity.model.state.value.notice })
            pass("Go offline: Start disabled online, the airplane-mode settings opened and left, Start offline; Wi-Fi on at Home returns to Go offline")
            finish(activity)
        } finally {
            shellText("cmd connectivity airplane-mode " + (if (airplane == "1") "enable" else "disable"))
            shellText("cmd wifi set-wifi-enabled " + (if (wifi == "0" || wifi == "3") "disabled" else "enabled"))
        }
    }

    /** A new MainActivity through its self-test, First launch and Go offline's Start (the phone offline) to Home. */
    private fun toHome(): MainActivity {
        val activity = launch()
        on(activity, Screen.FirstLaunch, START_SECONDS)
        tap("first_launch_continue")
        on(activity, Screen.GoOffline)
        await("the app reads the phone offline", 30) { onMain { activity.model.state.value.offline } }
        tap("start")
        on(activity, Screen.Home)
        return activity
    }

    /** count rolls through the model's dice pick and confirmRoll, as the pad and Confirm call them, faces in pattern's order. */
    private fun roll(activity: MainActivity, count: Int, pattern: String) {
        onMain {
            for (index in 0 until count) {
                activity.model.dicePick.replace(pattern[index % pattern.length])
                activity.model.confirmRoll()
            }
        }
    }

    /** Waits up to seconds for the activity to show screen, then for the screen to settle. */
    private fun on(activity: MainActivity, screen: Screen, seconds: Int = 10) {
        await("the app shows " + screenId(screen), seconds) { onMain { activity.shownScreen } == screen }
        device.waitForIdle()
    }

    /** After a press that must do nothing: a moment for it to land, then the same screen. */
    private fun stays(activity: MainActivity, screen: Screen, what: String) {
        device.waitForIdle()
        SystemClock.sleep(SETTLE_MS)
        assertEquals(what + " left the screen", screen, onMain { activity.shownScreen })
    }

    /** The control or text with resource id tag, waited for up to 10 s. */
    private fun find(tag: String): UiObject2 =
        device.wait(Until.findObject(By.res(tag)), 10_000) ?: throw AssertionError("not on screen: " + tag)

    private fun tap(tag: String) {
        find(tag).click()
        device.waitForIdle()
    }

    private fun text(tag: String): String = find(tag).text

    private fun enabled(tag: String): Boolean = find(tag).isEnabled

    /** Waits up to 10 s for the node tag to show text. */
    private fun awaitText(tag: String, text: String) {
        val shown = device.wait(Until.hasObject(By.res(tag).text(text)), 10_000)
        assertTrue(tag + " does not show " + text + " (it shows " + text(tag) + ")", shown == true)
    }

    private fun stage(activity: MainActivity): Stage =
        onMain { ActivityLifecycleMonitorRegistry.getInstance().getLifecycleStageOf(activity) }

    /** Waits up to seconds for condition, checked every 100 ms. */
    private fun await(what: String, seconds: Int, condition: () -> Boolean) {
        val end = SystemClock.elapsedRealtime() + seconds * 1_000L
        while (!condition()) {
            if (SystemClock.elapsedRealtime() > end) fail("timed out: " + what)
            SystemClock.sleep(100)
        }
    }

    private companion object {
        /** The start-up self-test's and a start's time limit (a translated library is slower; NativeTest's). */
        const val START_SECONDS = 120

        /** How long a press that must do nothing gets to land. */
        const val SETTLE_MS = 500L

        /** vectors/kcr.json's dice-50-words12: 123456 repeated. */
        const val DICE_50_ROLLS = "123456"

        /** vectors/kcr.json's dice-99-words12 and dice-99-words24: 654321 repeated. */
        const val DICE_99_ROLLS = "654321"

        /** C as the commitment screen shows it: four rows of four groups of four lower-case hex digits. */
        val HEX_GROUPS = Regex("^[0-9a-f]{4}( [0-9a-f]{4}){3}(\n[0-9a-f]{4}( [0-9a-f]{4}){3}){3}$")
    }
}
