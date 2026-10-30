package com.keepcrypt.entropy

import android.app.Activity
import android.os.PowerManager
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import androidx.test.uiautomator.UiDevice
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.launch
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Capture.probe
import com.keepcrypt.entropy.Capture.shellText
import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Words
import com.keepcrypt.entropy.screens.Notice
import com.keepcrypt.entropy.screens.Overlay
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.screens.screenId
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Discards on the phone (tasks/todo.md, M5 groups 14 and 17), run by scripts/android-instrument.sh on
 * the shipping app: the app is left during a backup's scrypt and during the start-up self-test (which
 * First launch's Continue runs, lead decision M5-50), and Wi-Fi comes on during a start; the app is
 * left on a words page (a Protected screen: discarded at once), and on the dice (a Public screen: 50 s
 * away keeps the session and 70 s wipes it, through the real 60 s rule on the phone's clock); and a words
 * page outlasts the system's shortest screen timeout, its window keeping the screen on until Finish
 * (lead decision M5-72 (b)); and a second start reaches the running activity (U2a). In each
 * the main thread never waits (the script's judge finds no not-responding window) and a discarded
 * session is gone: afterwards the slot is at home, where only an empty slot takes the self-test (a
 * session there would make that call halt), and the screen is the start screen, Go offline once the
 * start-up self-test has passed (group 15), saying why where the plan says so. And the ViewModel's
 * end, when the activity finishes, empties the slot (CeremonyHolder's onCleared calls wipeAll). The
 * ceremonies are vectors/kcr.json's public gate seed dice-50-words12, driven through Core on this
 * thread while the model runs nothing, as NativeTest drives it, or through the model's entry points
 * as its screens call them; the long calls, First launch's Continue among them, go through the model.
 */
@RunWith(AndroidJUnit4::class)
class LifecycleTest {
    private val device: UiDevice get() = UiDevice.getInstance(Capture.instrumentation)

    /**
     * The scrypt at log2 N = 18 runs for about a second on the CI emulators (runs 39582638947 to
     * 39642302623: the reply came back after 0.9 to 1.5 s) and about 0.5 s on kc37's native arm64
     * (Q76's local loop). Home reached the activity's onStop 0.6 to 1.1 s after the press on CI,
     * since UI Automator's press waits for the UI to go idle before it sends the key, so the two
     * raced, and on kc37 the scrypt won all three attempts of one run (lead decision M5-62 (c)).
     * So the leave is the activity sending its own task to the back (moveTaskToBack) in the same
     * main-thread step that starts the call, which is by then on its way to the worker (the
     * model's scope is Dispatchers.Main.immediate): the launcher comes to the front, and
     * SecureActivity's onStop reports the leave, as after Home. The call is the real backup
     * screen's (group 18): dice-50-words12 through the model's entry points, as its screens call
     * them, to the backup's confirm, whose second answer's Done (confirmTyped) has core check both
     * answers and then starts the encryption behind "Working...". The judge is unchanged (M5-47):
     * the leave counts only if it fell during the scrypt, its reply discarded, with the session
     * gone. An attempt whose reply came back first (the save screen) never reached the discard
     * during the scrypt and proves nothing: it is printed as a probe line, the activity is finished
     * (onCleared wipes the slot), and the case runs again on a fresh activity and session, up to
     * SCRYPT_ATTEMPTS times. An attempt that left during the scrypt is judged in full; none in
     * SCRYPT_ATTEMPTS fails the test.
     */
    @Test
    fun leavingDuringABackupsScryptDiscardsTheSession() {
        Capture.whileOffline {
            for (attempt in 1..SCRYPT_ATTEMPTS) {
                val activity = launch()
                selfTested(activity)
                await("the app reads airplane mode on and Wi-Fi off", 30) { onMain { activity.model.state.value.offline } }
                toTheLastAnswer(activity)
                val begun = SystemClock.elapsedRealtime()
                val moved = onMain {
                    activity.model.confirmTyped()
                    activity.moveTaskToBack(true)
                }
                assertTrue("moveTaskToBack did not send the app's task to the back", moved)
                await("the activity stopped", 30) { stage(activity) == Stage.STOPPED }
                val left = SystemClock.elapsedRealtime() - begun
                await("the long call's reply", 60) { onMain { activity.model.state.value.screen } != Screen.Working }
                val back = SystemClock.elapsedRealtime() - begun
                probe("backup scrypt, attempt $attempt: the app was left after $left ms; the reply came back after $back ms")
                if (onMain { activity.model.state.value.screen } == Screen.BackupSave) {
                    probe("backup scrypt, attempt $attempt: the scrypt ended before the app was left, so no discard came during it; again")
                    finish(activity)
                    continue
                }
                assertEquals(Screen.GoOffline, onMain { activity.model.state.value.screen })
                assertEquals(Notice.Left, onMain { activity.model.state.value.notice })
                assertTrue("the slot is not at home: the session was not discarded", Core.selfTest() is Reply.Done)
                pass("left during a backup's scrypt (attempt $attempt): discarded at once, the reply discarded, the session gone, no ANR")
                finish(activity)
                return@whileOffline
            }
            fail("the scrypt ended before the app was left in all $SCRYPT_ATTEMPTS attempts, so no discard came during it")
        }
    }

    /**
     * First launch's Continue (through the model, as its button calls it) runs the start-up self-test,
     * read back as the Self-test screen in the same main-thread step (the self-test's reply comes back
     * through the model's scope only after that step), so the press is seen to take and First launch
     * afterwards can only be a discard's. The app is left at once (Home), so the leave comes during the
     * self-test or just after it passed, and the screen it leaves behind once the self-test's reply is
     * in says which: First launch when the leave discarded the self-test (its Continue runs it again),
     * Go offline when the self-test had passed. Back in the app (am start, the task to the front), the
     * cover is taken away and, after a discard, Continue runs the self-test again; either way it has
     * passed, Go offline shows and the slot is empty. The pass line names the case: only "during" is
     * the discard during the self-test on the phone (lead decision M5-47; the JVM test
     * leavingDuringTheStartUpSelfTestReturnsToFirstLaunchWhoseContinueRunsItAgain holds that path on
     * every run).
     */
    @Test
    fun leavingDuringTheStartUpSelfTestLeavesNoSession() {
        val component = Capture.instrumentation.targetContext.packageName + "/com.keepcrypt.entropy.MainActivity"
        val activity = launch()
        await("the first screen, First launch", 10) { onMain { activity.shownScreen } == Screen.FirstLaunch }
        val begun = SystemClock.elapsedRealtime()
        val pressed = onMain {
            activity.model.firstLaunchDone()
            activity.model.state.value.screen
        }
        assertEquals("First launch's Continue did not start the self-test", Screen.SelfTest, pressed)
        device.pressHome()
        await("the activity stopped", 30) { stage(activity) == Stage.STOPPED }
        val left = SystemClock.elapsedRealtime() - begun
        await("the self-test's reply", START_SECONDS) { onMain { activity.model.state.value.screen } != Screen.SelfTest }
        val away = onMain { activity.model.state.value.screen }
        val during = away == Screen.FirstLaunch
        probe(
            "start-up self-test: the app was left $left ms after First launch's Continue; away it shows " +
                "${screenId(away)} (first_launch: the leave discarded the self-test)",
        )
        assertTrue("the screen left behind is neither First launch nor Go offline: " + screenId(away), during || away == Screen.GoOffline)
        shellText("am start -n " + component)
        await("back in the app", 30) { stage(activity) == Stage.RESUMED }
        onMain { activity.model.dismissOverlay() }
        if (during) onMain { activity.model.firstLaunchDone() }
        await("Go offline: the start-up self-test passed", START_SECONDS) { onMain { activity.shownScreen } == Screen.GoOffline }
        assertTrue("the slot is not at home", Core.selfTest() is Reply.Done)
        if (during) {
            pass(
                "left during the start-up self-test: discarded, First launch again, whose Continue ran it again and it passed; " +
                    "the slot is empty; no ANR",
            )
        } else {
            pass("left after the start-up self-test passed (not during it, this run): back on Go offline, the slot is empty; no ANR")
        }
        finish(activity)
    }

    /**
     * The ViewModel's end: a session started through Core, then the activity finished (no configuration
     * change, so its ViewModel is cleared and CeremonyHolder's onCleared calls wipeAll); once the
     * activity is destroyed the slot is at home and empty.
     */
    @Test
    fun finishingTheActivityEmptiesTheSlot() {
        val activity = launch()
        // First launch: the model has made no core call and runs none (lead decision M5-50).
        await("the first screen, First launch", 10) { onMain { activity.shownScreen } == Screen.FirstLaunch }
        done(Core.start(Words.Twelve, Mode.DiceOnly))
        finish(activity)
        assertTrue("the slot is not at home: onCleared did not wipe it", Core.selfTest() is Reply.Done)
        pass("the activity finished: the ViewModel's onCleared emptied the slot")
    }

    /**
     * Airplane mode on and Wi-Fi off (Capture.whileOffline), then Wi-Fi on while a start waits on the
     * worker: the offline monitor's report discards at once; the start, let go after that, reaches core
     * after the discard, and the model discards what it made again (a start takes well under the time
     * Wi-Fi takes to come on, so the call is held for the switch). The phone's settings are put back
     * after it.
     */
    @Test
    fun wifiComingOnDuringAStartDiscardsIt() {
        Capture.whileOffline {
            val activity = launch()
            selfTested(activity)
            probe("offline: airplane_mode_on=${settings("airplane_mode_on")}, wifi_on=${settings("wifi_on")}")
            await("the app reads airplane mode on and Wi-Fi off", 30) { onMain { activity.model.state.value.offline } }
            val entered = CountDownLatch(1)
            val release = CountDownLatch(1)
            val kept = AtomicBoolean(false)
            onMain {
                activity.model.work({
                    entered.countDown()
                    release.await()
                    Core.start(Words.Twelve, Mode.DiceOnly)
                }) { kept.set(true) }
            }
            assertTrue("the start never reached the worker", entered.await(10, TimeUnit.SECONDS))
            shellText("cmd wifi set-wifi-enabled enabled")
            await("the app reads Wi-Fi on", 30) { !onMain { activity.model.state.value.offline } }
            probe("online: airplane_mode_on=${settings("airplane_mode_on")}, wifi_on=${settings("wifi_on")}")
            release.countDown()
            await("the start screen", 30) { onMain { activity.model.state.value.screen } == Screen.GoOffline }
            assertFalse("the start's session was kept", kept.get())
            assertEquals(Notice.Offline, onMain { activity.model.state.value.notice })
            assertTrue("the slot is not at home: the session was not discarded", Core.selfTest() is Reply.Done)
            pass("Wi-Fi on during a start: discarded at once, the late start discarded again, the session gone, no ANR")
            finish(activity)
        }
    }

    /**
     * A words page (group 17), a Protected screen: dice-50-words12 through the model's entry points, as
     * its screens call them, to Skip's result, Show words and the privacy gate, and insert 2's page. Home:
     * by the time the activity has stopped, the session is discarded (its stop is the discard: no timer
     * runs for a Protected screen), the page on show wiped, the start screen saying why, the slot at home.
     */
    @Test
    fun leavingTheAppOnAWordsPageDiscardsTheSessionAtOnce() {
        Capture.whileOffline {
            val activity = launch()
            selfTested(activity)
            await("the app reads airplane mode on and Wi-Fi off", 30) { onMain { activity.model.state.value.offline } }
            toDice(activity)
            onMain {
                for (roll in DICE_50_ROLLS) {
                    activity.model.dicePick.replace(roll)
                    activity.model.confirmRoll()
                }
                activity.model.diceDone()
            }
            await("the check prompt", START_SECONDS) { onMain { activity.model.state.value.screen } == Screen.CheckPrompt }
            val page = onMain {
                activity.model.skip()
                activity.model.skipConfirmed()
                activity.model.showWords()
                activity.model.passGate()
                activity.model.nextPage()
                activity.model.state.value.let { if (it.screen == Screen.Words && it.page == 1) it.insert else null }
            } ?: throw AssertionError("not on insert 2's page")
            val begun = SystemClock.elapsedRealtime()
            device.pressHome()
            await("the activity stopped", 30) { stage(activity) == Stage.STOPPED }
            val away = onMain { activity.model.state.value }
            val after = SystemClock.elapsedRealtime() - begun
            probe("words page: Home pressed; the stop seen after $after ms, the screen then ${screenId(away.screen)}")
            assertEquals("leaving the words did not discard at once", Screen.GoOffline, away.screen)
            assertEquals(Notice.Left, away.notice)
            assertEquals(Overlay.Cover, away.overlay)
            assertTrue("the page on show was not wiped", onMain { page.position == 0 && page.word().size == 0 })
            assertTrue("the slot is not at home: the session was not discarded", Core.selfTest() is Reply.Done)
            pass("left on a words page: discarded at once (by the stop), the page wiped, the session gone, no ANR")
            finish(activity)
        }
    }

    /**
     * The dice (group 15), a Public screen: dice-50-words12's first ten rolls, then Home. Away 50 s (the
     * phone's real clock), the session is held and back in the app it is there under the privacy cover,
     * the same ten rolls; the cover tapped away, Home again: 70 s away wipes it (the 60 s rule: while away
     * if the timers run, else on the return, before anything shows; Q75), and back in the app Go offline
     * says why, the slot at home.
     */
    @Test
    fun fiftySecondsAwayFromTheDiceKeepTheSessionAndSeventyWipeIt() {
        Capture.whileOffline {
            val component = Capture.instrumentation.targetContext.packageName + "/com.keepcrypt.entropy.MainActivity"
            val activity = launch()
            selfTested(activity)
            await("the app reads airplane mode on and Wi-Fi off", 30) { onMain { activity.model.state.value.offline } }
            toDice(activity)
            onMain {
                for (roll in DICE_50_ROLLS.take(ROLLS_AWAY)) {
                    activity.model.dicePick.replace(roll)
                    activity.model.confirmRoll()
                }
            }
            device.pressHome()
            await("the activity stopped", 30) { stage(activity) == Stage.STOPPED }
            val left = SystemClock.elapsedRealtime()
            SystemClock.sleep(KEPT_MS)
            val held = onMain { activity.model.state.value }
            assertEquals("50 s away wiped the session", Screen.Dice, held.screen)
            assertEquals(Overlay.Cover, held.overlay)
            shellText("am start -n " + component)
            await("back in the app", 30) { stage(activity) == Stage.RESUMED }
            val back = SystemClock.elapsedRealtime() - left
            assertTrue("the return came after the 60 s rule's time ($back ms), so it proves nothing", back < BACKGROUND_MS)
            val kept = onMain { activity.model.state.value }
            assertEquals("the return after 50 s wiped the session", Screen.Dice, kept.screen)
            assertEquals(null, kept.notice)
            assertEquals(Overlay.Cover, kept.overlay)
            assertEquals("the rolls", ROLLS_AWAY, done(Core.diceProgress()).rolls)
            probe("dice: back after $back ms away, the session held under the cover")
            onMain { activity.model.dismissOverlay() }
            device.pressHome()
            await("the activity stopped", 30) { stage(activity) == Stage.STOPPED }
            val leftAgain = SystemClock.elapsedRealtime()
            SystemClock.sleep(WIPED_MS)
            val whileAway = onMain { activity.model.state.value.screen }
            shellText("am start -n " + component)
            await("back in the app", 30) { stage(activity) == Stage.RESUMED }
            val again = SystemClock.elapsedRealtime() - leftAgain
            val wiped = onMain { activity.model.state.value }
            probe("dice: back after $again ms away; away at 70 s the app showed ${screenId(whileAway)} (go_offline: the timers wiped it while away)")
            assertEquals("70 s away did not wipe the session", Screen.GoOffline, wiped.screen)
            assertEquals(Notice.Background, wiped.notice)
            assertTrue("the slot is not at home: the session was not wiped", Core.selfTest() is Reply.Done)
            pass("dice: 50 s away kept the session (back after $back ms), 70 s away wiped it (Go offline, the Background notice)")
            finish(activity)
        }
    }

    /**
     * A words page outlasts the system's screen timeout (lead decision M5-72 (b); docs/pi-firmware.md,
     * "slow punching or scanning is never cut short"; docs/mobile-apps.md, "Session lifetime"): a screen
     * that times out stops the activity, which is leaving the app, and a Protected screen is discarded
     * at once, so while the model holds a session (CeremonyModel.held) the activity's window has
     * FLAG_KEEP_SCREEN_ON, which the window manager turns into a screen wake lock while the window shows.
     * dice-50-words12 through the model's entry points, as its screens call them, to Skip's result, Show
     * words and the privacy gate. Then android-emulator.sh's `svc power stayon` is turned off
     * (Settings.Global's stay_on_while_plugged_in, which it writes) and the system's screen_off_timeout
     * set to its minimum, 10 s (config_minimumScreenOffTimeout, to which the power manager raises any
     * shorter setting); both are read first and put back as they were in a finally block, the display
     * woken if it slept, so no later test sees them. Insert 2's page (input for the model's idle time, so
     * its 30 s cover is not due), then twice that timeout: the session is held on the same page,
     * uncovered, with no notice, the activity resumed, the display still on, and the window has the flag
     * (dumpsys window's fl=). Without the flag the display sleeps within the timeout, the activity stops
     * and the session is discarded (Left). Then the read-back of every insert (its first four letters,
     * read in-process from the page the state holds), the summary, the exports skipped and Finish: Home,
     * nothing held, and the window no longer has the flag; the slot is at home. A probe line names, after
     * the wait, the screen, the activity's stage, whether the display is on and the power manager's facts
     * (its stay-on and timeout settings, the minimum, its wakefulness and its screen wake locks).
     */
    @Test
    fun aWordsPageOutlastsTheScreenTimeoutAndFinishClearsTheKeepScreenOnFlag() {
        Capture.whileOffline {
            val activity = launch()
            selfTested(activity)
            await("the app reads airplane mode on and Wi-Fi off", 30) { onMain { activity.model.state.value.offline } }
            toDice(activity)
            onMain {
                for (roll in DICE_50_ROLLS) {
                    activity.model.dicePick.replace(roll)
                    activity.model.confirmRoll()
                }
                activity.model.diceDone()
            }
            await("the check prompt", START_SECONDS) { onMain { activity.model.state.value.screen } == Screen.CheckPrompt }
            val shown = onMain {
                activity.model.skip()
                activity.model.skipConfirmed()
                activity.model.showWords()
                activity.model.passGate()
                activity.model.state.value.let { it.screen == Screen.Words && it.page == 0 && !it.gate }
            }
            assertTrue("not on insert 1's page past the privacy gate", shown)
            val power = checkNotNull(Capture.instrumentation.targetContext.getSystemService(PowerManager::class.java))
            val stayOn = shellText("settings get global stay_on_while_plugged_in")
            val timeout = shellText("settings get system screen_off_timeout")
            probe("before the screen timeout: stay_on_while_plugged_in=$stayOn, screen_off_timeout=$timeout")
            try {
                shellText("svc power stayon false")
                shellText("settings put system screen_off_timeout $MIN_SCREEN_OFF_MS")
                val set = "stay_on_while_plugged_in=${shellText("settings get global stay_on_while_plugged_in")}, " +
                    "screen_off_timeout=${shellText("settings get system screen_off_timeout")}"
                assertEquals("the settings did not take", "stay_on_while_plugged_in=0, screen_off_timeout=$MIN_SCREEN_OFF_MS", set)
                val page = onMain {
                    activity.model.nextPage()
                    activity.model.state.value.let { if (it.screen == Screen.Words && it.page == 1) it.insert else null }
                } ?: throw AssertionError("not on insert 2's page")
                val begun = SystemClock.elapsedRealtime()
                SystemClock.sleep(OUTLAST_MS)
                val after = onMain { activity.model.state.value }
                val lived = stage(activity)
                probe(
                    "words page, ${SystemClock.elapsedRealtime() - begun} ms past the timeout's start: the screen " +
                        "${screenId(after.screen)}, the activity $lived, the display ${if (power.isInteractive) "on" else "off"}; " +
                        powerFacts(),
                )
                assertEquals("the screen timeout discarded the session", Screen.Words, after.screen)
                assertEquals(null, after.notice)
                assertEquals("insert 2's page", 1, after.page)
                assertEquals("the page is covered", null, after.overlay)
                assertTrue("the session is not held", onMain { activity.model.held.value })
                assertTrue("the page on show was wiped", onMain { page.position == 2 })
                assertEquals("the activity is not resumed", Stage.RESUMED, lived)
                assertTrue("the display slept on a words page", power.isInteractive)
                await("the window has FLAG_KEEP_SCREEN_ON while the words show", 10) { keptOn() }
            } finally {
                restore("global", "stay_on_while_plugged_in", stayOn)
                restore("system", "screen_off_timeout", timeout)
                if (!power.isInteractive) {
                    shellText("input keyevent KEYCODE_WAKEUP")
                    shellText("wm dismiss-keyguard")
                }
            }
            val home = onMain {
                val model = activity.model
                repeat(10) { model.nextPage() }
                model.startReadback()
                repeat(12) {
                    val word = checkNotNull(model.state.value.insert).word()
                    for (index in 0 until minOf(4, word.size)) model.readbackLetters.type(Char(word[index].toInt()))
                    word.wipe()
                    model.readbackTyped()
                    model.readbackNext()
                }
                model.showSummary()
                model.summaryDone()
                model.skipBackup()
                model.skipWatchOnly()
                model.skipRegistration()
                val checklist = model.state.value.screen == Screen.Checklist && model.held.value
                model.finishCeremony()
                checklist && model.state.value.screen == Screen.Home && !model.held.value
            }
            assertTrue("the read-back, the exports skipped and Finish did not end at Home with nothing held", home)
            await("the window no longer has FLAG_KEEP_SCREEN_ON after Finish", 10) { !keptOn() }
            assertTrue("the slot is not at home: Finish did not end the session", Core.selfTest() is Reply.Done)
            pass(
                "a words page outlasted the screen timeout ($MIN_SCREEN_OFF_MS ms, stay-on off) by its window's " +
                    "FLAG_KEEP_SCREEN_ON, the session held; after Finish the window has no flag",
            )
            finish(activity)
        }
    }

    /**
     * One activity (Stage U's commit U2a): a second start of MainActivity, as another app's intent with
     * FLAG_ACTIVITY_NEW_TASK and FLAG_ACTIVITY_MULTIPLE_TASK (am start -W, which returns once the launch
     * is done), reaches the running activity, since the manifest's launchMode is singleTask: no second
     * MainActivity is created in any stage, the first one is resumed, and its model still holds the
     * session on the dice with its rolls, uncovered and with no notice. With the standard launch mode
     * that intent made a new task with a second activity and a second ceremony model over the process's
     * one slot, and the first activity's stop covered its dice.
     */
    @Test
    fun aSecondStartReachesTheRunningActivityAndItsSession() {
        Capture.whileOffline {
            val component = Capture.instrumentation.targetContext.packageName + "/com.keepcrypt.entropy.MainActivity"
            val activity = launch()
            selfTested(activity)
            await("the app reads airplane mode on and Wi-Fi off", 30) { onMain { activity.model.state.value.offline } }
            toDice(activity)
            onMain {
                for (roll in DICE_50_ROLLS.take(ROLLS_AWAY)) {
                    activity.model.padKey(roll)
                    activity.model.confirmRoll()
                }
            }
            val started = shellText("am start -W -n $component -f $NEW_TASK_MULTIPLE_TASK")
            probe("second start: am start -W printed " + started.lines().map { it.trim() }.filter { it.isNotEmpty() }.joinToString(" | ").take(400))
            await("the activity resumed", 30) { stage(activity) == Stage.RESUMED }
            val others = onMain {
                val registry = ActivityLifecycleMonitorRegistry.getInstance()
                Stage.values().filter { it != Stage.DESTROYED }
                    .flatMap { registry.getActivitiesInStage(it) }
                    .filter { it is MainActivity && it !== activity }
            }
            assertEquals("a second MainActivity was created", 0, others.size)
            val held = onMain { activity.model.state.value }
            assertEquals("the second start left the dice", Screen.Dice, held.screen)
            assertEquals(null, held.overlay)
            assertEquals(null, held.notice)
            assertTrue("the session is no longer held", onMain { activity.model.held.value })
            assertEquals("the rolls", ROLLS_AWAY, done(Core.diceProgress()).rolls)
            pass("a second start (NEW_TASK and MULTIPLE_TASK) reached the running activity: one MainActivity, its session on the dice")
            finish(activity)
        }
    }

    /** From Go offline, offline: Start, Dice-only seed, 12 words (the start's long call), through the model as the buttons call it, to the dice. */
    private fun toDice(activity: MainActivity) {
        onMain {
            activity.model.startOffline()
            activity.model.chooseMode(Mode.DiceOnly)
            activity.model.chooseLength(Words.Twelve)
        }
        await("the dice", START_SECONDS) { onMain { activity.model.state.value.screen } == Screen.Dice }
    }

    /**
     * First launch, then its Continue (through the model, as its button calls it), which runs the
     * start-up self-test, to Go offline: past the start-up, a discard's start screen is Go offline and
     * going online discards (lead decision M5-50).
     */
    private fun selfTested(activity: MainActivity) {
        await("the first screen, First launch", 10) { onMain { activity.shownScreen } == Screen.FirstLaunch }
        onMain { activity.model.firstLaunchDone() }
        await("Go offline: the start-up self-test passed", START_SECONDS) { onMain { activity.shownScreen } == Screen.GoOffline }
    }

    /**
     * dice-50-words12 through the model's entry points, as its screens call them, to the backup's confirm
     * with its second answer typed and its Done not yet pressed: from Go offline the dice-only ceremony,
     * Skip, the words to the last insert past their privacy gate, the read-back of every insert (its first
     * four letters, read in-process from the page the state holds), the summary, the offer's "Make an
     * encrypted backup", the passphrase past its gate (its two pages read in-process from the state's
     * Secrets), "I wrote it down", the first answer and its Done, and the second answer's letters on the
     * model's letter pad. The passphrase's copies are zeroed once typed.
     */
    private fun toTheLastAnswer(activity: MainActivity) {
        toDice(activity)
        val ready = onMain {
            val model = activity.model
            for (roll in DICE_50_ROLLS) {
                model.dicePick.replace(roll)
                model.confirmRoll()
            }
            model.diceDone()
            model.state.value.screen == Screen.Working
        }
        assertTrue("the dice's Done did not start the seed", ready)
        await("the check prompt", START_SECONDS) { onMain { activity.model.state.value.screen } == Screen.CheckPrompt }
        val confirm = onMain {
            val model = activity.model
            model.skip()
            model.skipConfirmed()
            model.showWords()
            model.passGate()
            repeat(11) { model.nextPage() }
            model.startReadback()
            repeat(12) {
                val word = checkNotNull(model.state.value.insert).word()
                for (index in 0 until minOf(4, word.size)) model.readbackLetters.type(Char(word[index].toInt()))
                word.wipe()
                model.readbackTyped()
                model.readbackNext()
            }
            model.showSummary()
            model.summaryDone()
            model.makeBackup()
            model.passGate()
            val words = ArrayList<ByteArray>()
            for (page in 0..1) {
                if (page == 1) model.nextPage()
                val text = checkNotNull(model.state.value.passphrase)
                var start = 0
                for (at in 0..text.size) {
                    if (at == text.size || text[at] == SPACE) {
                        words.add(ByteArray(at - start) { text[start + it] })
                        start = at + 1
                    }
                }
            }
            model.passphraseWritten()
            for (question in 0..1) {
                val state = model.state.value
                val word = words[checkNotNull(state.challenge).questions[state.page].position - 1]
                for (index in 0 until minOf(4, word.size)) model.backupLetters.type(Char(word[index].toInt()))
                if (question == 0) model.confirmTyped()
            }
            for (word in words) word.fill(0)
            model.state.value.let { it.screen == Screen.BackupConfirm && it.page == 1 && words.size == 8 }
        }
        assertTrue("the ceremony did not reach the backup's second question with eight passphrase words", confirm)
    }

    /** reply's value; any other reply fails the test. */
    private fun <T> done(reply: Reply<T>): T = when (reply) {
        is Reply.Done -> reply.value
        is Reply.Refused, Reply.Discarded -> throw AssertionError("a call that must succeed did not")
    }

    private fun stage(activity: Activity): Stage =
        onMain { ActivityLifecycleMonitorRegistry.getInstance().getLifecycleStageOf(activity) }

    private fun settings(name: String): String = Capture.globalSetting(name)

    /** Whether one of the app's windows has FLAG_KEEP_SCREEN_ON in the flags dumpsys window lists (fl=). */
    private fun keptOn(): Boolean {
        val windows = Capture.windows(Capture.instrumentation.targetContext.packageName)
        assertTrue("dumpsys window lists no window of the app", windows.isNotEmpty())
        return windows.any { it.keepScreenOn }
    }

    /** A setting of namespace (global or system) put back to value as settings get read it ("null": none, so deleted). */
    private fun restore(namespace: String, name: String, value: String) {
        if (value == "null") shellText("settings delete $namespace $name") else shellText("settings put $namespace $name $value")
    }

    /**
     * The power manager's facts the screen timeout turns on (dumpsys power): its stay-on and timeout
     * settings, the timeout's minimum, its wakefulness and its screen wake locks (a window's
     * FLAG_KEEP_SCREEN_ON is the window manager's), each line trimmed, in one line.
     */
    private fun powerFacts(): String {
        val wanted = Regex(
            "^(mStayOn=|mStayOnWhilePluggedInSetting=|mScreenOffTimeoutSetting=|mMinimumScreenOffTimeoutConfig=|mWakefulness=)",
        )
        return shellText("dumpsys power").lines().map { it.trim() }
            .filter { wanted.containsMatchIn(it) || it.startsWith("SCREEN_BRIGHT_WAKE_LOCK") }
            .distinct()
            .joinToString("; ") { it.take(160) }
    }

    /** Waits up to seconds for condition, checked every 100 ms. */
    private fun await(what: String, seconds: Int, condition: () -> Boolean) {
        val end = SystemClock.elapsedRealtime() + seconds * 1_000L
        while (!condition()) {
            if (SystemClock.elapsedRealtime() > end) fail("timed out: " + what)
            SystemClock.sleep(100)
        }
    }

    private companion object {
        /** The start-up self-test's time limit (a translated library is slower; NativeTest's). */
        const val START_SECONDS = 120

        /** vectors/kcr.json's dice-50-words12: 50 rolls, 123456 repeated. */
        const val DICE_50_ROLLS = "12345612345612345612345612345612345612345612345612"

        /** The space between the backup passphrase's words. */
        const val SPACE: Byte = 0x20

        /** How many times the scrypt case may miss its window before it fails. */
        const val SCRYPT_ATTEMPTS = 3

        /** The rolls on the dice before the app is left there. */
        const val ROLLS_AWAY = 10

        /** am start's -f for FLAG_ACTIVITY_NEW_TASK (0x10000000) with FLAG_ACTIVITY_MULTIPLE_TASK (0x08000000). */
        const val NEW_TASK_MULTIPLE_TASK = "0x18000000"

        /** The 60 s rule (Timers.BACKGROUND_MILLIS), 50 s away that keep the session and 70 s that wipe it. */
        const val BACKGROUND_MS = 60_000L
        const val KEPT_MS = 50_000L
        const val WIPED_MS = 70_000L

        /**
         * The shortest screen timeout the power manager honours (AOSP's config_minimumScreenOffTimeout, 10 s
         * in the API 37 SDK's copy of the framework's config.xml), and twice it, which a words page must
         * outlast while its 30 s cover is not yet due.
         */
        const val MIN_SCREEN_OFF_MS = 10_000
        const val OUTLAST_MS = 2L * MIN_SCREEN_OFF_MS
    }
}
