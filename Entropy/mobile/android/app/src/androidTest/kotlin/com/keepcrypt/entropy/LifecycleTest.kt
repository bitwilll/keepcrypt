package com.keepcrypt.entropy

import android.app.Activity
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
import com.keepcrypt.entropy.ffi.Readback
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Secret
import com.keepcrypt.entropy.ffi.Words
import com.keepcrypt.entropy.screens.Notice
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
 * Discards during "Working..." on the phone (tasks/todo.md, M5 group 14), run by
 * scripts/android-instrument.sh on the shipping app: the app is left during a backup's scrypt and
 * during the start-up self-test (which First launch's Continue runs, lead decision M5-50), and Wi-Fi
 * comes on during a start. In each the main thread never waits (the script's judge finds no
 * not-responding window) and the session is gone: afterwards the slot is at home, where only an empty
 * slot takes the self-test (a session there would make that call halt), and the screen is the start
 * screen, Go offline once the start-up self-test has passed (group 15), saying why where the plan says
 * so. And the ViewModel's end, when the activity finishes, empties the slot (CeremonyHolder's
 * onCleared calls wipeAll). The ceremony is vectors/kcr.json's public gate seed dice-50-words12,
 * driven through Core on this thread while the model runs nothing, as NativeTest drives it; the long
 * calls, First launch's Continue among them, go through the model, as its screens make them.
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
     * SecureActivity's onStop reports the leave, as after Home. The judge is unchanged (M5-47):
     * the leave counts only if it fell during the scrypt, its reply discarded, with the session
     * gone. An attempt whose reply came back first never reached the discard during the scrypt and
     * proves nothing: it is printed as a probe line, the activity is finished (onCleared wipes the
     * slot), and the case runs again on a fresh activity and session, up to SCRYPT_ATTEMPTS times.
     * An attempt that left during the scrypt is judged in full; none in SCRYPT_ATTEMPTS fails the
     * test.
     */
    @Test
    fun leavingDuringABackupsScryptDiscardsTheSession() {
        for (attempt in 1..SCRYPT_ATTEMPTS) {
            val activity = launch()
            selfTested(activity)
            readyToEncrypt()
            val encrypted = AtomicBoolean(false)
            val begun = SystemClock.elapsedRealtime()
            val moved = onMain {
                activity.model.work({ Core.encryptBackup() }) { encrypted.set(true) }
                activity.moveTaskToBack(true)
            }
            assertTrue("moveTaskToBack did not send the app's task to the back", moved)
            await("the activity stopped", 30) { stage(activity) == Stage.STOPPED }
            val left = SystemClock.elapsedRealtime() - begun
            await("the long call's reply", 60) { onMain { activity.model.state.value.screen } != Screen.Working }
            val back = SystemClock.elapsedRealtime() - begun
            probe("backup scrypt, attempt $attempt: the app was left after $left ms; the reply came back after $back ms")
            if (encrypted.get()) {
                probe("backup scrypt, attempt $attempt: the scrypt ended before the app was left, so no discard came during it; again")
                finish(activity)
                continue
            }
            assertEquals(Screen.GoOffline, onMain { activity.model.state.value.screen })
            assertEquals(Notice.Left, onMain { activity.model.state.value.notice })
            assertTrue("the slot is not at home: the session was not discarded", Core.selfTest() is Reply.Done)
            pass("left during a backup's scrypt (attempt $attempt): discarded at once, the reply discarded, the session gone, no ANR")
            finish(activity)
            return
        }
        fail("the scrypt ended before the app was left in all $SCRYPT_ATTEMPTS attempts, so no discard came during it")
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
     * dice-50-words12 through Core to the backup's encryption: the dice-only ceremony, Skip, the
     * read-back of every insert (its first four letters, read from its page), and the backup
     * passphrase generated and confirmed (each question's choice found among the passphrase's pages).
     */
    private fun readyToEncrypt() {
        done(Core.start(Words.Twelve, Mode.DiceOnly))
        done(Core.commit())
        done(Core.startDice())
        for (roll in DICE_50_ROLLS) done(Core.pushRoll(roll - '0'))
        done(Core.finish())
        done(Core.skipCheck())
        for (position in 1..12) {
            val page = done(Core.wordPage(position))
            val word = page.word()
            page.wipe()
            val letters = Secret(ByteArray(minOf(4, word.size)) { word[it] })
            word.wipe()
            val readback = done(Core.checkReadback(position, letters))
            letters.wipe()
            assertTrue("an insert did not read back", readback is Readback.Match)
        }
        done(Core.generateBackupPassphrase())
        val words = ArrayList<ByteArray>()
        for (page in 0..1) {
            val text = done(Core.backupPassphrasePage(page))
            var start = 0
            for (at in 0..text.size) {
                if (at == text.size || text[at] == SPACE) {
                    words.add(ByteArray(at - start) { text[start + it] })
                    start = at + 1
                }
            }
            text.wipe()
        }
        assertEquals("eight passphrase words", 8, words.size)
        val challenge = done(Core.backupChallenge())
        val picks = challenge.questions.map { question ->
            question.choices.indexOfFirst { choice -> same(choice, words[question.position - 1]) }
        }
        challenge.wipe()
        for (word in words) word.fill(0)
        assertTrue("the backup passphrase's confirm failed", done(Core.confirmBackup(picks[0], picks[1])))
    }

    private fun same(choice: Secret, word: ByteArray): Boolean =
        choice.size == word.size && word.indices.all { choice[it] == word[it] }

    /** reply's value; any other reply fails the test. */
    private fun <T> done(reply: Reply<T>): T = when (reply) {
        is Reply.Done -> reply.value
        is Reply.Refused, Reply.Discarded -> throw AssertionError("a call that must succeed did not")
    }

    private fun stage(activity: Activity): Stage =
        onMain { ActivityLifecycleMonitorRegistry.getInstance().getLifecycleStageOf(activity) }

    private fun settings(name: String): String = Capture.globalSetting(name)

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
    }
}
