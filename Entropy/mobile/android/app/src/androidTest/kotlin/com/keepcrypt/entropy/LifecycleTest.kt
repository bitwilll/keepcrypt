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
 * during the start-up self-test, and Wi-Fi comes on during a start. In each the main thread never
 * waits (the script's judge finds no not-responding window) and the session is gone: afterwards the
 * slot is at home, where only an empty slot takes the self-test (a session there would make that call
 * halt). The ceremony is vectors/kcr.json's public gate seed dice-50-words12, driven through Core on
 * this thread while the model runs nothing, as NativeTest drives it; the long calls go through the
 * model, as its screens make them.
 */
@RunWith(AndroidJUnit4::class)
class LifecycleTest {
    private val device: UiDevice get() = UiDevice.getInstance(Capture.instrumentation)

    /**
     * The scrypt at log2 N = 18 runs for a second or so, and leaving the app (Home) reaches the activity
     * within a few hundred milliseconds of the press, so the discard comes while core runs it; a reply
     * that came back with the file first fails the test, with the times printed.
     */
    @Test
    fun leavingDuringABackupsScryptDiscardsTheSession() {
        val activity = launch()
        await("the first screen", START_SECONDS) { onMain { activity.shownScreen } == Screen.FirstLaunch }
        readyToEncrypt()
        val encrypted = AtomicBoolean(false)
        val begun = SystemClock.elapsedRealtime()
        onMain { activity.model.work({ Core.encryptBackup() }) { encrypted.set(true) } }
        device.pressHome()
        await("the activity stopped", 30) { stage(activity) == Stage.STOPPED }
        val left = SystemClock.elapsedRealtime() - begun
        await("the long call's reply", 60) { onMain { activity.model.state.value.screen } != Screen.Working }
        val back = SystemClock.elapsedRealtime() - begun
        probe("backup scrypt: the app was left after $left ms; the reply came back after $back ms")
        assertFalse("the scrypt ended before the app was left, so no discard came during it", encrypted.get())
        assertEquals(Screen.FirstLaunch, onMain { activity.model.state.value.screen })
        assertEquals(Notice.Left, onMain { activity.model.state.value.notice })
        assertTrue("the slot is not at home: the session was not discarded", Core.selfTest() is Reply.Done)
        pass("left during a backup's scrypt: discarded at once, the reply discarded, the session gone, no ANR")
        finish(activity)
    }

    /**
     * The app is started from the shell and left at once, so the leave comes during its start-up
     * self-test or just after it: either way, back in the app, the self-test has passed (run again if
     * the leave discarded it) and the slot is empty.
     */
    @Test
    fun leavingDuringTheStartUpSelfTestLeavesNoSession() {
        val component = Capture.instrumentation.targetContext.packageName + "/com.keepcrypt.entropy.MainActivity"
        val begun = SystemClock.elapsedRealtime()
        shellText("am start -n " + component)
        device.pressHome()
        var found: MainActivity? = null
        await("the app's activity, left", 30) {
            found = onMain {
                ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(Stage.STOPPED)
                    .filterIsInstance<MainActivity>().firstOrNull()
            }
            found != null
        }
        val activity = found!!
        val away = onMain { activity.model.state.value.screen }
        probe(
            "start-up self-test: the app was left ${SystemClock.elapsedRealtime() - begun} ms after its start; " +
                "away it shows ${screenId(away)} (working: the self-test had not passed)",
        )
        shellText("am start -n " + component)
        await("the first screen after the return", START_SECONDS) {
            onMain { activity.shownScreen } == Screen.FirstLaunch && stage(activity) == Stage.RESUMED
        }
        assertTrue("the slot is not at home", Core.selfTest() is Reply.Done)
        pass("left during the start-up: back, the self-test passed and the slot is empty; no ANR")
        finish(activity)
    }

    /**
     * Airplane mode on and Wi-Fi off, then Wi-Fi on while a start waits on the worker: the offline
     * monitor's report discards at once; the start, let go after that, reaches core after the discard,
     * and the model discards what it made again (a start takes well under the time Wi-Fi takes to come
     * on, so the call is held for the switch). The phone's settings are put back after it.
     */
    @Test
    fun wifiComingOnDuringAStartDiscardsIt() {
        val airplane = shellText("settings get global airplane_mode_on")
        val wifi = shellText("settings get global wifi_on")
        probe("before the test: airplane_mode_on=$airplane, wifi_on=$wifi")
        try {
            shellText("cmd connectivity airplane-mode enable")
            shellText("cmd wifi set-wifi-enabled disabled")
            val activity = launch()
            await("the first screen", START_SECONDS) { onMain { activity.shownScreen } == Screen.FirstLaunch }
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
            await("the start screen", 30) { onMain { activity.model.state.value.screen } == Screen.FirstLaunch }
            assertFalse("the start's session was kept", kept.get())
            assertEquals(Notice.Offline, onMain { activity.model.state.value.notice })
            assertTrue("the slot is not at home: the session was not discarded", Core.selfTest() is Reply.Done)
            pass("Wi-Fi on during a start: discarded at once, the late start discarded again, the session gone, no ANR")
            finish(activity)
        } finally {
            shellText("cmd connectivity airplane-mode " + (if (airplane == "1") "enable" else "disable"))
            shellText("cmd wifi set-wifi-enabled " + (if (wifi == "0" || wifi == "3") "disabled" else "enabled"))
        }
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

    private fun settings(name: String): String = shellText("settings get global " + name)

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
    }
}
