package com.keepcrypt.entropy

import android.os.SystemClock
import android.view.WindowManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Capture.probe
import com.keepcrypt.entropy.Capture.shellText
import com.keepcrypt.entropy.GateSeeds.DICE_50_ROLLS
import com.keepcrypt.entropy.GateSeeds.DICE_50_WORDS
import com.keepcrypt.entropy.Journeys.since
import com.keepcrypt.entropy.Ui.START_SECONDS
import com.keepcrypt.entropy.Ui.assertInsert
import com.keepcrypt.entropy.Ui.await
import com.keepcrypt.entropy.Ui.awaitPick
import com.keepcrypt.entropy.Ui.awaitText
import com.keepcrypt.entropy.Ui.device
import com.keepcrypt.entropy.Ui.find
import com.keepcrypt.entropy.Ui.on
import com.keepcrypt.entropy.Ui.pressFace
import com.keepcrypt.entropy.Ui.tap
import com.keepcrypt.entropy.Ui.tapRolls
import com.keepcrypt.entropy.Ui.text
import com.keepcrypt.entropy.Ui.toHome
import com.keepcrypt.entropy.Ui.touchOn
import com.keepcrypt.entropy.screens.Screen
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * A real configuration change on the phone (tasks/todo.md, Stage U's U2h), on the shipping app in
 * android-emulator.sh's registry part, after LifecycleTest: a rotation (to landscape and back), a font
 * scale (1.3 and back) and a night-mode switch (to the other mode and back) on four screens of
 * vectors/kcr.json's public gate seed dice-50-words12, reached through the UI: the dice with three rolls
 * tapped and a fourth face picked, the code entry with four symbols of the go-ahead code typed, the words'
 * privacy gate, and the words page of insert 2. MainActivity declares no configChanges (its manifest), so
 * each change recreates the activity: each must bring a new MainActivity, the old one destroyed, over the
 * same ceremony model (CeremonyHolder, the ViewModel), with the screen, its page, its gate, what is held
 * and every pad's entry as they were (the model's state, read in-process, compared and never printed:
 * the state of a words page holds its insert), so the change took no step and made no call (U2d's JVM
 * test, ConfigurationAndOnlineTest, counts the worker's calls); and its window keeps FLAG_SECURE. Before
 * each change a touch on a text that takes no press is an input (Ui.touchOn), since a Protected screen's
 * cover after 30 s without one would change the state. After the changes the ceremony goes on from what
 * they kept: the picked face confirmed and the 50 rolls finished, the rest of the code typed and the check
 * passed, the gate passed and the page's word the vector's. Every setting changed is put back in a finally.
 */
@RunWith(AndroidJUnit4::class)
class DeviceChangeTest {
    @Test
    fun rotationFontScaleAndNightModeRecreateTheActivityAndKeepTheDiceTheCodeEntryTheGateAndAWordsPage() {
        val autoRotate = shellText("settings get system accelerometer_rotation")
        val fontScale = shellText("settings get system font_scale")
        val night = shellText("cmd uimode night").contains("yes")
        try {
            Capture.whileOffline {
                val start = SystemClock.elapsedRealtime()
                var activity = toHome()
                tap("dice_only_seed")
                on(activity, Screen.Length)
                tap("words_12")
                on(activity, Screen.Dice, START_SECONDS)
                tapRolls(activity, 3, DICE_50_ROLLS)
                pressFace(DICE_50_ROLLS[3])
                awaitPick(DICE_50_ROLLS[3])
                activity = changes(activity, "the dice with 3 rolls and a face picked", "dice_count", night, fontScale)
                tap("confirm")
                tapRolls(activity, 46, DICE_50_ROLLS.substring(4) + DICE_50_ROLLS.substring(0, 4))
                awaitText("dice_count", "50 / 50 rolls, 129.2 bits")
                tap("dice_done")
                on(activity, Screen.CheckPrompt, START_SECONDS)
                tap("check_now")
                on(activity, Screen.SealCard)
                tap("show_check_qr")
                on(activity, Screen.CheckQr)
                val drawn = Checker.read(onMain { activity.model.state.value.checkRequest } ?: throw AssertionError("no check QR"))
                val (tag, nonce) = Checker.request(drawn)
                val code = Checker.goAhead(tag, nonce)
                tap("type_code")
                on(activity, Screen.CodeEntry)
                for (symbol in code.take(4)) tap("key_$symbol")
                val model = activity.model
                await("four symbols of the code typed", 10) { onMain { model.goAheadCode.length == 4 } }
                activity = changes(activity, "the code entry with 4 symbols typed", "code", night, fontScale)
                for (symbol in code.drop(4)) tap("key_$symbol")
                awaitText("code", Checker.grouped(code))
                tap("code_done")
                on(activity, Screen.CheckResult, START_SECONDS)
                assertTrue("the check did not pass", text("check_result_text").startsWith("No collision for seal "))
                tap("show_words")
                find("privacy_gate")
                assertTrue("the words showed before the privacy gate", onMain { model.state.value.gate })
                activity = changes(activity, "the words' privacy gate", "seedbook_rules", night, fontScale)
                tap("pass_gate")
                assertInsert(activity, DICE_50_WORDS, 0, 1, 1)
                tap("next")
                assertInsert(activity, DICE_50_WORDS, 1, 1, 1)
                activity = changes(activity, "the words page of insert 2", "insert_header", night, fontScale)
                assertInsert(activity, DICE_50_WORDS, 1, 1, 1)
                pass(
                    "a rotation, a font scale and a night-mode switch, each and its way back (24 changes), on the dice with " +
                        "a face picked, the code entry with 4 symbols, the words' gate and the words page of insert 2: each a " +
                        "new MainActivity over the same model, the state, what is held and every pad kept, FLAG_SECURE on " +
                        "each new window; then the 50 rolls, the code's check and the page's word from what was kept; " +
                        "the test " + since(start),
                )
                finish(activity)
            }
        } finally {
            device.setOrientationNatural()
            if (autoRotate == "1") device.unfreezeRotation()
            shellText("settings put system font_scale " + if (fontScale == "null") "1.0" else fontScale)
            shellText("cmd uimode night " + if (night) "yes" else "no")
        }
    }

    /**
     * The three changes on what, each to its other setting and back (six recreations), each kept (change),
     * the touch before each on the text tag. Returns the activity the last one made.
     */
    private fun changes(start: MainActivity, what: String, tag: String, night: Boolean, fontScale: String): MainActivity {
        val begun = SystemClock.elapsedRealtime()
        var activity = start
        activity = change(activity, "$what, rotated to landscape", tag) { device.setOrientationLeft() }
        activity = change(activity, "$what, rotated back", tag) { device.setOrientationNatural() }
        activity = change(activity, "$what, font scale 1.3", tag) { shellText("settings put system font_scale 1.3") }
        val back = if (fontScale == "null") "1.0" else fontScale
        activity = change(activity, "$what, font scale back", tag) { shellText("settings put system font_scale $back") }
        val other = if (night) "no" else "yes"
        activity = change(activity, "$what, night mode $other", tag) { shellText("cmd uimode night $other") }
        activity = change(activity, "$what, night mode back", tag) { shellText("cmd uimode night " + if (night) "yes" else "no") }
        probe("$what: six changes, each a new activity with everything kept, in " + since(begun))
        return activity
    }

    /**
     * One configuration change, made by apply after a touch on tag (an input): a new MainActivity, resumed,
     * the old one destroyed, over the same model, showing the same screen (or its gate), with the model's
     * state, what is held and the pads' entries as they were (compared in-process, never printed), and
     * FLAG_SECURE on its window. Returns the new activity.
     */
    private fun change(old: MainActivity, what: String, tag: String, apply: () -> Unit): MainActivity {
        touchOn(tag)
        val model = old.model
        val before = onMain { model.state.value }
        val held = onMain { model.held.value }
        val pads = onMain { pads(old) }
        apply()
        var recreated: MainActivity? = null
        await("$what: a new MainActivity resumed", 30) {
            recreated = onMain {
                ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(Stage.RESUMED)
                    .filterIsInstance<MainActivity>().firstOrNull { it !== old }
            }
            recreated != null
        }
        val activity = checkNotNull(recreated)
        assertTrue("$what: the activity before it was not destroyed", onMain { old.isDestroyed })
        assertTrue("$what: the new activity has another model: the session did not outlive the change", onMain { activity.model } === model)
        on(activity, before.screen)
        assertTrue("$what: the model's state changed (neither is printed)", onMain { model.state.value } == before)
        assertTrue("$what: what is held changed", onMain { model.held.value } == held)
        assertTrue("$what: a pad's entry changed (neither is printed)", onMain { pads(activity) } == pads)
        val secure = onMain { activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0 }
        assertTrue("$what: the new window is not FLAG_SECURE", secure)
        return activity
    }

    /**
     * Every pad's entry: its length, and the Public pads' keys (the dice pick and the go-ahead code, which
     * are no secret; the letter and ASCII pads' are empty here, their lengths compared).
     */
    private fun pads(activity: MainActivity): List<String> = with(activity.model) {
        listOf(
            String(CharArray(dicePick.length) { dicePick.keyAt(it) }),
            String(CharArray(goAheadCode.length) { goAheadCode.keyAt(it) }),
            readbackLetters.length.toString(),
            backupLetters.length.toString(),
            bip39Letters.length.toString(),
        )
    }
}
