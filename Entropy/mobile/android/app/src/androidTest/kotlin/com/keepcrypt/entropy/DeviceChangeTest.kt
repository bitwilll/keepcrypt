package com.keepcrypt.entropy

import android.content.res.Configuration
import android.os.SystemClock
import android.view.Surface
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
import com.keepcrypt.entropy.Ui.touchMargin
import com.keepcrypt.entropy.screens.Screen
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import kotlin.math.abs

/**
 * A real configuration change on the phone (tasks/todo.md, Stage U's U2h, and U2m for Q77), on the shipping
 * app in android-emulator.sh's registry part, after LifecycleTest: a rotation request (to landscape and back),
 * a font scale (1.3 and back) and a night-mode switch (to the other mode and back) on four screens of
 * vectors/kcr.json's public gate seed dice-50-words12, reached through the UI: the dice with three rolls
 * tapped and a fourth face picked, the code entry with four symbols of the go-ahead code typed, the words'
 * privacy gate, and the words page of insert 2. MainActivity is portrait and handles these changes in place
 * (its manifest's screenOrientation and configChanges), so each must leave the SAME MainActivity resumed,
 * never destroyed and with no other instance in any stage, its configuration showing the change (still
 * portrait on its display's natural rotation after the rotation request; the font scale; the night mode),
 * over the same ceremony model, with the screen, its page, its gate, what is held and every pad's entry as
 * they were (the model's state, read in-process, compared and never printed: the state of a words page holds
 * its insert), so the change took no step and made no call (U2d's JVM test, ConfigurationAndOnlineTest,
 * counts the worker's calls); and its window keeps FLAG_SECURE. Then one recreation on each screen
 * (Activity.recreate, what a change the manifest does not handle still does, a locale change say): a new
 * MainActivity, the old one destroyed, over the same model (CeremonyHolder, the ViewModel), everything kept
 * and FLAG_SECURE on its window, and the Bundle it was given holds nothing (the one a process death would
 * keep: KillTest, U2j-b, M5-80). Before each change a touch in the screen's own margin is an input
 * (Ui.touchMargin), since a Protected screen's cover after 30 s without one would change the state. After
 * the changes the ceremony goes on from what they kept: the picked face confirmed and the 50 rolls finished,
 * the rest of the code typed and the check passed, the gate passed and the page's word the vector's. Every
 * setting changed is put back in a finally.
 */
@RunWith(AndroidJUnit4::class)
class DeviceChangeTest {
    @Test
    fun rotationFontScaleAndNightModeKeepTheActivityAndTheDiceTheCodeEntryTheGateAndAWordsPage() {
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
                activity = changes(activity, "the dice with 3 rolls and a face picked", night, fontScale)
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
                activity = changes(activity, "the code entry with 4 symbols typed", night, fontScale)
                for (symbol in code.drop(4)) tap("key_$symbol")
                awaitText("code", Checker.grouped(code))
                tap("code_done")
                on(activity, Screen.CheckResult, START_SECONDS)
                assertTrue("the check did not pass", text("check_result_text").startsWith("No collision for seal "))
                tap("show_words")
                find("privacy_gate")
                assertTrue("the words showed before the privacy gate", onMain { model.state.value.gate })
                activity = changes(activity, "the words' privacy gate", night, fontScale)
                tap("pass_gate")
                assertInsert(activity, DICE_50_WORDS, 0, 1, 1)
                tap("next")
                assertInsert(activity, DICE_50_WORDS, 1, 1, 1)
                activity = changes(activity, "the words page of insert 2", night, fontScale)
                assertInsert(activity, DICE_50_WORDS, 1, 1, 1)
                pass(
                    "a rotation request, a font scale and a night-mode switch, each and its way back (24 changes), on the " +
                        "dice with a face picked, the code entry with 4 symbols, the words' gate and the words page of insert " +
                        "2: each handled in place by the same MainActivity, still portrait, the state, what is held and every " +
                        "pad kept, FLAG_SECURE on its window; a recreation on each, a new MainActivity over the same model " +
                        "given no saved state; then the 50 rolls, the code's check and the page's word from what was kept; " +
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
     * The three changes on what, each to its other setting and back (six changes), each handled in place by
     * the activity with everything kept (change), then one recreation (recreated). Returns the activity the
     * recreation made.
     */
    private fun changes(activity: MainActivity, what: String, night: Boolean, fontScale: String): MainActivity {
        val begun = SystemClock.elapsedRealtime()
        val portrait = { c: Configuration -> c.orientation == Configuration.ORIENTATION_PORTRAIT }
        change(activity, "$what, a rotation to landscape asked", portrait) { device.setOrientationLeft() }
        val asked = shellText("settings get system user_rotation")
        change(activity, "$what, rotated back", portrait) { device.setOrientationNatural() }
        change(activity, "$what, font scale 1.3", scaled(1.3f)) { shellText("settings put system font_scale 1.3") }
        val back = if (fontScale == "null") "1.0" else fontScale
        change(activity, "$what, font scale back", scaled(back.toFloat())) { shellText("settings put system font_scale $back") }
        val other = if (night) "no" else "yes"
        change(activity, "$what, night mode $other", night(!night)) { shellText("cmd uimode night $other") }
        change(activity, "$what, night mode back", night(night)) { shellText("cmd uimode night " + if (night) "yes" else "no") }
        val recreated = recreated(activity, "$what, recreated")
        probe(
            "$what: six changes, each handled in place by the same activity with everything kept (user_rotation $asked " +
                "while landscape was asked, the activity portrait), then a recreation given " + onMain { recreated.createdWith } +
                ", in " + since(begun),
        )
        return recreated
    }

    /** A configuration whose font scale is scale. */
    private fun scaled(scale: Float): (Configuration) -> Boolean = { abs(it.fontScale - scale) < 0.01f }

    /** A configuration in night mode when on, in day mode otherwise. */
    private fun night(on: Boolean): (Configuration) -> Boolean =
        { (it.uiMode and Configuration.UI_MODE_NIGHT_MASK) == if (on) Configuration.UI_MODE_NIGHT_YES else Configuration.UI_MODE_NIGHT_NO }

    /**
     * One configuration change, made by apply after a touch in the screen's margin (Ui.touchMargin, an input),
     * handled in place: the activity's own configuration shows it (applied), the activity still portrait on its
     * display's natural rotation, resumed and never destroyed, no other MainActivity alive (in a stage but destroyed),
     * showing the same screen (or its gate) over the same model, with the model's state, what is held and the
     * pads' entries as they were (compared in-process, never printed), and FLAG_SECURE on its window.
     */
    private fun change(activity: MainActivity, what: String, applied: (Configuration) -> Boolean, apply: () -> Unit) {
        touchMargin(activity)
        val model = activity.model
        val before = onMain { model.state.value }
        val held = onMain { model.held.value }
        val pads = onMain { pads(activity) }
        apply()
        await("$what: the change reached the activity in place", 30) { onMain { applied(activity.resources.configuration) } }
        Capture.instrumentation.waitForIdleSync()
        assertTrue("$what: the activity was destroyed", onMain { !activity.isDestroyed })
        val stage = onMain { ActivityLifecycleMonitorRegistry.getInstance().getLifecycleStageOf(activity) }
        assertTrue("$what: the activity is not resumed but $stage", stage == Stage.RESUMED)
        val others = onMain {
            Stage.values().filter { it != Stage.DESTROYED }.sumOf { s ->
                ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(s).count { it is MainActivity && it !== activity }
            }
        }
        assertTrue("$what: $others other MainActivity instances alive: the change recreated the activity", others == 0)
        val upright = onMain {
            activity.resources.configuration.orientation == Configuration.ORIENTATION_PORTRAIT &&
                activity.display.rotation == Surface.ROTATION_0
        }
        assertTrue("$what: the activity is not portrait on its display's natural rotation", upright)
        assertTrue("$what: the activity has another model", onMain { activity.model } === model)
        on(activity, before.screen)
        assertTrue("$what: the model's state changed (neither is printed)", onMain { model.state.value } == before)
        assertTrue("$what: what is held changed", onMain { model.held.value } == held)
        assertTrue("$what: a pad's entry changed (neither is printed)", onMain { pads(activity) } == pads)
        val secure = onMain { activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0 }
        assertTrue("$what: the window is not FLAG_SECURE", secure)
    }

    /**
     * One recreation (Activity.recreate, as a change the manifest does not handle makes one) after a touch in the
     * screen's margin (Ui.touchMargin, an input): a new MainActivity, resumed, the old one destroyed, over the same
     * model, showing the same screen (or its gate), with the model's state, what is held and the pads' entries as
     * they were (compared in-process, never printed), FLAG_SECURE on its window, and no saved state in the Bundle
     * it was given. Returns the new activity.
     */
    private fun recreated(old: MainActivity, what: String): MainActivity {
        touchMargin(old)
        val model = old.model
        val before = onMain { model.state.value }
        val held = onMain { model.held.value }
        val pads = onMain { pads(old) }
        onMain { old.recreate() }
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
        // The Bundle the new activity was given is the one onSaveInstanceState left at the stop, which a process
        // death would keep: it must hold nothing (SecureActivity clears it), so no restore can bring back a screen.
        val given = onMain { activity.createdWith }
        assertTrue("$what: the recreated activity was given saved state: $given", !given.contains("holding"))
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
