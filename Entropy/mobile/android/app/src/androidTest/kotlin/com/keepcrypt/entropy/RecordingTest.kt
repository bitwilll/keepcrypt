package com.keepcrypt.entropy

import android.os.Build
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.uiautomator.By
import androidx.test.uiautomator.Until
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.launch
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Capture.probe
import com.keepcrypt.entropy.Capture.shellText
import com.keepcrypt.entropy.GateSeeds.DICE_50_ROLLS
import com.keepcrypt.entropy.Ui.await
import com.keepcrypt.entropy.Ui.device
import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Words
import com.keepcrypt.entropy.screens.Notice
import com.keepcrypt.entropy.screens.REDACTED_LINE
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.screens.screenId
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.regex.Pattern

/**
 * Android 15's screen-recording callback on a real recording (tasks/todo.md, M7 D4b), on the shipping app in
 * android-emulator.sh's registry part, made on API 36 (lead decision M7-11; on API 34, which has no such callback, it
 * only says so). The callback fires only for a MediaProjection (adb's screenrecord never fires it), so the test
 * starts SystemUI's own screen recorder, a MediaProjection of the whole screen, from its Quick Settings tile: no
 * recorder of our own, so no service or notification in any APK (rule 9's gate). The tile is put first in Quick
 * Settings for the test (the shell's settings command) and the tile list restored in a finally.
 * The recording starts before the app does, since leaving the app on a Protected screen discards the session and
 * Quick Settings may count as leaving. The app's words page, past the privacy gate, must then show the redacted
 * placeholder (REDACTED_LINE) and the model must hold the recording. Once the recording is stopped from its tile the
 * model must drop it and the placeholder go; Quick Settings over the app may stop the activity, so the page is
 * either back with the session kept or the session discarded at once (Home, notice Left; kc37 at API 37 does this).
 * Setup to the words goes through the model's entry points (an edge test, as AwayTest's). Only screen ids
 * and states are printed. The recording is stopped in a finally.
 */
@RunWith(AndroidJUnit4::class)
class RecordingTest {

    @Test
    fun aRecordingHidesTheWordsPageAndItsEndShowsItAgain() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.VANILLA_ICE_CREAM) {
            pass("the screen-recording callback is Android 15's; not made at API " + Build.VERSION.SDK_INT)
            return
        }
        val tiles = shellText("settings get secure $QS_TILES")
        try {
            recorderTileFirst(tiles)
            Capture.whileOffline {
                startRecorder()
                val activity = toWords()
                await("the model holds the recording", 20) { onMain { activity.model.state.value.recording } }
                val redacted = device.wait(Until.findObject(By.res("redacted")), 10_000)
                    ?: throw AssertionError("the words page did not show the redacted placeholder while recorded")
                assertTrue(
                    "the placeholder does not say REDACTED_LINE",
                    device.hasObject(By.text(REDACTED_LINE)),
                )
                probe("recording on: screen " + screenId(onMain { activity.model.state.value.screen }) + ", placeholder shown (" + redacted.resourceName + ")")
                stopRecorder()
                await("the model drops the recording once it ends", 20) { onMain { !activity.model.state.value.recording } }
                assertTrue(
                    "the placeholder stayed after the recording ended",
                    device.wait(Until.gone(By.res("redacted")), 10_000) == true,
                )
                // Quick Settings, opened over the app to stop the recording, may stop the activity: leaving a
                // Protected screen then discards the session at once (Home, notice Left), as the app's rule says.
                // Either outcome is right; any other is not.
                val state = onMain { activity.model.state.value }
                val kept = state.screen == Screen.Words && !state.gate
                val discarded = state.screen == Ui.discardedTo(offline = true) && state.notice == Notice.Left
                assertTrue(
                    "after the recording neither the words page nor a discard: screen " + screenId(state.screen) +
                        ", gate " + state.gate + ", overlay " + state.overlay + ", notice " + state.notice,
                    kept || discarded,
                )
                if (discarded) {
                    assertTrue("the slot is not at home: the session was not discarded", Core.selfTest() is Reply.Done)
                }
                pass(
                    "a real recording (MediaProjection, the whole screen): the words page redacted while recorded; once it ended, " +
                        if (kept) "the page shown again, the session kept" else "the session discarded (Quick Settings over the app left it), Home saying why",
                )
                finish(activity)
            }
        } finally {
            try {
                stopRecorder()
            } finally {
                restoreTiles(tiles)
            }
        }
    }

    /**
     * SystemUI's screen-record tile put first in Quick Settings for the test, the other tiles after it in their
     * order: on CI's API 36 image (AOSP's SystemUI) it is on the second page, and run 45016186578's swipe did not
     * turn the page (the tiles showed "Page 1 of 2"). An image whose SystemUI follows the setting shows the tile on
     * the first page; one that ignores it (kc37's) still has tapTile's paging. The shell may write the setting;
     * restoreTiles puts it back.
     */
    private fun recorderTileFirst(tiles: String) {
        val rest = if (tiles.isEmpty() || tiles == "null") emptyList() else tiles.split(",").filter { it != RECORD_SPEC }
        shellText("settings put secure $QS_TILES " + (listOf(RECORD_SPEC) + rest).joinToString(","))
        probe("recorder: the screen-record tile put first in Quick Settings (it was " + (if (tiles == "null" || tiles.isEmpty()) "the image's default list" else tiles) + ")")
        SystemClock.sleep(1_000)
    }

    /** The tile list as it was before the test (none set: the setting deleted, the image's default list again). */
    private fun restoreTiles(tiles: String) {
        if (tiles.isEmpty() || tiles == "null") shellText("settings delete secure $QS_TILES")
        else shellText("settings put secure $QS_TILES $tiles")
    }

    /**
     * SystemUI's own screen recorder started: its Quick Settings tile (on whichever page of the image's default
     * tiles holds it), then the dialog's Start (the whole screen, its default); a MediaProjection of SystemUI's must
     * then run.
     */
    private fun startRecorder() {
        tapTile()
        val start = device.wait(Until.findObject(By.text(START).clickable(true)), 10_000)
            ?: device.findObject(By.desc(START).clickable(true))
            ?: device.findObject(By.text(START))
            ?: device.findObject(By.desc(START))
            ?: throw AssertionError("the screen recorder's dialog did not show its Start; SystemUI shows: " + systemUiLabels())
        start.click()
        await("SystemUI's projection runs", 30) { recording() }
        shellText("cmd statusbar collapse")
        probe("recorder: SystemUI's screen recorder started from its tile, its projection running")
    }

    /** The recorder stopped from its tile (a running recording's tile ends it). */
    private fun stopRecorder() {
        if (recording()) {
            tapTile()
            await("SystemUI's projection ends", 30) { !recording() }
            shellText("cmd statusbar collapse")
        }
    }

    /**
     * Quick Settings opened and the screen-record tile pressed, found by its label or description on the first page
     * or, swiping the tiles to the left, on up to PAGES more.
     */
    private fun tapTile() {
        shellText("cmd statusbar expand-settings")
        SystemClock.sleep(1_000)
        for (page in 0..PAGES) {
            val tile = device.wait(Until.findObject(By.desc(TILE)), 3_000) ?: device.findObject(By.text(TILE))
            if (tile != null) {
                tile.click()
                return
            }
            val w = device.displayWidth
            val h = device.displayHeight
            device.swipe(w * 4 / 5, h * 2 / 5, w / 5, h * 2 / 5, 20)
            SystemClock.sleep(1_000)
        }
        throw AssertionError("Quick Settings showed no screen-record tile on " + (PAGES + 1) + " pages; SystemUI shows: " + systemUiLabels())
    }

    /** Every text and description SystemUI's windows show (the window hierarchy's), for a tile that is not found. */
    private fun systemUiLabels(): String {
        val out = java.io.ByteArrayOutputStream()
        device.dumpWindowHierarchy(out)
        val label = Regex("(?:text|content-desc)=\"([^\"]+)\"")
        return Regex("<node [^>]*>").findAll(out.toString("UTF-8")).map { it.value }
            .filter { it.contains("package=\"$SYSTEMUI\"") }
            .flatMap { node -> label.findAll(node).map { it.groupValues[1] } }
            .distinct().take(60).joinToString(" | ")
    }

    private fun recording(): Boolean = shellText("dumpsys media_projection").contains(SYSTEMUI)

    /** A new MainActivity through First launch and Go offline to the words of dice-50-words12, its gate passed, through the model. */
    private fun toWords(): MainActivity {
        val activity = launch()
        await("First launch", 10) { onMain { activity.shownScreen } == Screen.FirstLaunch }
        onMain { activity.model.firstLaunchDone() }
        await("Go offline: the start-up self-test passed", Ui.START_SECONDS) { onMain { activity.shownScreen } == Screen.GoOffline }
        await("the app reads airplane mode on and Wi-Fi off", 30) { onMain { activity.model.state.value.offline } }
        onMain {
            activity.model.startOffline()
            activity.model.chooseMode(Mode.DiceOnly)
            activity.model.chooseLength(Words.Twelve)
        }
        await("the dice", Ui.START_SECONDS) { onMain { activity.model.state.value.screen } == Screen.Dice }
        onMain {
            for (roll in DICE_50_ROLLS.repeat(9).take(50)) {
                activity.model.dicePick.replace(roll)
                activity.model.confirmRoll()
            }
            activity.model.diceDone()
        }
        await("the check prompt", Ui.START_SECONDS) { onMain { activity.model.state.value.screen } == Screen.CheckPrompt }
        onMain {
            activity.model.skip()
            activity.model.skipConfirmed()
            activity.model.showWords()
            activity.model.passGate()
        }
        await("the words page past its gate", 10) { onMain { activity.model.state.value.let { it.screen == Screen.Words && !it.gate } } }
        return activity
    }

    private companion object {
        const val SYSTEMUI = "com.android.systemui"

        /** The secure setting holding Quick Settings' tile list, and the screen recorder's tile in it. */
        const val QS_TILES = "sysui_qs_tiles"
        const val RECORD_SPEC = "screenrecord"

        /** The Quick Settings pages past the first that are searched for the tile. */
        const val PAGES = 3

        /** The screen recorder's tile, by its label. */
        val TILE: Pattern = Pattern.compile("(?i)screen record.*")

        /** The system dialog's button: "Start" or "Start recording" from Android 14, "Start now" before. */
        val START: Pattern = Pattern.compile("(?i)start( now| recording)?")
    }
}
