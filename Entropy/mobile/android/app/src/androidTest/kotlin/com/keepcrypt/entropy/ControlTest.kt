package com.keepcrypt.entropy

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.uiautomator.UiDevice
import com.keepcrypt.entropy.Capture.CONTROL_PACKAGE
import com.keepcrypt.entropy.Capture.CONTROL_WORDS
import com.keepcrypt.entropy.Capture.KNOWN_MIN
import com.keepcrypt.entropy.Capture.KNOWN_MIN_RECENTS
import com.keepcrypt.entropy.Capture.display
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.knownPixels
import com.keepcrypt.entropy.Capture.launch
import com.keepcrypt.entropy.Capture.litPixels
import com.keepcrypt.entropy.Capture.openRecents
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Capture.probe
import com.keepcrypt.entropy.Capture.proveDrawn
import com.keepcrypt.entropy.Capture.region
import com.keepcrypt.entropy.Capture.screencap
import com.keepcrypt.entropy.Capture.screenshot
import com.keepcrypt.entropy.Capture.startControl
import com.keepcrypt.entropy.Capture.windows
import com.keepcrypt.entropy.Capture.wordsPageSecrets
import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Words
import com.keepcrypt.entropy.screens.SECRET_TAG
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.screens.faceSixText
import com.keepcrypt.entropy.screens.insertHeader
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Positive control (a) (tasks/todo.md, M5 group 6): capture-control draws the app's first screen with
 * the same composable and no FLAG_SECURE, so the captures CaptureTest finds black must find its known
 * pixels here, through the same calls, and lit pixels over the very region (the app's window, from
 * Capture.region) whose lit-pixel count CaptureTest asserts is 0; a missing control fails the job.
 * The window parser must also tell its window apart (no SECURE). It draws dice-99-words12's first
 * words page the same way (lead decision M5-68 (f)), and the same captures must find its pixels too,
 * the words' own among them. Run once per emulator, before CaptureTest (the positive control first);
 * scripts/android-emulator.sh then clears capture-control's data (pm clear), which takes its tasks out
 * of recents, so its thumbnail is not beside the app's in CaptureTest's recents view. The raw-frame
 * half of the control, both screens, is scripts/android-emulator.sh's, which also keeps the shell's
 * screencap of each for the owner's screen review.
 */
@RunWith(AndroidJUnit4::class)
class ControlTest {
    @Test
    fun theSameCapturesShowTheControlsScreen() {
        // The region CaptureTest's black assertions read: the app's window, its first screen drawn.
        val app = launch()
        proveDrawn(app, Screen.FirstLaunch)
        val region = region(app)
        val display = display(app)
        finish(app)
        startControl()
        val cap = screencap()
        val shot = screenshot()
        Capture.assertCaptureSize(cap, display, "screencap")
        Capture.assertCaptureSize(shot, display, "takeScreenshot")
        val inCap = knownPixels(cap)
        val inShot = knownPixels(shot)
        val capLit = litPixels(cap, region)
        val shotLit = litPixels(shot, region)
        val found = windows(CONTROL_PACKAGE)
        probe(
            "capture control: $inCap known-colour pixels in screencap, $inShot in takeScreenshot; $capLit and $shotLit lit " +
                "pixels over the app's window $region; ${found.size} window(s), ${found.count { it.secure }} with SECURE",
        )
        assertTrue("screencap does not show the capture control's screen", inCap >= KNOWN_MIN)
        assertTrue("takeScreenshot does not show the capture control's screen", inShot >= KNOWN_MIN)
        assertTrue("screencap has no lit pixel over the app's window region", capLit > 0)
        assertTrue("takeScreenshot has no lit pixel over the app's window region", shotLit > 0)
        assertTrue("dumpsys window windows lists no window of the capture control", found.isNotEmpty())
        assertTrue("no window's owner line names the capture control", found.any { it.byOwner })
        for (w in found) assertTrue("the capture control's window has SECURE: " + w.title, !w.secure)
        pass("control (a): screencap and takeScreenshot show the capture control's screen, lit over the app's window region; its windows lack SECURE")
        UiDevice.getInstance(Capture.instrumentation).pressHome()
    }

    /**
     * In the recents view, proven on screen (Capture.openRecents), the control's thumbnail shows its
     * known colour, and fewer such pixels than its whole screen showed just before: a scaled
     * thumbnail, not the live window left in front.
     */
    @Test
    fun theRecentsThumbnailShowsTheControlsScreen() {
        startControl()
        val full = knownPixels(screencap())
        val device = UiDevice.getInstance(Capture.instrumentation)
        openRecents(device)
        val inCap = knownPixels(screencap())
        device.pressHome()
        probe("capture control in recents: $inCap known-colour pixels in screencap, $full on its whole screen before")
        assertTrue("screencap does not show the capture control's screen", full >= KNOWN_MIN)
        assertTrue("the recents view does not show the capture control's screen", inCap >= KNOWN_MIN_RECENTS)
        assertTrue("the recents view shows the control's whole screen, not a thumbnail", inCap * 10 < full * 9)
        pass("control (a): the recents thumbnail shows the capture control's screen")
    }

    /**
     * Control (a) on the words page: capture-control's WordsActivity draws dice-99-words12's first words
     * page with the app's words composable (WordsInsert) and no FLAG_SECURE, under the TEST REGISTRY
     * strip, as the test-registry APK draws it. It is the gate seed's page: the secret texts its nodes
     * draw (read in-process, Capture.nodes, with no selector) are exactly those of core's first page for
     * the seed's rolls, made here through Core (dice99FirstPage), and its header and face 6 line are
     * core's too; none of them is printed. Then the same screencap and takeScreenshot that CaptureTest
     * finds black over the app's words page show its known colour (the strip's) and lit pixels inside
     * every node that draws one of those texts, so the words' own drawing is in each capture; its
     * windows lack SECURE.
     */
    @Test
    fun theSameCapturesShowTheControlsWordsPage() {
        val core = dice99FirstPage()
        startControl(CONTROL_WORDS)
        val nodes = Capture.nodes(CONTROL_PACKAGE)
        val secret = nodes.filter { it.resourceName == SECRET_TAG && !it.text.isNullOrBlank() }
        assertTrue(
            "the control's words page does not draw the secret texts of core's first page of dice-99-words12 (none is printed)",
            secret.map { it.text }.toSet() == core.secrets,
        )
        assertTrue("its header is not core's page's", nodes.any { it.resourceName == "insert_header" && it.text == core.header })
        assertTrue("its face 6 line is not core's page's", nodes.any { it.resourceName == "face_six" && it.text == core.faceSix })
        assertTrue("a node drawing a secret text lies off screen", secret.all { it.visible })
        val cap = screencap()
        val shot = screenshot()
        val inCap = knownPixels(cap)
        val inShot = knownPixels(shot)
        val capUnlit = secret.count { litPixels(cap, it.bounds) == 0 }
        val shotUnlit = secret.count { litPixels(shot, it.bounds) == 0 }
        val found = windows(CONTROL_PACKAGE)
        probe(
            "capture control's words page: $inCap known-colour pixels in screencap, $inShot in takeScreenshot; " +
                "${secret.size} nodes draw its secret texts, $capUnlit and $shotUnlit of them unlit; " +
                "${found.size} window(s), ${found.count { it.secure }} with SECURE",
        )
        assertTrue("screencap does not show the capture control's words page", inCap >= KNOWN_MIN)
        assertTrue("takeScreenshot does not show the capture control's words page", inShot >= KNOWN_MIN)
        assertTrue("screencap has a node of the words with no lit pixel", capUnlit == 0)
        assertTrue("takeScreenshot has a node of the words with no lit pixel", shotUnlit == 0)
        assertTrue("dumpsys window windows lists no window of the capture control", found.isNotEmpty())
        assertTrue("no window's owner line names the capture control", found.any { it.byOwner })
        for (w in found) assertTrue("the capture control's window has SECURE: " + w.title, !w.secure)
        pass(
            "control (a), words page: dice-99-words12's first page as core gives it; screencap and takeScreenshot show it, " +
                "lit in each of its ${secret.size} nodes of the words; its windows lack SECURE",
        )
        UiDevice.getInstance(Capture.instrumentation).pressHome()
    }

    /** The texts core's first page of dice-99-words12 draws: its secret texts, its header and its face 6 line. */
    private class CorePage(val secrets: Set<String>, val header: String, val faceSix: String)

    /**
     * dice-99-words12's first page through Core on this thread, as NativeTest drives a ceremony: a
     * dice-only 12-word seed of the vector's 99 rolls, sealed and its check skipped, then word page 1,
     * whose texts are taken as the words page draws them; the page is wiped and the slot left empty.
     */
    private fun dice99FirstPage(): CorePage {
        assertTrue("start", Core.start(Words.Twelve, Mode.DiceOnly) is Reply.Done)
        assertTrue("commit", Core.commit() is Reply.Done)
        assertTrue("start_dice", Core.startDice() is Reply.Done)
        for (index in 0 until DICE_99_COUNT) {
            assertTrue("a roll", Core.pushRoll(DICE_99_ROLLS[index % DICE_99_ROLLS.length] - '0') is Reply.Done)
        }
        assertTrue("finish", Core.finish() is Reply.Done)
        assertTrue("skip_check", Core.skipCheck() is Reply.Done)
        val reply = Core.wordPage(1)
        assertTrue("word_page 1", reply is Reply.Done)
        val page = (reply as Reply.Done).value
        val texts = CorePage(wordsPageSecrets(page), insertHeader(page), faceSixText(page.sequence))
        page.wipe()
        assertTrue("wipe_all", Core.wipeAll() is Reply.Done)
        return texts
    }

    private companion object {
        /** vectors/kcr.json's dice-99-words12: 99 rolls, 654321 repeated. */
        const val DICE_99_ROLLS = "654321"
        const val DICE_99_COUNT = 99
    }
}
