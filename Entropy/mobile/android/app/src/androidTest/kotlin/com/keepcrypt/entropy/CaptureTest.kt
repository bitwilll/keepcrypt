package com.keepcrypt.entropy

import android.os.Build
import android.os.SystemClock
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import com.keepcrypt.entropy.Capture.KNOWN_MIN
import com.keepcrypt.entropy.Capture.KNOWN_MIN_RECENTS
import com.keepcrypt.entropy.Capture.PERMISSION_PROMPT
import com.keepcrypt.entropy.Capture.PROMPT_DENY
import com.keepcrypt.entropy.Capture.SETTLE_MS
import com.keepcrypt.entropy.Capture.display
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.launch
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.openRecents
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Capture.probe
import com.keepcrypt.entropy.Capture.proveDrawn
import com.keepcrypt.entropy.Capture.region
import com.keepcrypt.entropy.Capture.report
import com.keepcrypt.entropy.Capture.screencap
import com.keepcrypt.entropy.Capture.screenshot
import com.keepcrypt.entropy.Capture.shell
import com.keepcrypt.entropy.Capture.shellText
import com.keepcrypt.entropy.Capture.waitUntil
import com.keepcrypt.entropy.Capture.windows
import com.keepcrypt.entropy.Capture.wordOf
import com.keepcrypt.entropy.Capture.wordsPageSecrets
import com.keepcrypt.entropy.ffi.KcHalt
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Words
import com.keepcrypt.entropy.screens.CeremonyModel
import com.keepcrypt.entropy.screens.DICE_KEYS
import com.keepcrypt.entropy.screens.DocumentPickers
import com.keepcrypt.entropy.screens.DocumentPlace
import com.keepcrypt.entropy.screens.INSERTS_PER_DEVICE
import com.keepcrypt.entropy.screens.Overlay
import com.keepcrypt.entropy.screens.PASSPHRASE_WORDS
import com.keepcrypt.entropy.screens.PickedFile
import com.keepcrypt.entropy.screens.SECRET_TAG
import com.keepcrypt.entropy.screens.ScanStop
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.screens.choiceText
import com.keepcrypt.entropy.screens.isProtected
import com.keepcrypt.entropy.screens.overviewLine
import com.keepcrypt.entropy.screens.passphraseLines
import com.keepcrypt.entropy.screens.screenId
import com.keepcrypt.entropy.screens.seedbookText
import com.keepcrypt.entropy.screens.typedFaces
import com.keepcrypt.entropy.screens.verdictLine
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The capture harness on the app (tasks/todo.md, M5 group 6; gate item 1), run once per app APK by
 * scripts/android-instrument.sh. Every capture of the app comes after the drawn-screen proof, so a
 * black capture means the screen was protected, not that it was never drawn. The positive control
 * (a), the same captures finding capture-control's pixels, is ControlTest, which runs before this
 * class; scripts/android-emulator.sh then clears capture-control's data (pm clear), which takes its
 * tasks out of the recents list, so that none of them is in the recents view here.
 */
@RunWith(AndroidJUnit4::class)
class CaptureTest {
    private val pkg get() = Capture.instrumentation.targetContext.packageName

    /** Holds the long call that keeps the self-test's screen up for its captures; released after them. */
    private val selfTest = CountDownLatch(1)

    /** Holds the long call that keeps "Working..." up for its captures; released after them. */
    private val working = CountDownLatch(1)

    /** The one activity the every-screen pass walks, from First launch to the stop screen. */
    private var walk: MainActivity? = null

    /**
     * The walk's backup passphrase, its words as the passphrase's pages showed them, read in-process from
     * the state's Secrets (compared and typed, never printed, never in a selector), zeroed after the walk.
     */
    private val passphrase = ArrayList<ByteArray>(PASSPHRASE_WORDS)

    /** The walk's backup file, as the save screen's place took it (in memory: the walk saves to no provider), for Check a backup. */
    private var savedBackup: ByteArray? = null

    private val device: UiDevice get() = UiDevice.getInstance(Capture.instrumentation)

    /**
     * Brings screen up in the walk's one activity, from the screen before it in Screen's order (the
     * ceremony's, lead decision M5-50, its collision check in the order one walk reaches its screens),
     * through the model's entry points as the screens call them. The when is exhaustive: a new screen
     * without a way here fails to compile, and one out of order finds the model on another screen, which
     * ignores the press, so its drawn-screen proof times out. The self-test's screen and "Working..." are
     * long calls held on the worker, as the model makes every long call (the real start-up self-test is
     * over before a capture could start): the held one goes back to First launch when let go, whose
     * Continue then runs the real self-test to Go offline. The dice's Done and the restart are the real
     * long calls, waited for. The ceremony is a 24-word one (99 rolls, and the restart's the same), so the
     * words' pages pass the device swap. Each Protected screen (the collision-report QR, the words, their
     * overview, the read-back entry and its mismatch) is shown past its privacy gate, so the capture is of
     * the screen itself: the words from Skip's result, the overview from word 1, the swap after the
     * overview's third page, the entry from the last insert, its mismatch from letters no word begins
     * with ("zzzz"), and the read-back's end after every insert read back in-process from the page on
     * show (its word's copy wiped), the first from the entry the walk left matched (matchedEntry), then
     * the wallet summary; the encrypted backup (group 18): its offer, the passphrase past its privacy
     * gate (its pages read in-process), its confirm (each answer typed on the model's letter pad), the
     * save screen once core has encrypted (the encryption's real long call, waited for), and also with a
     * failed write (failedSave), then "Backup verified" after a place in memory took the file and core
     * verified it (the real long call); the checklist, whose Finish leads Home, and Check a backup on the
     * saved file handed to the model as the picker would (the system's pickers are BackupTest's): its
     * entry past its gate, its result once core opened the file with the passphrase typed in-process
     * (the real long call), and the re-check QR; then the checked backup's words past their gate
     * (checkedWords), from which "Working..." is held. The scan screen asks for
     * the camera as it opens, and the
     * walk is the first of this APK's tests to open it: dumpsys package shows CAMERA requested and not
     * granted, no permission prompt is up, then the scan screen opens and the system's prompt shows over
     * the app, another package's window, which the walk answers "Don't allow" before the capture (the
     * scan screen then says the camera was refused, and its "Type go-ahead code" leads on). The stop
     * screen is the halt status as Core throws it, so this process's slot stays live for the tests after
     * it (the model's own tests halt a real one). Home on needs the phone offline, which the pass sees to.
     */
    private fun show(screen: Screen): MainActivity {
        val activity = if (screen == Screen.FirstLaunch) started().also { walk = it } else checkNotNull(walk)
        val model = activity.model
        when (screen) {
            Screen.FirstLaunch -> {}
            Screen.SelfTest -> onMain { model.work({ selfTest.await(); Reply.Done(Unit) }, busy = Screen.SelfTest) {} }
            Screen.GoOffline -> {
                selfTest.countDown()
                waitUntil("First launch again, after the held call") { onMain { activity.shownScreen } == Screen.FirstLaunch }
                onMain { model.firstLaunchDone() }
                waitUntil("the start-up self-test passed", START_SECONDS) { onMain { activity.shownScreen } == Screen.GoOffline }
            }
            Screen.Home -> onMain { model.startOffline() }
            Screen.Length -> onMain { model.chooseMode(Mode.Mixed) }
            Screen.DeviceEntropy -> onMain { model.chooseLength(Words.TwentyFour) }
            Screen.Commitment -> onMain { model.deviceEntropyDone() }
            Screen.Dice -> onMain { model.commitmentDone() }
            Screen.CheckPrompt -> finishDice(activity, 99)
            Screen.SkipConfirm -> onMain { model.skip() }
            Screen.SealCard -> onMain {
                model.back()
                model.checkNow()
            }
            Screen.Scan -> askedOnTheScanScreen(activity)
            Screen.CodeEntry -> onMain { model.typeCode() }
            Screen.MatchFoundConfirm -> onMain {
                model.back()
                model.matchFound()
            }
            Screen.CannotCheckConfirm -> onMain {
                model.back()
                model.cannotCheck()
            }
            Screen.Collision -> onMain {
                model.back()
                model.matchFound()
                model.matchFoundConfirmed()
            }
            Screen.CollisionReport -> {
                onMain { model.showReport() }
                waitUntil("the report's privacy gate") { onMain { activity.shownScreen == Screen.CollisionReport && model.state.value.gate } }
                onMain { model.passGate() }
            }
            Screen.CheckResult -> {
                onMain { model.addFreshEntropy() }
                waitUntil("Add fresh entropy's new ceremony", START_SECONDS) { onMain { activity.shownScreen } == Screen.DeviceEntropy }
                onMain {
                    model.deviceEntropyDone()
                    model.commitmentDone()
                }
                finishDice(activity, 99)
                onMain {
                    model.skip()
                    model.skipConfirmed()
                }
            }
            Screen.Words -> {
                onMain { model.showWords() }
                waitUntil("the words' privacy gate") { onMain { activity.shownScreen == Screen.Words && model.state.value.gate } }
                onMain { model.passGate() }
            }
            Screen.WordsOverview -> onMain { model.toOverview() }
            Screen.DeviceSwap -> onMain { repeat(3) { model.nextPage() } }
            Screen.ReadbackEntry -> onMain {
                model.swapDone()
                model.passGate()
                model.toInsertView()
                repeat(INSERTS_PER_DEVICE - 1) { model.nextPage() }
                model.startReadback()
            }
            Screen.ReadbackMismatch -> onMain {
                for (letter in "zzzz") model.readbackLetters.type(letter)
                model.readbackTyped()
            }
            Screen.ReadbackDone -> onMain {
                model.readbackNext()
                repeat(2 * INSERTS_PER_DEVICE - 1) {
                    readBackShown(model)
                    model.readbackNext()
                }
            }
            Screen.Wallet -> onMain { model.showSummary() }
            Screen.BackupOffer -> onMain { model.summaryDone() }
            Screen.BackupPassphrase -> {
                onMain { model.makeBackup() }
                waitUntil("the passphrase's privacy gate") { onMain { activity.shownScreen == Screen.BackupPassphrase && model.state.value.gate } }
                onMain {
                    model.passGate()
                    readPassphrasePage(model)
                }
            }
            Screen.BackupConfirm -> onMain {
                model.nextPage()
                readPassphrasePage(model)
                model.passphraseWritten()
            }
            Screen.BackupSave -> {
                onMain {
                    answer(model)
                    answer(model)
                }
                waitUntil("the save screen, after the encryption", START_SECONDS) { onMain { activity.shownScreen } == Screen.BackupSave }
            }
            Screen.BackupVerified -> {
                onMain {
                    model.saveBackup(NoPickers)
                    model.backupPlaced(InMemory())
                }
                waitUntil("Backup verified, after core verified the file", START_SECONDS) { onMain { activity.shownScreen } == Screen.BackupVerified }
            }
            Screen.Checklist -> onMain { model.backupVerifiedDone() }
            Screen.BackupCheckEntry -> {
                onMain {
                    model.finishCeremony()
                    model.checkBackup(NoPickers)
                    model.backupPicked(Picked(checkNotNull(savedBackup)))
                }
                waitUntil("the entry's privacy gate") { onMain { activity.shownScreen == Screen.BackupCheckEntry && model.state.value.gate } }
                onMain { model.passGate() }
            }
            Screen.BackupCheckResult -> {
                onMain {
                    for (word in passphrase) {
                        for (index in 0 until minOf(4, word.size)) model.backupLetters.type(Char(word[index].toInt()))
                        model.entryTyped()
                    }
                }
                waitUntil("the result, after core opened the backup", START_SECONDS) { onMain { activity.shownScreen } == Screen.BackupCheckResult }
            }
            Screen.BackupRecheck -> onMain { model.showRecheck() }
            Screen.Working -> onMain { model.work({ working.await(); Reply.Done(Unit) }) {} }
            Screen.Stop -> {
                working.countDown()
                waitUntil("the checked backup's words again, after the held call") { onMain { activity.shownScreen } == Screen.Words }
                onMain { model.work<Unit>({ throw KcHalt() }) {} }
            }
        }
        return activity
    }

    /** The passphrase's page on show read into passphrase, its words copied from the state's Secret (never a String). Main thread only. */
    private fun readPassphrasePage(model: CeremonyModel) {
        val text = checkNotNull(model.state.value.passphrase)
        var start = 0
        for (index in 0..text.size) {
            if (index == text.size || text[index] == SPACE) {
                passphrase.add(ByteArray(index - start) { text[start + it] })
                start = index + 1
            }
        }
    }

    /** The confirm's question on show answered on the model's letter pad: its word's first four letters (or three), then Done. Main thread only. */
    private fun answer(model: CeremonyModel) {
        val state = model.state.value
        val word = passphrase[checkNotNull(state.challenge).questions[state.page].position - 1]
        for (index in 0 until minOf(4, word.size)) model.backupLetters.type(Char(word[index].toInt()))
        model.confirmTyped()
    }

    /**
     * The save screen once more, with a failed write: a place whose write fails, so the screen names
     * that step and offers Save again (the session stays). The walk checks it as it checks each screen,
     * before "Backup verified".
     */
    private fun failedSave(): MainActivity {
        val activity = checkNotNull(walk)
        val failed = onMain {
            activity.model.saveBackup(NoPickers)
            activity.model.backupPlaced(FailingPlace)
            activity.model.state.value.let { it.screen == Screen.BackupSave && it.saveFailure != null }
        }
        assertTrue("the save screen does not name the failed write", failed)
        return activity
    }

    /**
     * The checked backup's words, from the re-check QR: its Back to the result, "Show the words" and the
     * privacy gate, so insert 1 of the backup's words shows (opened in the state). The walk checks it as
     * it checks each screen, before "Working..." is held from it.
     */
    private fun checkedWords(): MainActivity {
        val activity = checkNotNull(walk)
        onMain {
            activity.model.back()
            activity.model.showBackupWords()
        }
        waitUntil("the checked backup's words' privacy gate") {
            onMain { activity.shownScreen == Screen.Words && activity.model.state.value.gate }
        }
        val shown = onMain {
            activity.model.passGate()
            activity.model.state.value.let { it.screen == Screen.Words && it.opened != null && !it.gate }
        }
        assertTrue("the checked backup's words are not on show", shown)
        return activity
    }

    /** The walk's pickers: the model opens nothing, and the walk hands it the place and the file as the pickers would. */
    private object NoPickers : DocumentPickers {
        override fun create(name: String) {}

        override fun open() {}
    }

    /** The save screen's place, in memory: it keeps what it is given for Check a backup, and reads it back. */
    private inner class InMemory : DocumentPlace {
        override fun write(bytes: ByteArray): Boolean {
            savedBackup = bytes.copyOf()
            return true
        }

        override fun readBack(limit: Int): ByteArray? = savedBackup?.copyOf()
    }

    /** A place whose write fails. */
    private object FailingPlace : DocumentPlace {
        override fun write(bytes: ByteArray): Boolean = false

        override fun readBack(limit: Int): ByteArray? = null
    }

    /** The walk's saved backup as the open-document picker gives a file: core's kind of name and its size. */
    private class Picked(private val bytes: ByteArray) : PickedFile {
        override val name: String = "keepcrypt-backup-00000000.age"
        override val size: Long = bytes.size.toLong()

        override fun read(limit: Int): ByteArray = bytes.copyOf()
    }

    /**
     * From the seal card, the scan screen and its camera prompt (M5 group 16): CAMERA requested and not
     * granted before it (dumpsys package) and no prompt up; once it opens, the system's prompt, whose
     * "Don't allow" the walk presses once (Capture.denyPrompt, which waits for the prompt to go), then
     * the refusal reaching the scan screen, and CAMERA still not granted.
     */
    private fun askedOnTheScanScreen(activity: MainActivity) {
        val before = Capture.permission(pkg, CAMERA)
        probe(
            "CAMERA before the scan screen (dumpsys package): requested ${before.requested}, granted ${before.granted}; " +
                before.state,
        )
        assertTrue("CAMERA is not among the app's requested permissions", before.requested)
        assertFalse("CAMERA is granted before the scan screen", before.granted)
        assertFalse("a permission prompt is up before the scan screen", device.hasObject(PERMISSION_PROMPT))
        onMain { activity.model.scanQr() }
        val deny = device.wait(Until.findObject(PROMPT_DENY), 10_000)
            ?: throw AssertionError("no camera prompt (the permission controller's Don't allow) when the scan screen opened")
        pass(
            "the camera prompt showed as the scan screen opened and on no screen before it; CAMERA requested and not " +
                "granted before it (dumpsys package)",
        )
        Capture.denyPrompt(device, deny)
        waitUntil("the prompt went but no refusal reached the scan screen") { onMain { activity.model.state.value.scanStop } == ScanStop.Refused }
        assertFalse("CAMERA granted after Don't allow", Capture.permission(pkg, CAMERA).granted)
    }

    /**
     * On the read-back entry, the insert on show read back in-process: its word's first four letters (a
     * three-letter word's three), read from the page the state holds into the model's letter pad through
     * a copy that is wiped at once, then Done, which leaves the entry matched. Main thread only.
     */
    private fun readBackShown(model: CeremonyModel) {
        val insert = checkNotNull(model.state.value.insert)
        val word = insert.word()
        for (index in 0 until minOf(4, word.size)) model.readbackLetters.type(Char(word[index].toInt()))
        word.wipe()
        model.readbackTyped()
    }

    /**
     * The read-back entry once more, from the mismatch: Read it again, then the insert read back
     * (readBackShown), so the entry shows its match, where ReadbackEntry draws the whole word
     * (InsertWord). The walk checks it as it checks each screen, before the read-back's end.
     */
    private fun matchedEntry(): MainActivity {
        val activity = checkNotNull(walk)
        val matched = onMain {
            activity.model.readbackAgain()
            readBackShown(activity.model)
            activity.model.state.value.let { it.screen == Screen.ReadbackEntry && it.matched }
        }
        assertTrue("the read-back entry did not match the insert read back", matched)
        return activity
    }

    /** On the dice, rolls faces through the model's pick and confirm, then Done, and waits for the check prompt (the real finish). */
    private fun finishDice(activity: MainActivity, rolls: Int) {
        onMain {
            for (index in 0 until rolls) {
                activity.model.dicePick.replace(DICE_KEYS[index % DICE_KEYS.length])
                activity.model.confirmRoll()
            }
            activity.model.diceDone()
        }
        waitUntil("the check prompt after the dice's Done", START_SECONDS) { onMain { activity.shownScreen } == Screen.CheckPrompt }
    }

    /** A new MainActivity on its first screen, First launch, which shows before any core call. */
    private fun started(): MainActivity {
        val activity = launch()
        waitUntil("the first screen") { onMain { activity.shownScreen } == Screen.FirstLaunch }
        return activity
    }

    /**
     * For every screen id, in one activity walked through the ceremony with the phone offline (groups
     * 15-17): drawn, with no permission prompt over it (the scan screen's is answered first, and none
     * comes before it), then black over the app's window in the shell's screencap and in
     * UiAutomation.takeScreenshot(), FLAG_SECURE in the window's own flags, the root view opted out of
     * content capture (read back in-process, group 14), SECURE on every window of the package in
     * dumpsys window windows, found by its owner line too (the owner line is shown to be read on this
     * image: some window is found by it), and its secret text marked data sensitive where Android has
     * the mark (assertSecretsMarked); the read-back entry also in its matched state (matchedEntry), the
     * save screen also with a failed write (failedSave) and the words also as a checked backup's
     * (checkedWords). After the walk the log holds none of its secret lines (assertNoSecretInTheLog).
     */
    @Test
    fun everyScreenIsDrawnAndThenBlackInEveryCapture() {
        Capture.whileOffline { walkEveryScreen() }
    }

    private fun walkEveryScreen() {
        val lines = HashSet<String>()
        var mark = ""
        for (screen in Screen.entries) {
            // From the words on, the walk holds secret texts. As they come, a line of the walk's own goes
            // to the log, through the shell's log, to the main buffer, where UI Automator's lines go too: a
            // log that still holds it after the walk has dropped nothing written since, so the search after
            // the walk reads every line written while the walk held a secret.
            if (screen == Screen.Words) {
                mark = "kc_capture_walk_" + SystemClock.elapsedRealtimeNanos()
                shell("log -t KcCaptureTest " + mark)
            }
            if (screen == Screen.ReadbackDone) {
                checkScreen(Screen.ReadbackEntry, matchedEntry(), screenId(Screen.ReadbackEntry) + " (matched)", lines)
            }
            if (screen == Screen.BackupVerified) {
                checkScreen(Screen.BackupSave, failedSave(), screenId(Screen.BackupSave) + " (a failed write)", lines)
            }
            if (screen == Screen.Working) {
                checkScreen(Screen.Words, checkedWords(), screenId(Screen.Words) + " (a checked backup's)", lines)
            }
            checkScreen(screen, show(screen), screenId(screen), lines)
        }
        finish(checkNotNull(walk))
        for (word in passphrase) word.fill(0)
        savedBackup?.fill(0)
        assertNoSecretInTheLog(mark, lines)
    }

    /** One screen of the walk, named name in its lines, its secret lines added to lines (see walkEveryScreen). */
    private fun checkScreen(screen: Screen, activity: MainActivity, name: String, lines: MutableSet<String>) {
        proveDrawn(activity, screen)
        assertFalse("a permission prompt over " + name, device.hasObject(PERMISSION_PROMPT))
        val region = region(activity)
        val display = display(activity)
        report("kc_region", "${region.left},${region.top},${region.right},${region.bottom}")
        report("kc_display", "${display.width()}x${display.height()}")
        val cap = Capture.screencapOrRefused()
        val shot = Capture.screenshotOrRefused()
        if (cap != null) Capture.assertCaptureSize(cap, display, "screencap")
        if (shot != null) Capture.assertCaptureSize(shot, display, "takeScreenshot")
        val capLit = Capture.litOrRefused(cap, region)
        val shotLit = Capture.litOrRefused(shot, region)
        val flagged = onMain { activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0 }
        val contentCapture = onMain { activity.window.decorView.importantForContentCapture }
        val found = windows(pkg)
        probe("screencap -p: ${Capture.described(cap)}; takeScreenshot(): ${Capture.described(shot)}")
        probe("$name: $capLit lit pixels in screencap, $shotLit in takeScreenshot over the app's window $region")
        assertEquals("lit pixels in screencap over the app's window", 0, capLit)
        assertEquals("lit pixels in takeScreenshot over the app's window", 0, shotLit)
        assertTrue("the window's flags lack FLAG_SECURE", flagged)
        assertEquals(
            "the root view does not opt out of content capture",
            View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS, contentCapture,
        )
        assertTrue("dumpsys window windows lists no window of the app", found.isNotEmpty())
        assertTrue("no window's owner line names the app: windows are found by title alone", found.any { it.byOwner })
        probe("windows of the app: " + found.joinToString("; ") { "${it.title} (by owner ${it.byOwner}, SECURE ${it.secure})" })
        for (w in found) assertTrue("a window without SECURE: " + w.title, w.secure)
        assertSecretsMarked(screen, activity.model, name, lines)
        pass(
            "$name: drawn, then screencap and takeScreenshot black over the app's window; " +
                "SECURE on all ${found.size} of its windows; no content capture",
        )
    }

    /**
     * The secret text a screen draws is marked accessibility-data sensitive (docs/mobile-apps.md, "Rules
     * for Claude Code"; group 6's probe, where it applies): every node tagged SECRET_TAG (Kit.kt's secret(),
     * which every node that shows a secret takes) must be data sensitive as UiAutomation reads it on
     * Android 14+, the screens that show the words or their letters must hold such nodes, every node
     * there whose text is one of the screen's secrets must be one of them and each secret must be drawn
     * (assertSecretTextsTagged), and a Public screen holds none. Before Android 14 a probe line says the
     * mark does not exist there. The nodes are the app's windows' every node, read in-process
     * (Capture.nodes), so no selector holds a secret.
     */
    private fun assertSecretsMarked(screen: Screen, model: CeremonyModel, name: String, lines: MutableSet<String>) {
        val nodes = Capture.nodes(pkg)
        val secrets = nodes.filter { it.resourceName == SECRET_TAG }
        if (!isProtected(screen)) {
            assertTrue("a secret's node on the Public screen " + name, secrets.isEmpty())
            return
        }
        if (screen in SECRET_SCREENS) {
            assertTrue("no secret's node on " + name, secrets.isNotEmpty())
            assertSecretTextsTagged(screen, model, nodes, name, lines)
        }
        if (secrets.isEmpty()) return
        val away = secrets.count { !it.visible }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            probe("$name: ${secrets.size} secret nodes ($away off screen); no data-sensitive mark before Android 14 (API ${Build.VERSION.SDK_INT})")
            return
        }
        val unmarked = secrets.count { !it.dataSensitive }
        assertEquals("secret nodes not marked data sensitive on " + name, 0, unmarked)
        pass("$name: all ${secrets.size} of its secret nodes ($away off screen) are data sensitive (API ${Build.VERSION.SDK_INT})")
    }

    /**
     * Each secret the screen shows, as the model holds it in-process (secretTexts), is drawn, and only by
     * nodes tagged SECRET_TAG: every one of the screen's nodes whose text is a secret carries the tag,
     * which secret() gives with the data-sensitive mark, so a secret drawn without secret() fails here
     * however many other nodes carry it; and each secret is some node's text, so none is left unchecked.
     * The texts are compared in-process and never printed; the screen's secret lines join lines, for the
     * search of the log after the walk.
     */
    private fun assertSecretTextsTagged(
        screen: Screen,
        model: CeremonyModel,
        nodes: List<Capture.NodeFacts>,
        name: String,
        lines: MutableSet<String>,
    ) {
        val secrets = onMain { secretTexts(screen, model) }
        val texts = secrets.drawn
        assertTrue("no secret text for " + name, texts.isNotEmpty())
        val drawing = nodes.filter { it.text != null && it.text in texts }
        assertTrue(
            "a node on " + name + " shows a secret without the secret tag (its text is not printed)",
            drawing.all { it.resourceName == SECRET_TAG },
        )
        val drawn = texts.count { text -> drawing.any { it.text == text } }
        assertTrue("only " + drawn + " of the " + texts.size + " secret texts of " + name + " are drawn (none is printed)", drawn == texts.size)
        lines.addAll(secrets.lines)
        pass("$name: each of its ${texts.size} secret texts is drawn, and only by secret nodes (${drawing.size} nodes)")
    }

    /**
     * A screen's secret texts: drawn, every one it draws; lines, those of them the log is searched for
     * after the walk, the SeedBook number's line ("SeedBook 0123") and the whole lines (an overview line,
     * a verdict, the faces typed once a letter is typed), which no line the system writes can hold by
     * chance, as it can a word or a letter.
     */
    private class ScreenSecrets(val drawn: Set<String>, val lines: Set<String>)

    /**
     * The secret texts screen draws, from the model's state, as the screens draw them: on the words the
     * word, its SeedBook number and each face's letter and label (a blank face's letter is no text); on
     * the overview its lines; on the read-back entry the faces typed, or once it matched the word; on the
     * mismatch the four verdicts; on the backup passphrase its page's lines ("1 ostrich"); on the confirm
     * its question's four choices and the letters typed; on Check a backup's entry the letters typed. The
     * word's copy is wiped once read. Main thread only.
     */
    private fun secretTexts(screen: Screen, model: CeremonyModel): ScreenSecrets {
        val state = model.state.value
        return when (screen) {
            Screen.Words -> {
                val insert = checkNotNull(state.insert)
                ScreenSecrets(wordsPageSecrets(insert), setOf(seedbookText(insert.seedbook)))
            }
            Screen.WordsOverview -> checkNotNull(state.overview).map { overviewLine(it) }.toSet().let { ScreenSecrets(it, it) }
            Screen.ReadbackEntry -> if (state.matched) {
                ScreenSecrets(setOf(wordOf(checkNotNull(state.insert))), emptySet())
            } else {
                val faces = typedFaces(model.readbackLetters)
                ScreenSecrets(setOf(faces), if (model.readbackLetters.length > 0) setOf(faces) else emptySet())
            }
            Screen.ReadbackMismatch -> {
                val mismatch = checkNotNull(state.mismatch)
                (1..4).map { verdictLine(it, mismatch.face(it)) }.toSet().let { ScreenSecrets(it, it) }
            }
            Screen.BackupPassphrase -> passphraseLines(state.page, checkNotNull(state.passphrase)).toSet().let { ScreenSecrets(it, it) }
            Screen.BackupConfirm -> {
                val question = checkNotNull(state.challenge).questions[state.page]
                val faces = typedFaces(model.backupLetters)
                ScreenSecrets(question.choices.map { choiceText(it) }.toSet() + faces, if (model.backupLetters.length > 0) setOf(faces) else emptySet())
            }
            Screen.BackupCheckEntry -> {
                val faces = typedFaces(model.backupLetters)
                ScreenSecrets(setOf(faces), if (model.backupLetters.length > 0) setOf(faces) else emptySet())
            }
            else -> ScreenSecrets(emptySet(), emptySet())
        }
    }

    /**
     * After the walk, the log holds none of its secret lines (rule 5; lead decision M5-68 (e)): logcat -d
     * (its default buffers, main, system and crash), read into memory through the shell and never
     * written to a file, still holds mark, the line the walk wrote as the words came, so the main
     * buffer, where this process's lines go, UI Automator's among them, dropped nothing written since;
     * and it holds no line of lines, which the walk's secret screens drew. Only counts and the buffers'
     * sizes (logcat -g) are printed.
     */
    private fun assertNoSecretInTheLog(mark: String, lines: Set<String>) {
        assertTrue("the walk held no secret line to search the log for", mark.isNotEmpty() && lines.isNotEmpty())
        probe("logcat -g: " + shellText("logcat -g").lines().joinToString(" | ") { it.trim() })
        val log = String(shell("logcat -d"), Charsets.UTF_8)
        val at = log.indexOf(mark)
        assertTrue("the log no longer holds the line the walk wrote as the words came, so it cannot be searched whole", at >= 0)
        probe("logcat -d: ${log.length} characters, ${log.length - at} of them from the line the walk wrote as the words came")
        val held = lines.count { log.contains(it) }
        assertTrue("the log holds " + held + " of the walk's " + lines.size + " secret lines (neither is printed)", held == 0)
        pass("the log after the walk (logcat -d, ${log.length} characters, the walk's own line still held) holds none of its ${lines.size} secret lines")
    }

    /**
     * The recents thumbnail is the placeholder: in the recents view, opened from the drawn first
     * screen and proven on screen (Capture.openRecents), no pixel has the known colour of its content
     * (ControlTest finds it in the control's).
     */
    @Test
    fun theRecentsThumbnailIsThePlaceholder() {
        val activity = launch()
        proveDrawn(activity, Screen.FirstLaunch)
        val device = UiDevice.getInstance(Capture.instrumentation)
        openRecents(device)
        val cap = Capture.screencapOrRefused()
        val shot = Capture.screenshotOrRefused()
        val inCap = Capture.knownOrRefused(cap)
        val inShot = Capture.knownOrRefused(shot)
        device.pressHome()
        probe(
            "recents: screencap ${Capture.described(cap)}, $inCap known-colour pixels; " +
                "takeScreenshot ${Capture.described(shot)}, $inShot",
        )
        assertTrue("the recents view shows the app's content", inCap < KNOWN_MIN_RECENTS && inShot < KNOWN_MIN_RECENTS)
        pass("recents: the thumbnail shows none of the app's content")
        finish(activity)
    }

    /**
     * The privacy cover carries the TEST REGISTRY strip in the test-registry APK, as every screen does,
     * and nothing shows one in the shipping APK (Q60, lead decision M5-51). The app is left from its
     * drawn first screen (Home) and brought back (am start, the task to the front, as LifecycleTest
     * returns), so the cover is up; UI Automator then finds the cover by its resource id and, inside
     * it, the strip, or no strip anywhere in the shipping APK. The idle warning comes from the same
     * call (Screens.kt's OverlayScreen), strip included, so this holds for its strip too; only its
     * text is its own, and no emulator test reaches it (nine minutes without input while a session is
     * held). Where the strip lies against the system bars is not read here: UI Automator gives only
     * visible bounds, cut to the window as accessibility reports it.
     */
    @Test
    fun theCoverCarriesTheStripOnlyInTheTestRegistryApk() {
        val registry = pkg == REGISTRY_PACKAGE
        val activity = launch()
        proveDrawn(activity, Screen.FirstLaunch)
        val device = UiDevice.getInstance(Capture.instrumentation)
        device.pressHome()
        waitUntil("the app left") { stage(activity) == Stage.STOPPED }
        shellText("am start -n $pkg/com.keepcrypt.entropy.MainActivity")
        waitUntil("back in the app, covered") {
            stage(activity) == Stage.RESUMED && onMain { activity.model.state.value.overlay } == Overlay.Cover
        }
        proveDrawn(activity, Screen.FirstLaunch)
        val cover = device.wait(Until.findObject(By.res("cover")), 10_000) ?: throw AssertionError("the cover is not on screen")
        // The cover's tap merges its content into one node: the strip is the cover's when UI Automator
        // finds it under that node, or when the node's own text (its merged label) is the strip's.
        val under = cover.hasObject(By.res(STRIP))
        val label = (cover.text ?: "").contains(STRIP_TEXT)
        val anywhere = device.hasObject(By.res(STRIP)) || device.hasObject(By.text(STRIP_TEXT))
        probe(
            "cover (${if (registry) "test-registry" else "shipping"} APK): the strip under it: $under; its text names the strip: " +
                "$label; a strip on screen: $anywhere",
        )
        if (registry) {
            assertTrue("the cover lacks the TEST REGISTRY strip in the test-registry APK", under || label)
        } else {
            assertFalse("a TEST REGISTRY strip on screen in the shipping APK", anywhere || label)
        }
        cover.click()
        waitUntil("the cover taken away") { onMain { activity.model.state.value.overlay } == null }
        if (registry) {
            pass("the cover carries the TEST REGISTRY strip in the test-registry APK")
        } else {
            pass("no TEST REGISTRY strip on the cover or the screen under it in the shipping APK")
        }
        finish(activity)
    }

    private fun stage(activity: MainActivity): Stage =
        onMain { ActivityLifecycleMonitorRegistry.getInstance().getLifecycleStageOf(activity) }

    /**
     * Positive control (c), API 36 only, where the platform reads the setting (Android 15 added it):
     * disable_secure_windows is unset or 0 first; set to 1, the app's own captures (screencap and
     * takeScreenshot) show its screen, both its known colour and lit pixels over the region the
     * black assertions read, so litPixels and region are shown to see a screen that is drawn; back
     * as it was, black again. On API 31 the same steps run as a probe of whether the setting is read
     * there, and only the black-again check is asserted.
     */
    @Test
    fun disableSecureWindowsShowsTheScreenOnlyWhileSet() {
        val enforced = Build.VERSION.SDK_INT >= Build.VERSION_CODES.BAKLAVA
        val before = shellText("settings get secure disable_secure_windows")
        probe("disable_secure_windows: $before before the test; ro.debuggable=${shellText("getprop ro.debuggable")}")
        if (enforced) assertTrue("disable_secure_windows is set before the test", before == "null" || before == "0")
        val activity = launch()
        proveDrawn(activity, Screen.FirstLaunch)
        val region = region(activity)
        val shown = try {
            shell("settings put secure disable_secure_windows 1")
            SystemClock.sleep(2 * SETTLE_MS)
            proveDrawn(activity, Screen.FirstLaunch)
            // Where the platform reads the setting (enforced), the captures must be images; on API 31
            // a refusal is recorded as showing nothing.
            val cap = if (enforced) screencap() else Capture.screencapOrRefused()
            val shot = if (enforced) screenshot() else Capture.screenshotOrRefused()
            intArrayOf(
                Capture.knownOrRefused(cap), Capture.knownOrRefused(shot),
                Capture.litOrRefused(cap, region), Capture.litOrRefused(shot, region),
            )
        } finally {
            if (before == "null") shell("settings delete secure disable_secure_windows")
            else shell("settings put secure disable_secure_windows " + before)
        }
        val (capKnown, shotKnown, capLit, shotLit) = shown
        val read = capKnown >= KNOWN_MIN && shotKnown >= KNOWN_MIN && capLit > 0 && shotLit > 0
        probe(
            "disable_secure_windows=1: the app's own captures show $capKnown known-colour pixels in screencap, " +
                "$shotKnown in takeScreenshot; $capLit and $shotLit lit pixels over the app's window $region (the setting is read: $read)",
        )
        if (enforced) {
            assertTrue("disable_secure_windows=1: screencap does not show the app's screen", capKnown >= KNOWN_MIN)
            assertTrue("disable_secure_windows=1: takeScreenshot does not show the app's screen", shotKnown >= KNOWN_MIN)
            assertTrue("disable_secure_windows=1: no lit pixel in screencap over the app's window", capLit > 0)
            assertTrue("disable_secure_windows=1: no lit pixel in takeScreenshot over the app's window", shotLit > 0)
        }
        SystemClock.sleep(2 * SETTLE_MS)
        proveDrawn(activity, Screen.FirstLaunch)
        assertEquals("lit pixels in screencap after the setting went back", 0, Capture.litOrRefused(Capture.screencapOrRefused(), region))
        assertEquals(
            "lit pixels in takeScreenshot after the setting went back", 0,
            Capture.litOrRefused(Capture.screenshotOrRefused(), region),
        )
        assertEquals("disable_secure_windows was not put back", before, shellText("settings get secure disable_secure_windows"))
        if (enforced) {
            pass("control (c): disable_secure_windows unset, then 1 shows the screen in screencap and takeScreenshot, then black again")
        } else {
            pass("disable_secure_windows probe done; black again after it")
        }
        finish(activity)
    }

    /**
     * The empty saved-state Bundle crashes nothing: the activity is recreated from what it saved
     * (SecureActivity clears it, and passes null on), draws its first screen again with FLAG_SECURE,
     * and stays black. A crash would also fail android-instrument.sh's judge. The recreation is a
     * configuration change, which is no leaving of the app (group 14): the new activity has the same
     * ceremony model (the ViewModel outlived the change), and that model took no stop for a leave, so
     * no cover is up and nothing was wiped.
     */
    @Test
    fun anEmptySavedStateBundleCrashesNothing() {
        val first = launch()
        proveDrawn(first, Screen.FirstLaunch)
        Capture.instrumentation.runOnMainSync { first.recreate() }
        var second: MainActivity? = null
        waitUntil("the recreated activity is resumed") {
            second = onMain {
                ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(Stage.RESUMED)
                    .filterIsInstance<MainActivity>().firstOrNull { it !== first }
            }
            second != null
        }
        val again = second!!
        proveDrawn(again, Screen.FirstLaunch)
        val flagged = onMain { again.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0 }
        assertTrue("the recreated window lacks FLAG_SECURE", flagged)
        assertEquals("lit pixels in screencap after the recreation", 0, Capture.litOrRefused(Capture.screencapOrRefused(), region(again)))
        assertTrue("the recreated activity has another ceremony model", onMain { again.model === first.model })
        val state = onMain { again.model.state.value }
        assertEquals("the configuration change was taken for leaving the app (a cover is up)", null, state.overlay)
        assertEquals("the configuration change wiped the session", null, state.notice)
        probe("empty saved-state Bundle: the activity was recreated from it and drew its first screen again, secure; nothing crashed")
        pass("the empty saved-state Bundle: recreated, drawn, black; the same model, no leaving taken, nothing wiped")
        finish(again)
    }

    /**
     * No content capture of the app (group 14, SecureActivity): with its first screen drawn, `dumpsys
     * content_capture` names the package on no line. The plan asks this only where the image runs a
     * capture service: where it runs none (as the probe found on API 31), the dump is empty or says
     * dumpsys can't find the service, and has nothing to name the app in, so the test passes with a
     * probe line saying it proved nothing here and no pass line. The root's own flag is read back in
     * everyScreenIsDrawnAndThenBlackInEveryCapture.
     */
    @Test
    fun contentCaptureHasNothingOfTheApp() {
        val activity = launch()
        proveDrawn(activity, Screen.FirstLaunch)
        val (out, err) = Capture.shellWithErrors("dumpsys content_capture")
        val dump = String(out, Charsets.UTF_8).lines().filter { it.isNotBlank() }
        val absent = String(err, Charsets.UTF_8).contains(NO_SERVICE) || dump.any { it.contains(NO_SERVICE) }
        val service = dump.isNotEmpty() && !absent
        val naming = dump.filter { it.contains(pkg) }
        probe(
            "dumpsys content_capture: the service ${if (service) "answers" else "is absent"}; ${dump.size} lines, " +
                "${naming.size} naming the app: " + naming.joinToString(" | ") { it.trim() },
        )
        assertTrue("dumpsys content_capture names the app", naming.isEmpty())
        if (service) {
            pass("content capture: the service answers and no line of dumpsys content_capture names the app")
        } else {
            probe("content capture: no content_capture service on this image, so nothing names the app: not proven here")
        }
        finish(activity)
    }

    /**
     * Probe only: whether UiAutomation sees and clicks a node marked accessibility-data sensitive
     * (Android 14+), which decides whether a UI Automator smoke test on a Protected pad can run on
     * API 36 (group 6, Driving). The node is a plain button the test adds to the drawn screen.
     */
    @Test
    fun dataSensitiveNodesProbe() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            probe("data-sensitive nodes: none before Android 14 (API ${Build.VERSION.SDK_INT})")
            return
        }
        val activity = launch()
        proveDrawn(activity, Screen.FirstLaunch)
        val clicked = CountDownLatch(1)
        Capture.instrumentation.runOnMainSync {
            val node = Button(activity)
            node.contentDescription = SENSITIVE_NODE
            node.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
            node.setOnClickListener { clicked.countDown() }
            activity.addContentView(node, ViewGroup.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT))
        }
        Capture.instrumentation.waitForIdleSync()
        val device = UiDevice.getInstance(Capture.instrumentation)
        val seen = device.wait(Until.findObject(By.desc(SENSITIVE_NODE)), 5_000)
        var reached = false
        if (seen != null) {
            seen.click()
            reached = clicked.await(5, TimeUnit.SECONDS)
        }
        probe("data-sensitive nodes on API ${Build.VERSION.SDK_INT}: UiAutomation sees one: ${seen != null}; its click reaches it: $reached")
        finish(activity)
    }

    private companion object {
        /** The start-up self-test's time limit (a translated library is slower; NativeTest's). */
        const val START_SECONDS = 120

        const val SENSITIVE_NODE = "kc_probe_data_sensitive"

        /** The test-registry APK's package (the withTestRegistry flavour's applicationId). */
        const val REGISTRY_PACKAGE = "com.keepcrypt.entropy.testregistry"

        /** The permission the scan screen asks for. */
        const val CAMERA = "android.permission.CAMERA"

        /** The TEST REGISTRY strip's resource id and text (Kit.kt's TestRegistryStrip). */
        const val STRIP = "test_registry_strip"
        const val STRIP_TEXT = "TEST REGISTRY"

        /** What dumpsys says (on stderr) for a service the image does not run. */
        const val NO_SERVICE = "Can't find service"

        /**
         * The Protected screens that draw secret text: the words, the overview, the read-back's letters and
         * its verdicts, the backup passphrase, its confirm's choices and letters, and Check a backup's letters.
         */
        val SECRET_SCREENS = setOf(
            Screen.Words, Screen.WordsOverview, Screen.ReadbackEntry, Screen.ReadbackMismatch, Screen.BackupPassphrase,
            Screen.BackupConfirm, Screen.BackupCheckEntry,
        )

        /** The space between the passphrase's words on a page. */
        const val SPACE: Byte = 0x20
    }
}
