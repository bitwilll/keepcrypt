package com.keepcrypt.entropy

import android.graphics.Bitmap
import android.graphics.Rect
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.accessibility.AccessibilityEvent
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
import com.keepcrypt.entropy.ffi.HaltReason
import com.keepcrypt.entropy.ffi.KcHalt
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Words
import com.keepcrypt.entropy.screens.COVER_TITLE
import com.keepcrypt.entropy.screens.CeremonyModel
import com.keepcrypt.entropy.screens.DICE_KEYS
import com.keepcrypt.entropy.screens.DocumentPickers
import com.keepcrypt.entropy.screens.DocumentPlace
import com.keepcrypt.entropy.screens.INSERTS_PER_DEVICE
import com.keepcrypt.entropy.screens.LETTER_KEYS
import com.keepcrypt.entropy.screens.Overlay
import com.keepcrypt.entropy.screens.PASSPHRASE_WORDS
import com.keepcrypt.entropy.screens.PickedFile
import com.keepcrypt.entropy.screens.QrKind
import com.keepcrypt.entropy.screens.SECRET_TAG
import com.keepcrypt.entropy.screens.ScanStop
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.screens.UiState
import com.keepcrypt.entropy.screens.asciiPage
import com.keepcrypt.entropy.screens.bip39Shown
import com.keepcrypt.entropy.screens.choiceText
import com.keepcrypt.entropy.screens.deviceLegText
import com.keepcrypt.entropy.screens.isProtected
import com.keepcrypt.entropy.screens.keyLabel
import com.keepcrypt.entropy.screens.overviewLine
import com.keepcrypt.entropy.screens.passphraseLines
import com.keepcrypt.entropy.screens.passphraseText
import com.keepcrypt.entropy.screens.screenId
import com.keepcrypt.entropy.screens.screenTitle
import com.keepcrypt.entropy.screens.seedbookText
import com.keepcrypt.entropy.screens.typedFaces
import com.keepcrypt.entropy.screens.verdictLine
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.math.abs
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

    /** The walk's passphrase pages, each its four lines as drawn ("1 ostrich"), for the search of the log after the walk. */
    private val pages = ArrayList<Set<String>>()

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
     * verified it (the real long call); the exports (group 18): the watch-only offer, the BIP39 question,
     * its entry past its gate with the walk's passphrase typed in-process before the gate is passed (so
     * the entry draws it), the watch-only summary core's export gives, the account QR past its gate and the
     * descriptor QR, the registration's offer and its QR past its gate, D's offer (the walk's seed is
     * mixed) and D past its gate; the checklist, whose Finish leads Home, and Check a backup on the saved
     * file handed to the model as the picker would (the system's pickers are BackupTest's): its entry past
     * its gate, its result once core opened the file with the passphrase typed in-process (the real long
     * call), and the re-check QR; then the checked backup's words past their gate (checkedWords), paged to
     * their last insert, whose Done returns to the result, and its Done Home; Load registry snapshot's
     * result once core has judged vectors/kcr.json's with-dice-50, handed to the model as the picker would
     * (the real long call: loaded in the test-registry APK, refused in the shipping APK, which trusts no
     * registry key; the picker is SnapshotDrillTest's and CheckTest's); and About, from which "Working..."
     * is held. The scan screen asks for
     * the camera as it opens, and the
     * walk is the first of this APK's tests to open it: dumpsys package shows CAMERA requested and not
     * granted, no permission prompt is up, then the scan screen opens and the system's prompt shows over
     * the app, another package's window, which the walk answers "Don't allow" before the capture (the
     * scan screen then says the camera was refused, and its "Type go-ahead code" leads on). The stop
     * screen is a halt status as Core throws it, a health test's (STOP_REASON), so this process's slot
     * stays live for the tests after it (the model's own tests halt a real one) and the screen's reason
     * line is not the one a halt with no reason draws. Home on needs the phone offline, which the pass
     * sees to.
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
            Screen.CheckQr -> onMain { model.showCheckQr() }
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
            Screen.WatchOffer -> onMain { model.backupVerifiedDone() }
            Screen.Bip39Ask -> onMain { model.showWatchOnly() }
            Screen.Bip39Entry -> {
                onMain { model.withBip39Passphrase() }
                waitUntil("the BIP39 entry's privacy gate") { onMain { activity.shownScreen == Screen.Bip39Entry && model.state.value.gate } }
                onMain {
                    for (key in WALK_PASSPHRASE) model.bip39Letters.type(key)
                    model.passGate()
                }
            }
            Screen.WatchSummary -> onMain { model.bip39Typed() }
            Screen.WatchAccountQr -> passedTo(activity, Screen.WatchAccountQr) { model.watchSummaryDone() }
            Screen.WatchDescriptorQr -> onMain { model.nextPage() }
            Screen.RegisterOffer -> onMain { model.watchDone() }
            Screen.RegisterQr -> passedTo(activity, Screen.RegisterQr) { model.showRegistration() }
            Screen.RevealDOffer -> onMain { model.registrationDone() }
            Screen.RevealD -> passedTo(activity, Screen.RevealD) { model.showDeviceLeg() }
            Screen.Checklist -> onMain { model.deviceLegDone() }
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
            Screen.Snapshot -> {
                onMain {
                    repeat(INSERTS_PER_DEVICE - 1) { model.nextPage() }
                    model.nextPage()
                    model.swapDone()
                    model.passGate()
                    repeat(INSERTS_PER_DEVICE - 1) { model.nextPage() }
                    model.backupWordsDone()
                    model.closeBackup()
                    model.loadSnapshot(NoPickers)
                    model.snapshotPicked(PickedSnapshot)
                }
                waitUntil("Load registry snapshot's result, after core judged the file", START_SECONDS) {
                    onMain { activity.shownScreen } == Screen.Snapshot
                }
                val judged = onMain { activity.model.state.value.let { if (pkg == REGISTRY_PACKAGE) it.loaded != null else it.snapshotRefusal != null } }
                assertTrue("the snapshot was not loaded in the test-registry APK, or not refused in the shipping APK", judged)
            }
            Screen.About -> onMain {
                model.snapshotDone()
                model.about()
            }
            Screen.Working -> onMain { model.work({ working.await(); Reply.Done(Unit) }) {} }
            Screen.Stop -> {
                working.countDown()
                waitUntil("About again, after the held call") { onMain { activity.shownScreen } == Screen.About }
                onMain { model.work<Unit>({ throw KcHalt(STOP_REASON) }) {} }
            }
        }
        return activity
    }

    /**
     * A Protected screen past its privacy gate: open (on the main thread) leads from the screen before to
     * screen, which shows its gate first; once it does, the gate is passed.
     */
    private fun passedTo(activity: MainActivity, screen: Screen, open: () -> Unit) {
        onMain { open() }
        waitUntil(screenId(screen) + "'s privacy gate") { onMain { activity.shownScreen == screen && activity.model.state.value.gate } }
        onMain { activity.model.passGate() }
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
     * it checks each screen, before Load registry snapshot's result.
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

    /** The walk's pickers: the model opens nothing, and the walk hands it the place and the files as the pickers would. */
    private object NoPickers : DocumentPickers {
        override fun create(name: String) {}

        override fun open() {}

        override fun openSnapshot() {}
    }

    /** vectors/kcr.json's with-dice-50 as the open-document picker gives a file: its name and its size. */
    private object PickedSnapshot : PickedFile {
        private val bytes = Checker.bytes(Checker.WITH_DICE_50_KCR)
        override val name: String = Checker.WITH_DICE_50_FILE
        override val size: Long = bytes.size.toLong()

        override fun read(limit: Int): ByteArray = bytes.copyOf()
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
     * From the check QR, the scan screen and its camera prompt (M5 group 16): CAMERA requested and not
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

    /**
     * On the dice, rolls faces (the pad's six in order, unless faces names others, repeated) through the
     * model's pick and confirm, then Done, and waits for the check prompt (the real finish).
     */
    private fun finishDice(activity: MainActivity, rolls: Int, faces: String = DICE_KEYS) {
        onMain {
            for (index in 0 until rolls) {
                activity.model.dicePick.replace(faces[index % faces.length])
                activity.model.confirmRoll()
            }
            activity.model.diceDone()
        }
        waitUntil("the check prompt after the dice's Done", START_SECONDS) { onMain { activity.shownScreen } == Screen.CheckPrompt }
    }

    /**
     * A new MainActivity on vectors/kcr.json's dice-99-words12, a gate seed, at its first words page past
     * the privacy gate, reached as FlowTest reaches a dice-only seed's words (Home's Dice-only seed, 12
     * words, the vector's 99 rolls, Done, Skip and its confirm, Show words and the gate), through the
     * model's entry points as the screens call them: First launch's Continue runs the real self-test, and
     * Go offline's Start needs the phone offline, which the caller sees to. The page on show is checked
     * in-process to be the vector's first of 12 (its word compared, never printed). A dice-only seed has
     * no D, so Reveal D is never reached.
     */
    private fun gateSeedsWords(): MainActivity {
        val activity = started()
        val model = activity.model
        onMain { model.firstLaunchDone() }
        waitUntil("the start-up self-test passed", START_SECONDS) { onMain { activity.shownScreen } == Screen.GoOffline }
        waitUntil("the app reads the phone offline", 30) { onMain { model.state.value.offline } }
        onMain {
            model.startOffline()
            model.chooseMode(Mode.DiceOnly)
            model.chooseLength(Words.Twelve)
        }
        waitUntil("the dice, after the start", START_SECONDS) { onMain { activity.shownScreen } == Screen.Dice }
        finishDice(activity, GATE_SEED_ROLLS, GATE_SEED_FACES)
        onMain {
            model.skip()
            model.skipConfirmed()
            model.showWords()
        }
        waitUntil("the words' privacy gate") { onMain { activity.shownScreen == Screen.Words && model.state.value.gate } }
        val first = onMain {
            model.passGate()
            val state = model.state.value
            val insert = state.insert
            state.screen == Screen.Words && !state.gate && insert != null && insert.position == 1 &&
                insert.count == GATE_SEED_WORDS && wordOf(insert) == GATE_SEED_FIRST_WORD
        }
        assertTrue("the words on show are not dice-99-words12's first page (no word is printed)", first)
        return activity
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
     * (checkedWords), and the stop screen drawing its halt's reason line (assertStopNamesTheReason). After the
     * walk the log holds none of its secret lines (assertNoSecretInTheLog).
     */
    @Test
    fun everyScreenIsDrawnAndThenBlackInEveryCapture() {
        Capture.whileOffline { walkEveryScreen() }
    }

    /**
     * The layout on a 412 dp phone (Stage U's U3h-b): the window manager set to 1080x2424 px at density 420 (put back
     * with wm size reset and wm density reset in a finally), the layout walk (layoutWalk); no capture is judged
     * here, everyScreenIsDrawnAndThenBlackInEveryCapture does that at CI's window.
     */
    @Test
    fun everyScreenIsLaidOutOnA412DpPhone() {
        try {
            shell("wm size $PHONE_SIZE")
            shell("wm density $PHONE_DENSITY")
            probe("the window manager: " + Capture.shellText("wm size").replace('\n', ' ') + "; " + Capture.shellText("wm density").replace('\n', ' '))
            layoutWalk("412 dp")
            pass("every screen laid out on a 412 dp phone ($PHONE_SIZE at density $PHONE_DENSITY): $LAID_OUT")
        } finally {
            shell("wm density reset")
            shell("wm size reset")
        }
    }

    /**
     * The layout at the system's largest font scale, 2.0, at CI's window (Q78 with minSdk 34, lead decision
     * M5-84 (d), commit U3i-b): settings put system font_scale 2.0 (put back as it was, or 1.0 when it was unset,
     * in a finally, as DeviceChangeTest puts its 1.3 back), then the layout walk (layoutWalk), each screen judged
     * once its activity's configuration has the scale. No capture is judged here.
     */
    @Test
    fun everyScreenIsLaidOutAtFontScale2() {
        val before = shellText("settings get system font_scale")
        try {
            shell("settings put system font_scale $FONT_SCALE")
            probe("the font scale: " + shellText("settings get system font_scale") + " (it was $before)")
            layoutWalk("font scale $FONT_SCALE") { activity, name ->
                waitUntil("$name at font scale $FONT_SCALE") { onMain { abs(activity.resources.configuration.fontScale - FONT_SCALE) < 0.01f } }
            }
            pass("every screen laid out at font scale $FONT_SCALE at CI's window: $LAID_OUT")
        } finally {
            shell("settings put system font_scale " + if (before == "null") "1.0" else before)
        }
    }

    /**
     * The layout walk: walkScreens through every screen in a new activity, its detours too, each screen (after
     * ready, given its activity and name) drawn and laid out (assertLaidOut) as its column is scrolled through
     * (through), named in its lines with what; then, pass or fail, the camera's answer forgotten
     * (forgetTheCameraAnswer).
     */
    private fun layoutWalk(what: String, ready: (MainActivity, String) -> Unit = { _, _ -> }) {
        try {
            Capture.whileOffline {
                walkScreens { screen, activity, name ->
                    ready(activity, name)
                    proveDrawn(activity, screen)
                    assertLaidOut(activity, through(activity, screen), "$name ($what)")
                }
            }
        } finally {
            forgetTheCameraAnswer()
        }
    }

    /**
     * CAMERA put back as a fresh install has it, not granted and with no answer kept: pm clear-permission-flags
     * drops its user-set and user-fixed flags, and dumpsys package then shows neither. Each walk answers the scan
     * screen's prompt with Don't allow (askedOnTheScanScreen), and Android shows no prompt after a second denial;
     * with two layout walks before it in one run, the capture walk, which needs the prompt, met none (kc37, local,
     * U3i-b). So each layout walk leaves no answer behind, and every walk after one meets a first prompt.
     */
    private fun forgetTheCameraAnswer() {
        shell("pm clear-permission-flags $pkg $CAMERA user-set user-fixed")
        val after = Capture.permission(pkg, CAMERA)
        assertFalse("CAMERA granted after the layout walk", after.granted)
        assertFalse("CAMERA's answer still kept after pm clear-permission-flags: " + after.state, ANSWER_KEPT.containsMatchIn(after.state))
    }

    private fun walkEveryScreen() {
        val lines = HashSet<String>()
        var mark = ""
        walkScreens(
            before = { screen ->
                // From the words on, the walk holds secret texts. As they come, a line of the walk's own goes
                // to the log, through the shell's log, to the main buffer, where UI Automator's lines go too: a
                // log that still holds it after the walk has dropped nothing written since, so the search after
                // the walk reads every line written while the walk held a secret.
                if (screen == Screen.Words) {
                    mark = "kc_capture_walk_" + SystemClock.elapsedRealtimeNanos()
                    shell("log -t KcCaptureTest " + mark)
                }
            },
        ) { screen, activity, name ->
            checkScreen(screen, activity, name, lines)
            if (name == screenId(Screen.Stop)) assertStopNamesTheReason()
        }
        assertNoSecretInTheLog(mark, lines)
    }

    /**
     * The walk (show) through every screen in Screen's order in one activity, each screen handed to check
     * with the name its lines give it, before(screen) run before each is brought up; with the walk's
     * detours, each checked as a screen is: the read-back entry in its matched state (matchedEntry) before
     * the read-back's end, the save screen with a failed write (failedSave) before "Backup verified", and a
     * checked backup's words (checkedWords) before Load registry snapshot's result. Both walks take them,
     * since the screen after a detour is reached from where it leaves the model (run 43613600587: the 412 dp
     * walk, which had none, met the mismatch where the read-back's end needs a match, and never reached it).
     * Then the walk's activity finished, and its passphrase and backup zeroed.
     */
    private fun walkScreens(before: (Screen) -> Unit = {}, check: (Screen, MainActivity, String) -> Unit) {
        for (screen in Screen.entries) {
            before(screen)
            if (screen == Screen.ReadbackDone) check(Screen.ReadbackEntry, matchedEntry(), screenId(Screen.ReadbackEntry) + " (matched)")
            if (screen == Screen.BackupVerified) check(Screen.BackupSave, failedSave(), screenId(Screen.BackupSave) + " (a failed write)")
            if (screen == Screen.Snapshot) check(Screen.Words, checkedWords(), screenId(Screen.Words) + " (a checked backup's)")
            check(screen, show(screen), screenId(screen))
        }
        finish(checkNotNull(walk))
        for (word in passphrase) word.fill(0)
        savedBackup?.fill(0)
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
        if (capLit > 0) probe("$name: screencap " + Capture.litAccount(cap, region))
        if (shotLit > 0) probe("$name: takeScreenshot " + Capture.litAccount(shot, region))
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
        val seen = through(activity, screen)
        val reads = seen.reads
        assertSecretsMarked(screen, activity.model, name, lines, reads)
        assertPadKeysMarked(screen, activity.model, name, reads)
        assertLaidOut(activity, seen, name)
        pass(
            "$name: drawn, then screencap and takeScreenshot black over the app's window; " +
                "SECURE on all ${found.size} of its windows; no content capture",
        )
    }

    /**
     * The showing screen's nodes at each position of its column as it is scrolled through (Capture.nodesThrough),
     * and Compose's layout of it read in-process at each (Layout.read), position by position.
     */
    private class Through(val reads: List<List<Capture.NodeFacts>>, val layout: List<List<Layout.Node>>)

    private fun through(activity: MainActivity, screen: Screen): Through {
        val layout = ArrayList<List<Layout.Node>>()
        val reads = Capture.nodesThrough(pkg, screen) { layout.add(Layout.read(activity)) }
        return Through(reads, layout)
    }

    /**
     * The screen's layout (Stage U's U3h-b; U3i-b, Q78, M5-84 (d)): every control the screen shows (a node that
     * takes a click, or a button by its role) has a touch target at least 48 dp each way, in Compose's own layout
     * (Layout.read: its node's whole size, in view or not) and as the accessibility reads see it,
     * and every text it shows lies across inside the app's window, none cut at its left or right edge. Judged on
     * the nodes in view at each of the reads, the screen's column scrolled through (Capture.nodesThrough), so a node
     * out of view at one position is judged where it is in view; a control's size is the largest it was read at,
     * since a position can cut it at the column's edge and nodesThrough reads each whole at one. Then in Compose's
     * own layout at those positions, which holds the nodes out of view too: every control and every text is shown
     * whole by scrolling (shownWhole: what its parents' clips, the window and the system bars leave
     * of it covers it, top to bottom across the positions, and its whole width at each), so a control that no
     * scrolling brings into view and a text its parent or the window cuts are found; and no text overflows its own
     * box. Read in-process from the screen's own nodes; only screen ids, tags, counts and sizes are printed.
     */
    private fun assertLaidOut(activity: MainActivity, walked: Through, name: String) {
        val reads = walked.reads
        val nodes = reads.flatten().filter { it.visible && !it.bounds.isEmpty }
        val density = onMain { activity.resources.displayMetrics.density }
        val window = region(activity)
        val target = (MIN_TARGET_DP * density).toInt()
        val laidControls = walked.layout.flatten().filter { it.control }.groupBy { it.id }.values
        val laidSmall = laidControls.filter { it.first().width < target || it.first().height < target }
        assertTrue(
            "$name: " + laidSmall.size + " of its " + laidControls.size + " controls are under 48 dp in Compose's layout: " +
                laidSmall.joinToString { described(it.first()) },
            laidSmall.isEmpty(),
        )
        val controls = nodes.filter { it.clickable || it.className == Ui.BUTTON }.groupBy { it.key }.values
        val small = controls.filter { seen -> seen.maxOf { it.bounds.width() } < target || seen.maxOf { it.bounds.height() } < target }
        // Before the failure, what the first two such nodes are (controlFacts).
        for (seen in small.take(2)) probe("$name: a control under 48 dp: " + controlFacts(seen, walked.layout))
        assertTrue("$name: " + small.size + " of its " + controls.size + " controls are under 48 dp: " + small.joinToString { seen -> sized(seen) }, small.isEmpty())
        val texts = nodes.filter { !it.text.isNullOrEmpty() }
        val cut = texts.filter { it.bounds.left < window.left || it.bounds.right > window.right }.distinctBy { it.key }
        val shown = texts.distinctBy { it.key }.size
        assertTrue("$name: " + cut.size + " of its " + shown + " texts are cut at the window's edge: " + cut.joinToString { it.resourceName ?: "a text" }, cut.isEmpty())
        val laid = walked.layout.flatten().filter { (it.control || it.text) && it.width > 0f && it.height > 0f }.groupBy { it.id }.values
        val unshown = laid.filter { !shownWhole(it) }
        assertTrue(
            "$name: " + unshown.size + " of its " + laid.size + " controls and texts are never shown whole by scrolling: " +
                unshown.joinToString { described(it.first()) + ", shown " + it.mapNotNull { node -> node.shown }.joinToString("; ").ifEmpty { "nowhere" } },
            unshown.isEmpty(),
        )
        val overflowing = laid.filter { it.any { node -> node.overflow } }
        assertTrue("$name: " + overflowing.size + " of its texts overflow their box: " + overflowing.joinToString { described(it.first()) }, overflowing.isEmpty())
        // Q97 (U3h): no line break inside a word on a button or in a large secret text (the insert's word), and no
        // soft wrap of the code, C, or a monospaced secret text (the letters typed, D, the overview, the choices).
        val whole = laid.filter { seen ->
            seen.any { node ->
                val secret = node.tag == SECRET_TAG
                ((node.control || (secret && node.large)) && node.brokenWord) ||
                    ((node.tag == "code" || node.tag == "commitment_hex" || (secret && node.monospace)) && node.wrapped)
            }
        }
        assertTrue("$name: " + whole.size + " of its texts break a word or a group across lines (Q97): " + whole.joinToString { described(it.first()) }, whole.isEmpty())
        val scale = onMain { activity.resources.configuration.fontScale }
        probe(
            "$name: " + controls.size + " controls of 48 dp or more (" + target + " px at density " + density + "), " + shown +
                " texts inside the window, over " + reads.size + " position(s) of its column; in Compose's layout " + laid.size +
                " controls and texts each shown whole by scrolling, none overflowing (font scale " + scale + ")",
        )
    }

    /**
     * Whether a node, read at each position of its screen's column (seen, Layout.read's reads of it), is shown
     * whole by scrolling: its shown parts, each its whole width, cover it from its top to its bottom with no gap
     * (within Layout.EDGE_PX), so every line of a text taller than the column is in view at one position at least.
     */
    private fun shownWhole(seen: List<Layout.Node>): Boolean {
        val parts = seen.mapNotNull { node -> node.shown?.let { node to it } }
        if (parts.isEmpty()) return false
        if (parts.any { (node, part) -> part.left > node.left + Layout.EDGE_PX || part.right < node.left + node.width - Layout.EDGE_PX }) return false
        var reached = 0f
        for ((top, bottom) in parts.map { (node, part) -> (part.top - node.top) to (part.bottom - node.top) }.sortedBy { it.first }) {
            if (top > reached + Layout.EDGE_PX) return false
            reached = maxOf(reached, bottom)
        }
        return reached >= seen.first().height - Layout.EDGE_PX
    }

    /**
     * For a failure's probe line, what a control the reads saw (seen) is: its window, its chain of nodes up to the
     * window's root, each as its class's simple name, its id, whether it takes a click and is visible, and its
     * bounds now; and at each position of layout, the Compose nodes whose whole bounds hold the centre it was first
     * read at, each with its id, tag, size, corner and shown part. Classes, ids, flags and sizes only, never a text.
     */
    private fun controlFacts(seen: List<Capture.NodeFacts>, layout: List<List<Layout.Node>>): String {
        val node = seen.first().key
        val chain = generateSequence(node) { it.parent }.take(12).joinToString(" < ") {
            (it.className?.toString()?.substringAfterLast('.') ?: "?") + "(" + (it.viewIdResourceName ?: "-") + ", click " + it.isClickable +
                ", visible " + it.isVisibleToUser + ", " + Rect().also(it::getBoundsInScreen).toShortString() + ")"
        }
        val x = seen.first().bounds.exactCenterX()
        val y = seen.first().bounds.exactCenterY()
        val under = layout.mapIndexed { i, at ->
            "position " + i + ": " + at.filter { it.left <= x && x <= it.left + it.width && it.top <= y && y <= it.top + it.height }
                .joinToString(" ") { "#" + it.id + " " + described(it) + " at " + it.left.toInt() + "," + it.top.toInt() + " shown " + it.shown }
        }
        return "window " + node.windowId + " (" + node.window?.title + "); " + chain + "; Compose at its centre: " + under.joinToString(" || ")
    }

    /** A control as the accessibility reads saw it, for a line: its id (or "a key"), its largest size and its bounds at each read. Never its text. */
    private fun sized(seen: List<Capture.NodeFacts>): String =
        (seen.first().resourceName ?: "a key") + " " + seen.maxOf { it.bounds.width() } + "x" + seen.maxOf { it.bounds.height() } + " px (read at " +
            seen.joinToString("; ") { it.bounds.toShortString() } + ")"

    /** A node of Layout.read for a failure line: its tag (or what it is) and its whole size. Never its text. */
    private fun described(node: Layout.Node): String =
        (node.tag ?: if (node.control) "a control" else "a text") + " " + node.width.toInt() + "x" + node.height.toInt() + " px"

    /** Each node of reads once, as its first read has it: for the checks of what a node is or says, not where it lies. */
    private fun joined(reads: List<List<Capture.NodeFacts>>): List<Capture.NodeFacts> = reads.flatten().distinctBy { it.key }

    /**
     * The stop screen names the walk's halt (docs/mobile-apps.md:36; M5 commit U3a4): the screen's own
     * nodes (Capture.nodesThrough, each once), read in-process, hold one node tagged HALT_REASON_TAG (Screens.kt's Stop),
     * and it draws STOP_LINE, the fixed line for STOP_REASON. The line is fixed text, no secret.
     */
    private fun assertStopNamesTheReason() {
        val reasons = joined(Capture.nodesThrough(pkg, Screen.Stop)).filter { it.resourceName == HALT_REASON_TAG }.map { it.text }
        assertEquals("the stop screen's reason line", listOf(STOP_LINE), reasons)
        pass("stop: its one reason line names the walk's halt, a health test's")
    }

    /**
     * The secret text a screen draws is marked accessibility-data sensitive (docs/mobile-apps.md, "Rules
     * for Claude Code"; group 6's probe, where it applies): every node tagged SECRET_TAG (Kit.kt's secret(),
     * which every node that shows a secret takes) must be data sensitive as UiAutomation reads it (the
     * app needs Android 14, minSdk 34, Q84), the screens that show the words or their letters must hold
     * such nodes, every node there whose text is one of the screen's secrets must be one of them and each
     * secret must be drawn (assertSecretTextsTagged), and a Public screen holds none. The nodes are the
     * app's windows' every node, read in-process (Capture.nodes), so no selector holds a secret, from the
     * first read whose roots are the screen's alone (Capture.nodesOf): a read that still shows the screen
     * before is read again, never judged, and the read judged is judged once. reads are the screen's at each position of its column, scrolled
     * through (Capture.nodesThrough), so every secret text is drawn in view and judged (Q85, M5-84 (a)): each
     * node is judged once (joined), and one off screen is one in view at none of them.
     */
    private fun assertSecretsMarked(screen: Screen, model: CeremonyModel, name: String, lines: MutableSet<String>, reads: List<List<Capture.NodeFacts>>) {
        val nodes = joined(reads)
        assertNamed(screen, nodes, name)
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
        val inView = reads.flatten().filter { it.visible }.map { it.key }.toSet()
        val away = secrets.count { it.key !in inView }
        val unmarked = secrets.count { !it.dataSensitive }
        assertEquals("secret nodes not marked data sensitive on " + name, 0, unmarked)
        pass("$name: all ${secrets.size} of its secret nodes ($away off screen) are data sensitive (API ${Build.VERSION.SDK_INT})")
    }

    /**
     * A Protected pad's keys carry their labels, marked (Q79): on a screen that shows one (the read-back entry
     * before its match, the backup's confirm and Check a backup's entry: the letter pad; the BIP39 entry: its
     * page of the ASCII pad), the screen's nodes with the button role whose text is one of the pad's labels
     * (Pads.kt's keyLabel) are its keys, each label once, and every one is marked accessibility-data sensitive,
     * as a secret's node is, takes a click (TalkBack presses it) and carries no tag (no id names a key). From the
     * same reads as the secrets' check, each node once (joined); compared in-process, only counts printed.
     */
    private fun assertPadKeysMarked(screen: Screen, model: CeremonyModel, name: String, reads: List<List<Capture.NodeFacts>>) {
        val labels = onMain { protectedPadLabels(screen, model.state.value) } ?: return
        val keys = joined(reads).filter { it.className == Ui.BUTTON && it.text in labels }
        assertTrue(
            "$name: " + keys.size + " buttons show a key's label, not the pad's " + labels.size + " keys once each",
            keys.size == labels.size && keys.mapNotNull { it.text }.toSet() == labels.toSet(),
        )
        assertEquals("$name: the pad's keys not marked data sensitive", 0, keys.count { !it.dataSensitive })
        assertEquals("$name: the pad's keys that take no click", 0, keys.count { !it.clickable })
        assertEquals("$name: the pad's keys with a tag", 0, keys.count { it.resourceName != null })
        pass("$name: its pad's ${keys.size} keys carry their labels, each data sensitive and clickable, none tagged (Q79)")
    }

    /** The labels of the Protected pad screen shows in state, as Pads.kt draws them (keyLabel); null where it shows none. */
    private fun protectedPadLabels(screen: Screen, state: UiState): List<String>? = when (screen) {
        Screen.ReadbackEntry -> if (state.matched) null else LETTER_KEYS.map(::keyLabel)
        Screen.BackupConfirm, Screen.BackupCheckEntry -> LETTER_KEYS.map(::keyLabel)
        Screen.Bip39Entry -> asciiPage(state.page).map(::keyLabel)
        else -> null
    }

    /**
     * The screen's names for TalkBack (Stage U's commit U3g), from the same read of its nodes: its pane
     * title is screenTitle's (the walk shows each screen past its gate, with no overlay), and a screen that
     * draws a QR code names it by its kind (QrKind) on the code's node, so no QR code is nameless; every
     * name is a constant, compared in-process.
     */
    private fun assertNamed(screen: Screen, nodes: List<Capture.NodeFacts>, name: String) {
        assertEquals("the pane titles on $name", listOf(screenTitle(screen)), nodes.mapNotNull { it.paneTitle }.distinct())
        val kind = QR_KINDS[screen]
        val qrs = nodes.mapNotNull { it.contentDescription }.filter { "QR code" in it }
        assertEquals("the QR codes' names on $name", listOfNotNull(kind?.spoken), qrs)
        pass("$name: its pane title is its own" + if (kind == null) "" else ", its QR code named by its kind")
    }

    /**
     * Each secret the screen shows, as the model holds it in-process (secretTexts), is drawn, and only by
     * nodes tagged SECRET_TAG: every one of the screen's nodes whose text is a secret carries the tag,
     * which secret() gives with the data-sensitive mark, so a secret drawn without secret() fails here
     * however many other nodes carry it; and each secret is some node's text, so none is left unchecked.
     * The texts are compared in-process and never printed; the screen's secret lines join lines, and a
     * passphrase page's lines pages, for the search of the log after the walk.
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
        if (secrets.page.isNotEmpty()) pages.add(secrets.page)
        pass("$name: each of its ${texts.size} secret texts is drawn, and only by secret nodes (${drawing.size} nodes)")
    }

    /**
     * A screen's secret texts: drawn, every one it draws; lines, those of them the log is searched for
     * after the walk, the SeedBook number's line ("SeedBook 0123") and the whole lines (an overview line,
     * a verdict, the faces typed once a letter is typed), which no line the system writes can hold by
     * chance, as it can a word or a letter; page, a passphrase page's four lines ("1 ostrich"), which
     * its one node draws one line feed apart: one such line the system can write by chance (a number and
     * a common word), so the search fails on two or more of a page's lines, as a logged page would show.
     */
    private class ScreenSecrets(val drawn: Set<String>, val lines: Set<String>, val page: Set<String> = emptySet())

    /**
     * The secret texts screen draws, from the model's state, as the screens draw them: on the words the
     * word, its SeedBook number and each face's letter and label (a blank face's letter is no text); on
     * the overview its lines; on the read-back entry the faces typed, or once it matched the word; on the
     * mismatch the four verdicts; on the backup passphrase its page, four lines ("1 ostrich") in one text; on the confirm
     * its question's four choices and the letters typed; on the BIP39 passphrase's entry the passphrase as
     * shown (a space a middle dot), searched for in the log as shown and as typed; on D its four rows of
     * hex groups in one text, each row searched for; on Check a backup's entry the letters typed. The
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
            Screen.BackupPassphrase -> {
                val text = checkNotNull(state.passphrase)
                ScreenSecrets(setOf(passphraseText(state.page, text)), emptySet(), passphraseLines(state.page, text).toSet())
            }
            Screen.BackupConfirm -> {
                val question = checkNotNull(state.challenge).questions[state.page]
                val faces = typedFaces(model.backupLetters)
                ScreenSecrets(question.choices.map { choiceText(it) }.toSet() + faces, if (model.backupLetters.length > 0) setOf(faces) else emptySet())
            }
            Screen.Bip39Entry -> {
                val shown = bip39Shown(model.bip39Letters)
                ScreenSecrets(setOf(shown), if (model.bip39Letters.length > 0) setOf(shown, WALK_PASSPHRASE) else emptySet())
            }
            Screen.RevealD -> {
                val shown = deviceLegText(checkNotNull(state.deviceLeg))
                ScreenSecrets(setOf(shown), shown.split("\n").toSet())
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
     * and from mark on (the walk drew no secret before it, so nothing before it can be one of them) it
     * holds no line of lines, which the walk's secret screens drew, and no two lines of any of its
     * passphrase pages. Only counts and the buffers' sizes (logcat -g) are printed.
     */
    private fun assertNoSecretInTheLog(mark: String, lines: Set<String>) {
        assertTrue("the walk held no secret line to search the log for", mark.isNotEmpty() && lines.isNotEmpty() && pages.isNotEmpty())
        probe("logcat -g: " + shellText("logcat -g").lines().joinToString(" | ") { it.trim() })
        val log = String(shell("logcat -d"), Charsets.UTF_8)
        val at = log.indexOf(mark)
        assertTrue("the log no longer holds the line the walk wrote as the words came, so it cannot be searched whole", at >= 0)
        val since = log.substring(at)
        probe("logcat -d: ${log.length} characters, ${since.length} of them from the line the walk wrote as the words came")
        val held = lines.count { since.contains(it) }
        val shown = pages.count { page -> page.count { since.contains(it) } >= 2 }
        assertTrue(
            "the log holds " + held + " of the walk's " + lines.size + " secret lines and two or more lines of " + shown + " of its " +
                pages.size + " passphrase pages (none is printed)",
            held == 0 && shown == 0,
        )
        pass(
            "the log after the walk (logcat -d, ${since.length} of its ${log.length} characters from the walk's own line) holds none of " +
                "its ${lines.size} secret lines and no two lines of its ${pages.size} passphrase page(s)",
        )
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
     * text is its own, and only IdleClockTest reaches it (nine minutes without input while a session is
     * held, on API 36). Where the strip lies against the system bars is not read here: UI Automator gives only
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

    /**
     * Reading counts as input and the cover hides the words from accessibility (Q80, commit U3j). A gate seed's
     * first words page (gateSeedsWords) is on show; READ_AFTER_MS later an accessibility focus event goes up from
     * the app's Compose view as Compose sends one when a service focuses a node (its view's parent's
     * requestSendAccessibilityEvent; Compose itself sends it only under touch exploration, which no test turns on),
     * through the root view's delegate (SecureActivity's): the cover must come 30 s after that reading, not 30 s
     * after the gate (the model's tick, 1 s, and this poll, LATE_MS late at most). Under the cover the screen
     * beneath is out of the accessibility tree (Capture.assertOverlayAlone: the cover's pane title alone, no tag of
     * the words page, no node showing one of its secret texts, compared in-process). The cover tapped away (the
     * model's dismissOverlay, as its tap calls it), the same read finds the page again: its pane title, its id and
     * its secret nodes. The idle warning comes from the same overlay call and the same clearing (Screens.kt);
     * IdleClockTest checks the tree under it on the real clock (API 36).
     */
    @Test
    fun aReadingRestartsTheIdleTimeAndTheCoverHidesTheWordsFromAccessibility() {
        Capture.whileOffline {
            val activity = gateSeedsWords()
            val passed = SystemClock.elapsedRealtime()
            SystemClock.sleep(READ_AFTER_MS)
            val read = onMain {
                sendReading(activity)
                SystemClock.elapsedRealtime()
            }
            var covered = -1L
            while (covered < 0 && SystemClock.elapsedRealtime() < read + COVER_MS + LATE_MS) {
                if (onMain { activity.model.state.value.overlay } == Overlay.Cover) covered = SystemClock.elapsedRealtime() - read
                SystemClock.sleep(POLL_MS)
            }
            probe("a reading ${read - passed} ms after the gate; the cover ${covered} ms after the reading")
            assertTrue("the cover did not come 30 s after the reading ($covered ms)", covered in COVER_MS - TICK_MS..COVER_MS + LATE_MS)
            val secrets = onMain { wordsPageSecrets(checkNotNull(activity.model.state.value.insert)) }
            val count = Capture.assertOverlayAlone(activity, pkg, COVER_TAG, COVER_TITLE, secrets, "the cover over a words page")
            onMain { activity.model.dismissOverlay() }
            waitUntil("the cover taken away") { onMain { activity.model.state.value.overlay } == null }
            val back = Capture.nodesOf(pkg, Screen.Words)
            assertEquals("the pane titles once uncovered", listOf(screenTitle(Screen.Words)), back.mapNotNull { it.paneTitle }.distinct())
            assertTrue("no secret node once uncovered", back.any { it.resourceName == SECRET_TAG })
            pass(
                "a reading ${read - passed} ms after the gate put the cover at ${covered} ms after it; under the cover, of " +
                    "$count nodes, the cover's alone, nothing of the words page; uncovered, the page's nodes back",
            )
            finish(activity)
        }
    }

    /**
     * An accessibility focus event, as Compose sends one for a node a service focuses: up from the activity's
     * Compose view (the innermost first child under its content) through its parent's requestSendAccessibilityEvent,
     * the path every event of Compose's takes (AndroidComposeViewAccessibilityDelegateCompat's sendEvent).
     * Main thread only.
     */
    private fun sendReading(activity: MainActivity) {
        var view: View = activity.findViewById(android.R.id.content)
        while (view is ViewGroup && view.childCount > 0) view = view.getChildAt(0)
        val parent = checkNotNull(view.parent) { "the Compose view has no parent" }
        parent.requestSendAccessibilityEvent(view, AccessibilityEvent(AccessibilityEvent.TYPE_VIEW_ACCESSIBILITY_FOCUSED))
    }

    private fun stage(activity: MainActivity): Stage =
        onMain { ActivityLifecycleMonitorRegistry.getInstance().getLifecycleStageOf(activity) }

    /**
     * Positive control (c), API 36 only, where the platform reads the setting (Android 15 added it):
     * disable_secure_windows is unset or 0 first; then the words page of a gate seed, dice-99-words12's
     * first (gateSeedsWords; the page control (a) draws), is on show; set to 1, the app's own captures
     * (screencap and takeScreenshot) show that page, judged as ControlTest judges control (a)'s: lit
     * pixels over the region the black assertions read, so litPixels and region are shown to see a
     * screen that is drawn, and inside every node that draws one of the page's secret texts (read
     * in-process with no selector, compared with the page the state holds and never printed), so the
     * words' own drawing is in each capture, and the known colour where the page draws it, under the
     * TEST REGISTRY strip (the shipping APK's words page draws none); back as it was, black again. On API
     * 34 the same steps run as a probe of whether the setting is read there, and only the black-again
     * check is asserted.
     */
    @Test
    fun disableSecureWindowsShowsTheScreenOnlyWhileSet() {
        val enforced = Build.VERSION.SDK_INT >= Build.VERSION_CODES.BAKLAVA
        val strip = pkg == REGISTRY_PACKAGE
        val before = shellText("settings get secure disable_secure_windows")
        probe("disable_secure_windows: $before before the test; ro.debuggable=${shellText("getprop ro.debuggable")}")
        if (enforced) assertTrue("disable_secure_windows is set before the test", before == "null" || before == "0")
        Capture.whileOffline {
            val activity = gateSeedsWords()
            proveDrawn(activity, Screen.Words)
            val region = region(activity)
            val (cap, shot, nodes) = try {
                shell("settings put secure disable_secure_windows 1")
                SystemClock.sleep(2 * SETTLE_MS)
                proveDrawn(activity, Screen.Words)
                val words = wordsOnShow(activity)
                // Where the platform reads the setting (enforced), the captures must be images; below API 36
                // a refusal is recorded as showing nothing.
                val screencapImage = if (enforced) screencap() else Capture.screencapOrRefused()
                val screenshotImage = if (enforced) screenshot() else Capture.screenshotOrRefused()
                Triple(shown(screencapImage, region, words), shown(screenshotImage, region, words), words.size)
            } finally {
                if (before == "null") shell("settings delete secure disable_secure_windows")
                else shell("settings put secure disable_secure_windows " + before)
            }
            val read = listOf(cap, shot).all { (!strip || it.known >= KNOWN_MIN) && it.lit > 0 && it.unlit == 0 }
            probe(
                "disable_secure_windows=1, the words page: the app's own captures show ${cap.known} known-colour pixels in screencap, " +
                    "${shot.known} in takeScreenshot (${if (strip) "under the TEST REGISTRY strip" else "the shipping APK's page draws none"}); " +
                    "${cap.lit} and ${shot.lit} lit pixels over the app's window $region; $nodes nodes draw its secret texts, " +
                    "${cap.unlit} and ${shot.unlit} of them unlit (the setting is read: $read)",
            )
            if (enforced) {
                if (strip) {
                    assertTrue("disable_secure_windows=1: screencap does not show the words page's known colour", cap.known >= KNOWN_MIN)
                    assertTrue("disable_secure_windows=1: takeScreenshot does not show the words page's known colour", shot.known >= KNOWN_MIN)
                }
                assertTrue("disable_secure_windows=1: no lit pixel in screencap over the app's window", cap.lit > 0)
                assertTrue("disable_secure_windows=1: no lit pixel in takeScreenshot over the app's window", shot.lit > 0)
                assertTrue("disable_secure_windows=1: screencap has a node of the words with no lit pixel", cap.unlit == 0)
                assertTrue("disable_secure_windows=1: takeScreenshot has a node of the words with no lit pixel", shot.unlit == 0)
            }
            SystemClock.sleep(2 * SETTLE_MS)
            proveDrawn(activity, Screen.Words)
            assertEquals("lit pixels in screencap after the setting went back", 0, Capture.litOrRefused(Capture.screencapOrRefused(), region))
            assertEquals(
                "lit pixels in takeScreenshot after the setting went back", 0,
                Capture.litOrRefused(Capture.screenshotOrRefused(), region),
            )
            assertEquals("disable_secure_windows was not put back", before, shellText("settings get secure disable_secure_windows"))
            if (enforced) {
                pass(
                    "control (c): disable_secure_windows unset, then 1 shows dice-99-words12's first words page in screencap and " +
                        "takeScreenshot, lit in each of its $nodes nodes of the words, then black again",
                )
            } else {
                pass("disable_secure_windows probe done on the words page; black again after it")
            }
            finish(activity)
        }
    }

    /**
     * The nodes that draw the words page's secret texts, as ControlTest finds control (a)'s: the app's
     * nodes tagged SECRET_TAG with text (read in-process, Capture.nodes, no selector), whose texts must be
     * exactly those of the page the state holds (wordsPageSecrets), each on screen, the page still the
     * words past their gate with no cover or placeholder over it. Compared, never printed.
     */
    private fun wordsOnShow(activity: MainActivity): List<Capture.NodeFacts> {
        val secrets = onMain {
            val state = activity.model.state.value
            val insert = state.insert
            if (state.screen == Screen.Words && !state.gate && state.overlay == null && !state.recording && insert != null) {
                wordsPageSecrets(insert)
            } else {
                null
            }
        }
        assertTrue("the words page is not on show past its gate (a cover or the placeholder over it)", secrets != null)
        val words = Capture.nodes(pkg).filter { it.resourceName == SECRET_TAG && !it.text.isNullOrBlank() }
        assertTrue("the words page's nodes do not draw its page's secret texts (none is printed)", words.map { it.text }.toSet() == secrets)
        assertTrue("a node drawing a secret text lies off screen", words.all { it.visible })
        return words
    }

    /**
     * One capture of the words page with the setting at 1: its known-colour pixels, its lit pixels over
     * the app's window and how many of the nodes of the words have none inside their bounds.
     */
    private class Shown(val known: Int, val lit: Int, val unlit: Int)

    /** What a capture that may have been refused shows of the words page (Shown): a refusal shows nothing, every node unlit. */
    private fun shown(image: Bitmap?, region: Rect, words: List<Capture.NodeFacts>): Shown = Shown(
        Capture.knownOrRefused(image),
        Capture.litOrRefused(image, region),
        if (image == null) words.size else words.count { Capture.litPixels(image, it.bounds) == 0 },
    )

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
     * (on every level the app runs on, Android 14+), which decides whether a UI Automator smoke test on a
     * Protected pad can run on API 36 (group 6, Driving). The node is a plain button the test adds to the drawn screen.
     */
    @Test
    fun dataSensitiveNodesProbe() {
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

    /**
     * No resource id of the shipping APK reaches accessibility (Q84, lead decision M5-84 (c), commit U3n): it turns
     * none of its Compose test tags into a resource id, so no node names what it holds by its id. With the tests'
     * own reading of the tags off (Tags.exposed false) before the activity is made, a gate seed's words page is shown
     * (gateSeedsWords), whose nodes carry SECRET_TAG and the screen's id among their tags in-process (Tags.of), and
     * every node of the app's windows is read from the app (Ui.appNodes: each refreshed, past the accessibility
     * cache): in the shipping APK none has a resource id but the platform's own views' (android:id/content), and
     * the positive control, the same read with the tests' reading back on, finds the page's tags as ids, SECRET_TAG
     * and the screen's among them, so the read sees an id where a node has one. The test-registry APK, never released, keeps its tags as ids (TEST_REGISTRY, for the
     * shell's camera check in scripts/android-local.sh): there the same read with the tests' reading off finds the
     * app's own ids, SECRET_TAG and the screen's among them. A probe line counts the nodes that offer Compose's
     * test-tag extra data (Tags.EXTRA_TAG), which Compose gives any service that asks for it, the nodes that answered
     * with a tag and those whose tag is SECRET_TAG: the residual Q84's answer leaves, which is no resource id. Tags
     * are fixed names; only counts and ids are printed.
     */
    @Test
    fun noResourceIdReachesAccessibility() {
        val registry = pkg == REGISTRY_PACKAGE
        Tags.exposed = false
        try {
            Capture.whileOffline {
                val activity = gateSeedsWords()
                proveDrawn(activity, Screen.Words)
                val tags = onMain { Tags.of(activity) }
                assertTrue("the words page holds no node tagged SECRET_TAG in-process", SECRET_TAG in tags)
                assertTrue("the words page's root is not tagged with its id in-process", screenId(Screen.Words) in tags)
                // UI Automator's first use here (nothing before it in this test) has UiAutomation report the
                // interactive windows, whose roots Ui.appNodes walks.
                device.waitForIdle()
                val nodes = Ui.appNodes()
                assertTrue("no node of the app's windows to read", nodes.isNotEmpty())
                // The platform's own views keep their framework ids (the content frame, android:id/content); every
                // other id would be the app's, a test tag among them.
                val ids = nodes.mapNotNull { it.viewIdResourceName }
                val own = ids.filterNot { it.startsWith(FRAMEWORK_ID) }
                val offered = nodes.filter { Tags.EXTRA_TAG in it.availableExtraData }
                val answered = offered.mapNotNull { node ->
                    node.takeIf { it.refreshWithExtraData(Tags.EXTRA_TAG, Bundle()) }?.extras?.getCharSequence(Tags.EXTRA_TAG)?.toString()
                }
                probe(
                    "test tags as extra data (${Tags.EXTRA_TAG}), words page: ${offered.size} of ${nodes.size} nodes offer it, " +
                        "${answered.size} answered with a tag, ${answered.count { it == SECRET_TAG }} of them SECRET_TAG",
                )
                if (registry) {
                    assertTrue("the test-registry APK's own ids lack SECRET_TAG", SECRET_TAG in ids)
                    assertTrue("the test-registry APK's own ids lack the screen's", screenId(Screen.Words) in ids)
                    pass(
                        "the test-registry APK keeps its tags as resource ids (TEST_REGISTRY): ${ids.size} of its ${nodes.size} nodes, " +
                            "the secret tag's among them",
                    )
                } else {
                    assertEquals("nodes of the shipping APK's windows with an id of its own: " + own.distinct().joinToString(), 0, own.size)
                    Tags.exposed = true
                    val exposed = Ui.appNodes().mapNotNull { it.viewIdResourceName }
                    assertTrue("the positive control: the tests' own reading gives no node SECRET_TAG as its id", SECRET_TAG in exposed)
                    assertTrue("the positive control: the tests' own reading gives the root no id", screenId(Screen.Words) in exposed)
                    pass(
                        "no resource id of its own: none of the ${nodes.size} nodes of the shipping APK's words page has one (the platform's: " +
                            ids.distinct().joinToString() + "), though ${tags.size} of its semantics nodes are tagged; with the tests' own " +
                            "reading on, ${exposed.size} ids, the secret tag's among them",
                    )
                }
                finish(activity)
            }
        } finally {
            Tags.exposed = true
        }
    }

    private companion object {
        /** The smallest touch target a control may have, each way (Material's and Android's accessibility minimum). */
        const val MIN_TARGET_DP = 48

        /** What a layout walk proves of every screen (assertLaidOut), for its pass line. */
        const val LAID_OUT = "controls of 48 dp or more, each reached by scrolling, texts inside the window, none cut by its parent or overflowing its box"

        /** The system's largest font scale, which the layout walk is also run at (Q78, M5-84 (d)). */
        const val FONT_SCALE = 2.0f

        /** A 412 dp phone, as wm sets it: 1080 px across at density 420 (Stage U's U3h-b). */
        const val PHONE_SIZE = "1080x2424"
        const val PHONE_DENSITY = "420"

        /** The screens that draw a QR code, and its kind (U3g). */
        val QR_KINDS: Map<Screen, QrKind> = mapOf(
            Screen.CheckQr to QrKind.CheckRequest,
            Screen.CollisionReport to QrKind.CollisionReport,
            Screen.WatchAccountQr to QrKind.Account,
            Screen.WatchDescriptorQr to QrKind.Descriptor,
            Screen.RegisterQr to QrKind.Registration,
            Screen.BackupRecheck to QrKind.Recheck,
        )

        /** The start-up self-test's time limit (a translated library is slower; NativeTest's). */
        const val START_SECONDS = 120

        const val SENSITIVE_NODE = "kc_probe_data_sensitive"

        /** The test-registry APK's package (the withTestRegistry flavour's applicationId). */
        const val REGISTRY_PACKAGE = "com.keepcrypt.entropy.testregistry"

        /** The platform's own view ids (android:id/content, the content frame), which no test tag is. */
        const val FRAMEWORK_ID = "android:id/"

        /** The permission the scan screen asks for. */
        const val CAMERA = "android.permission.CAMERA"

        /** A permission's flags in dumpsys package that keep the user's answer (forgetTheCameraAnswer). */
        val ANSWER_KEPT = Regex("\\bUSER_(SET|FIXED)\\b")

        /** How long after the gate the cover test's reading comes: before the 30 s cover the gate would bring. */
        const val READ_AFTER_MS = 20_000L

        /** The cover's 30 s (Timers.COVER_MILLIS). */
        const val COVER_MS = 30_000L

        /** The model's tick: a step is seen up to this much late, and the reading's clock read up to this much early. */
        const val TICK_MS = 1_000L

        /** How late the cover may be seen: the model's 1 s tick and the poll. */
        const val LATE_MS = 2_500L

        /** How often the cover test reads the state. */
        const val POLL_MS = 200L

        /** The cover's test tag (Screens.kt's OverlayScreen). */
        const val COVER_TAG = "cover"

        /** The TEST REGISTRY strip's resource id and text (Kit.kt's TestRegistryStrip). */
        const val STRIP = "test_registry_strip"
        const val STRIP_TEXT = "TEST REGISTRY"

        /** What dumpsys says (on stderr) for a service the image does not run. */
        const val NO_SERVICE = "Can't find service"

        /**
         * The walk's halt, a health test's, and its line on the stop screen (Screens.kt's stopLine), so the
         * line drawn is not the one a halt with no reason, or an internal one, draws.
         */
        val STOP_REASON = HaltReason.HealthTest
        const val STOP_LINE = "An entropy health test failed."

        /** The stop screen's reason line's tag (Screens.kt's Stop). */
        const val HALT_REASON_TAG = "halt_reason"

        /**
         * The Protected screens that draw secret text: the words, the overview, the read-back's letters and
         * its verdicts, the backup passphrase, its confirm's choices and letters, the BIP39 passphrase typed,
         * D and Check a backup's letters (the other Protected screens draw QR codes, which hold no text).
         */
        val SECRET_SCREENS = setOf(
            Screen.Words, Screen.WordsOverview, Screen.ReadbackEntry, Screen.ReadbackMismatch, Screen.BackupPassphrase,
            Screen.BackupConfirm, Screen.Bip39Entry, Screen.RevealD, Screen.BackupCheckEntry,
        )

        /**
         * vectors/kcr.json's dice-99-words12, control (c)'s gate seed (control (a)'s page): 99 rolls of
         * 654321 repeated, 12 words, and its mnemonic's first word, compared in-process and never printed.
         */
        const val GATE_SEED_FACES = "654321"
        const val GATE_SEED_ROLLS = 99
        const val GATE_SEED_WORDS = 12
        const val GATE_SEED_FIRST_WORD = "various"

        /** The walk's BIP39 passphrase, made up for the walk (no wallet's): typed in-process, never printed or put in a selector. */
        const val WALK_PASSPHRASE = "Kc walk 1!"

        /** The space between the passphrase's words on a page. */
        const val SPACE: Byte = 0x20
    }
}
