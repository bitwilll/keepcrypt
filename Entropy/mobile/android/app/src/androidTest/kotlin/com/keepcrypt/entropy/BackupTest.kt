package com.keepcrypt.entropy

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Capture.probe
import com.keepcrypt.entropy.Capture.report
import com.keepcrypt.entropy.Capture.shellText
import com.keepcrypt.entropy.Ui.START_SECONDS
import com.keepcrypt.entropy.Ui.await
import com.keepcrypt.entropy.Ui.awaitText
import com.keepcrypt.entropy.Ui.find
import com.keepcrypt.entropy.Ui.on
import com.keepcrypt.entropy.Ui.roll
import com.keepcrypt.entropy.Ui.tap
import com.keepcrypt.entropy.Ui.text
import com.keepcrypt.entropy.Ui.toHome
import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.WordPage
import com.keepcrypt.entropy.screens.CLOUD_FOLDER
import com.keepcrypt.entropy.screens.CeremonyModel
import com.keepcrypt.entropy.screens.FileRefusal
import com.keepcrypt.entropy.screens.PASSPHRASE_WORDS
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.screens.fileRefusalText
import com.keepcrypt.entropy.screens.fingerprintHex
import java.util.regex.Pattern
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The encrypted backup and Check a backup on the phone (tasks/todo.md, M5 group 18), run on the shipping
 * app in the API 31 and 36 legs by scripts/android-instrument.sh's age: form, which pipes this run's raw
 * output straight into scripts/android-age-check.py, the CI age -d hand-off. A dice-only seed of
 * vectors/kcr.json's public gate seed dice-50-words12 (the CI throwaway seed) goes through the model's
 * entry points to its wallet summary (the words and the read-back are FlowTest's); the offer, the save
 * screen and the results are tapped through UI Automator by their resource ids, as a user would, and
 * the Protected screens (the passphrase, its confirm, Check a backup's entry and the words) go through
 * the model's entry points, as their buttons and the letter pad call them, so no secret goes into a UI
 * Automator selector, a click's point or a message (lead decision M5-68 (e)); the passphrase is read
 * in-process from the screen's Secrets. The system's file picker (DocumentsUI) is driven by UI
 * Automator, its controls found by their own resource ids and labels: core's suggested name in its
 * title field, saved to Downloads, then read back and verified by core before "Backup verified". The
 * test then reports the hand-off's three values as status values: the passphrase (from the in-process
 * Secret: the one place it leaves this process, the key the gate's KtTestChannel rule allows only here
 * and in the checker), the name and the summary's fingerprint, both public; age -d decrypts the file
 * in the job after this run. A copy of the backup named .txt is refused by its name on Home, before any
 * byte is read (CheckBackupScreensTest proves the order on the JVM); the watch-only export and the
 * registration are skipped on the way to the checklist (FlowTest takes them); Check a backup opens the saved
 * file through the picker: a wrong passphrase is refused with core's text, the right one gives "Backup
 * OK" with the summary's fingerprint and the seed's Seal ID, the words through the privacy gate are the
 * vector's (compared in-process, never printed), the re-check QR shows, and Done returns Home with the
 * slot empty. The test's own probe and pass lines are fixed text with public values. Each test puts the
 * phone's airplane-mode and Wi-Fi settings back as they were.
 */
@RunWith(AndroidJUnit4::class)
class BackupTest {
    private val device: UiDevice get() = UiDevice.getInstance(Capture.instrumentation)

    @Test
    fun aBackupSavedToDownloadsVerifiesAndCheckABackupOpensItAndRefusesWhatItMust() {
        Capture.whileOffline {
            val activity = toHome()
            val fingerprint = toSummary(activity)
            tap("summary_next")
            on(activity, Screen.BackupOffer)
            tap("make_backup")
            find("privacy_gate")
            tap("pass_gate")
            await("past the passphrase's gate", 10) { onMain { activity.model.state.value.let { it.screen == Screen.BackupPassphrase && !it.gate } } }
            val passphrase = onMain { readPassphrase(activity.model) }
            onMain {
                repeat(2) {
                    val state = activity.model.state.value
                    type(activity.model, passphrase[checkNotNull(state.challenge).questions[state.page].position - 1])
                    activity.model.confirmTyped()
                }
            }
            on(activity, Screen.BackupSave, START_SECONDS)
            val name = text("backup_name")
            assertTrue("the save screen does not show core's suggested name", NAME.matcher(name).matches())
            assertEquals(CLOUD_FOLDER, text("cloud_folder"))
            tap("save_backup")
            val creator = Picker.opened()
            val title = device.wait(Until.findObject(By.pkg(Picker.PACKAGE).res("android:id/title")), 10_000)
                ?: throw AssertionError("the picker shows no name field (its facts are the probe line before this)").also { probe(Picker.facts("create")) }
            probe("the create-document picker: package $creator, its name field ${title.text}; " + Picker.facts("create"))
            assertEquals("the picker's name is not core's suggested one", name, title.text)
            Picker.toDownloads("create")
            val save = device.findObject(By.pkg(Picker.PACKAGE).res("android:id/button1"))
                ?: device.findObject(By.pkg(Picker.PACKAGE).clickable(true).text(Pattern.compile("(?i)save")))
                ?: throw AssertionError("the picker has no Save (its facts are the probe line before this)").also { probe(Picker.facts("create")) }
            save.click()
            on(activity, Screen.BackupVerified, START_SECONDS)
            val listed = shellText("ls -l " + DOWNLOADS + name)
            probe("the saved file: $listed")
            assertTrue("the backup is not in Downloads", listed.contains(name))
            report(HAND_OFF, passphrase.joinToString(" ") { String(it, Charsets.US_ASCII) })
            report("kc_backup_name", name)
            report("kc_backup_fingerprint", fingerprint)
            tap("backup_next")
            on(activity, Screen.WatchOffer)
            tap("skip_watch_only")
            on(activity, Screen.RegisterOffer)
            tap("skip_registration")
            on(activity, Screen.Checklist)
            tap("finish")
            on(activity, Screen.Home)
            assertTrue("the slot is not at home: Finish did not end the session", Core.selfTest() is Reply.Done)

            // A copy of the backup named .txt: refused by its name, before any byte is read.
            shellText("cp " + DOWNLOADS + name + " " + DOWNLOADS + RENAMED)
            tap("check_backup")
            Picker.pick(RENAMED)
            on(activity, Screen.Home)
            awaitText("file_refusal", fileRefusalText(FileRefusal.NotAge))
            assertEquals(FileRefusal.NotAge, onMain { activity.model.state.value.fileRefusal })

            tap("check_backup")
            Picker.pick(name)
            on(activity, Screen.BackupCheckEntry)
            find("privacy_gate")
            tap("pass_gate")
            await("past the entry's gate", 10) { onMain { !activity.model.state.value.gate } }
            val other = if (passphrase[0].decodeToString().take(4) == "aban") "zoo" else "aban"
            onMain {
                type(activity.model, other.toByteArray(Charsets.US_ASCII))
                activity.model.entryTyped()
                for (word in passphrase.drop(1)) {
                    type(activity.model, word)
                    activity.model.entryTyped()
                }
            }
            await("the wrong passphrase refused", START_SECONDS) {
                onMain { activity.model.state.value.let { it.screen == Screen.BackupCheckEntry && it.entryRefusal != null } }
            }
            awaitText("entry_refusal", "the passphrase does not open this backup")
            onMain {
                for (word in passphrase) {
                    type(activity.model, word)
                    activity.model.entryTyped()
                }
            }
            for (word in passphrase) word.fill(0)
            on(activity, Screen.BackupCheckResult, START_SECONDS)
            awaitText("backup_fingerprint", fingerprint)
            awaitText("backup_seal_id", DICE_50_SEAL_ID)
            tap("show_backup_words")
            find("privacy_gate")
            tap("pass_gate")
            for (index in DICE_50_WORDS.indices) {
                await("the backup's insert " + (index + 1), 10) {
                    onMain { activity.model.state.value.let { it.screen == Screen.Words && !it.gate && it.page == index } }
                }
                val same = onMain { sameWord(checkNotNull(activity.model.state.value.insert), DICE_50_WORDS[index]) }
                assertTrue("the backup's insert " + (index + 1) + " is not the vector's word", same)
                onMain { if (index + 1 < DICE_50_WORDS.size) activity.model.nextPage() else activity.model.backupWordsDone() }
            }
            on(activity, Screen.BackupCheckResult)
            tap("recheck")
            on(activity, Screen.BackupRecheck)
            tap("back")
            on(activity, Screen.BackupCheckResult)
            tap("backup_done")
            on(activity, Screen.Home)
            assertTrue("the slot is not at home: Done did not end the check", Core.selfTest() is Reply.Done)
            pass(
                "backup: saved through DocumentsUI ($creator) to Downloads under core's name, read back and verified (Backup " +
                    "verified); a .txt copy refused by its name; Check a backup through the picker: a wrong passphrase " +
                    "refused, then Backup OK with the summary's fingerprint and Seal ID $DICE_50_SEAL_ID, 12 words equal to " +
                    "the vector's (in-process), the re-check QR, Done: Home with the slot empty",
            )
            finish(activity)
        }
    }

    /**
     * From Home, a dice-only seed of dice-50-words12 through the model's entry points, as its screens call
     * them: Length, the rolls, Done (finish), Skip and its confirm, the words past their gate, each insert
     * read back from the page the state holds (a copy wiped at once), the read-back's end and the summary.
     * The summary's fingerprint (public), as the screen shows it.
     */
    private fun toSummary(activity: MainActivity): String {
        tap("dice_only_seed")
        on(activity, Screen.Length)
        tap("words_12")
        on(activity, Screen.Dice, START_SECONDS)
        roll(activity, DICE_50_ROLLS.length, DICE_50_ROLLS)
        tap("dice_done")
        on(activity, Screen.CheckPrompt, START_SECONDS)
        onMain {
            val model = activity.model
            model.skip()
            model.skipConfirmed()
            model.showWords()
            model.passGate()
            repeat(DICE_50_WORDS.size - 1) { model.nextPage() }
            model.startReadback()
            repeat(DICE_50_WORDS.size) {
                val word = checkNotNull(model.state.value.insert).word()
                for (index in 0 until minOf(4, word.size)) model.readbackLetters.type(Char(word[index].toInt()))
                word.wipe()
                model.readbackTyped()
                model.readbackNext()
            }
            model.showSummary()
        }
        on(activity, Screen.Wallet)
        val fingerprint = fingerprintHex(checkNotNull(onMain { activity.model.state.value.summary }).fingerprint)
        awaitText("fingerprint", fingerprint)
        return fingerprint
    }

    /**
     * The passphrase's two pages read in-process from the state's Secrets, the second through Next, then
     * "I wrote it down": its eight words, each its own array (never a String). Main thread only.
     */
    private fun readPassphrase(model: CeremonyModel): List<ByteArray> {
        val words = ArrayList<ByteArray>(PASSPHRASE_WORDS)
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
        assertEquals("eight passphrase words", PASSPHRASE_WORDS, words.size)
        return words
    }

    /** word's first four letters (a three-letter word's three) on the model's letter pad. Main thread only. */
    private fun type(model: CeremonyModel, word: ByteArray) {
        for (index in 0 until minOf(4, word.size)) model.backupLetters.type(Char(word[index].toInt()))
    }

    /** Whether insert's word is word, byte by byte, its copy wiped (the words are public vectors, never printed). */
    private fun sameWord(insert: WordPage, word: String): Boolean {
        val bytes = insert.word()
        val same = bytes.size == word.length && word.indices.all { bytes[it] == word[it].code.toByte() }
        bytes.wipe()
        return same
    }

    private companion object {
        /** The instrumentation status key of the CI age -d hand-off (tasks/todo.md, M5 group 18): the throwaway seed's backup passphrase. */
        const val HAND_OFF = "kc_ci_throwaway_passphrase"

        /** vectors/kcr.json's dice-50-words12: 123456 repeated, its words and its Seal ID (public gate-seed vectors). */
        const val DICE_50_ROLLS = "12345612345612345612345612345612345612345612345612"
        val DICE_50_WORDS = listOf(
            "unveil", "nice", "picture", "region", "tragic", "fault", "cream", "strike", "tourist", "control",
            "recipe", "tourist",
        )
        const val DICE_50_SEAL_ID = "YVM9CPP3"

        /** Core's suggested name: keepcrypt-backup-, 8 lower-case hex digits, .age. */
        val NAME: Pattern = Pattern.compile("keepcrypt-backup-[0-9a-f]{8}[.]age")

        /** Where the picker's Downloads root keeps its files, as the shell reads them. */
        const val DOWNLOADS = Picker.DOWNLOADS

        /** The .txt copy of the backup that Check a backup must refuse by its name. */
        const val RENAMED = "keepcrypt-backup-copy.txt"

        /** The space between the passphrase's words on a page. */
        const val SPACE: Byte = 0x20
    }
}
