package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Refusal
import com.keepcrypt.entropy.ffi.RefusalGroup
import com.keepcrypt.entropy.ffi.Reply
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * The CeremonyModel transitions of Check a backup (tasks/todo.md, M5 group 18; lead decision M5-48;
 * docs/mobile-apps.md, "Checking a backup"; the Pi's Home flow), over the real slot through Core and the
 * host library, on a backup the test's own ceremony saved (vectors/kcr.json's dice-50-words12, its
 * passphrase read from the screen in-process, compared and never printed): Home's Check a backup opening
 * the open-document picker under the picker rule; a file refused before any byte is read when its name
 * does not end in .age or its provider gives no size or one past core's limit, and after the read when
 * the read fails or runs past the limit (its bytes zeroed); the passphrase's entry behind the privacy
 * gate, eight first-fours on the letter pad, then core's opening behind "Working...": "Backup OK" with
 * the ceremony's fingerprint and the seed's Seal ID; a wrong passphrase, an entry that names no word and
 * a file that does not read refused with core's text, the entry emptied from word 1 and the file kept;
 * the backup's words through the gate equal to the seed's, with no read-back, the last insert's Done
 * back to the result; the re-check QR and Back; Done ending it in core; Back from the entry Home with
 * the file zeroed; leaving the entry discarding at once, and the result under the 60 s rule and the
 * offline rule as a session is; a late answer from the picker doing nothing. Each test leaves the slot
 * at home.
 */
class CheckBackupScreensTest {
    @AfterTest
    fun emptyTheSlot() {
        assertTrue(Core.wipeAll() is Reply.Done)
    }

    private fun assertNoSession(message: String) {
        assertTrue(Core.selfTest() is Reply.Done, message)
    }

    /** A backup saved by a ceremony of its own: the file's bytes, the passphrase's words and the wallet's fingerprint. */
    private class Saved(val file: ByteArray, val passphrase: List<String>, val fingerprint: ByteArray)

    private val saved: Saved get() = shared

    /** A new model at Home, Check a backup's picker opened, and the saved backup picked under its name. */
    private fun picked(name: String = "keepcrypt-backup-0123abcd.age", bytes: ByteArray = saved.file): Pair<Rig, FakeFile> {
        val file = FakeFile(name, bytes.size.toLong(), bytes)
        val rig = Rig().toHome()
        rig.model.checkBackup(FakePickers())
        rig.model.backupPicked(file)
        return rig to file
    }

    /** On the entry: entries typed one after another (each its letters on the pad, then Done). */
    private fun type(rig: Rig, entries: List<String>) {
        for (entry in entries) {
            for (letter in entry) rig.model.backupLetters.type(letter)
            rig.model.entryTyped()
        }
    }

    /** The passphrase's eight entries, as the Pi takes them: each word's first four letters, a three-letter word's three. */
    private fun firstFours(words: List<String>): List<String> = words.map { it.take(4) }

    /** A model at Check a backup's result, the saved backup opened with its passphrase. */
    private fun atResult(): Rig {
        val (rig, _) = picked()
        rig.model.passGate()
        type(rig, firstFours(saved.passphrase))
        rig.worker.run()
        assertEquals(Screen.BackupCheckResult, rig.screen)
        return rig
    }

    @Test
    fun homesCheckABackupOpensTheOpenDocumentPickerUnderThePickerRule() {
        val rig = Rig().toHome()
        rig.model.appReturned()
        val pickers = FakePickers()
        rig.model.checkBackup(pickers)
        assertEquals(1, pickers.opens)
        rig.model.appLeft()
        assertEquals(Screen.Home, rig.screen, "the picker over the app is no leaving")
        assertNull(rig.model.state.value.overlay)
        rig.model.appReturned()
        rig.model.backupPicked(null)
        assertEquals(Screen.Home, rig.screen, "a picker left with no file: Home stays")
        assertNull(rig.model.state.value.fileRefusal)
    }

    @Test
    fun aFileIsRefusedByItsNameOrSizeBeforeAnyByteIsReadAndByItsReadAfter() {
        val rig = Rig().toHome()
        val bytes = saved.file
        val cases = listOf(
            FakeFile("keepcrypt-backup-0123abcd.age.txt", bytes.size.toLong(), bytes) to FileRefusal.NotAge,
            FakeFile("backup.txt", bytes.size.toLong(), bytes) to FileRefusal.NotAge,
            FakeFile("age", bytes.size.toLong(), bytes) to FileRefusal.NotAge,
            FakeFile(null, bytes.size.toLong(), bytes) to FileRefusal.NotAge,
            FakeFile("keepcrypt-backup-0123abcd.age", null, bytes) to FileRefusal.NoSize,
            FakeFile("keepcrypt-backup-0123abcd.age", Core.BACKUP_MAX_BYTES + 1L, bytes) to FileRefusal.TooLarge,
            FakeFile("keepcrypt-backup-0123abcd.age", -1L, bytes) to FileRefusal.TooLarge,
        )
        for ((file, refusal) in cases) {
            rig.model.checkBackup(FakePickers())
            rig.model.backupPicked(file)
            val home = rig.model.state.value
            assertEquals(Screen.Home, home.screen, file.name.toString())
            assertEquals(refusal, home.fileRefusal, file.name.toString())
            assertEquals(0, file.reads, "no byte of a refused file is read: " + file.name)
        }
        assertEquals("That file was not opened: a KeepCrypt backup's name ends in .age.", fileRefusalText(FileRefusal.NotAge))
        // A provider that sized it within the limit and then gave more: refused, its bytes zeroed.
        val liar = FakeFile("keepcrypt-backup-0123abcd.age", 100L, ByteArray(Core.BACKUP_MAX_BYTES + 1) { 1 })
        rig.model.backupPicked(liar)
        assertEquals(FileRefusal.TooLarge, rig.model.state.value.fileRefusal)
        assertEquals(1, liar.reads)
        assertEquals(Core.BACKUP_MAX_BYTES, liar.readLimit)
        assertTrue(zeroed(liar.given), "the bytes past the limit were zeroed")
        val unreadable = FakeFile("keepcrypt-backup-0123abcd.AGE", 100L, null)
        rig.model.backupPicked(unreadable)
        assertEquals(FileRefusal.Unreadable, rig.model.state.value.fileRefusal, "an upper-case .AGE passes the name, then a read that fails")
        assertEquals(Screen.Home, rig.screen)
        rig.model.chooseMode(Mode.Mixed)
        assertEquals(Screen.Length, rig.screen, "Home's other choices stay")
    }

    @Test
    fun eightFirstFoursOpenTheBackupBackupOkWithTheCeremonysFingerprintAndSealId() {
        val (rig, file) = picked()
        assertEquals(1, file.reads)
        assertEquals(Core.BACKUP_MAX_BYTES, file.readLimit)
        val entry = rig.model.state.value
        assertEquals(Screen.BackupCheckEntry, entry.screen)
        assertTrue(isProtected(Screen.BackupCheckEntry))
        assertTrue(entry.gate, "the entry shows through the privacy gate")
        rig.model.passGate()
        val words = firstFours(saved.passphrase)
        for ((index, letters) in words.withIndex()) {
            assertEquals(index, rig.model.state.value.page, "word " + (index + 1) + " of 8")
            // Done does nothing below three letters.
            rig.model.backupLetters.type(letters[0])
            rig.model.backupLetters.type(letters[1])
            rig.model.entryTyped()
            assertEquals(index, rig.model.state.value.page)
            rig.model.backupLetters.wipe()
            for (letter in letters) rig.model.backupLetters.type(letter)
            rig.model.entryTyped()
            assertEquals(0, rig.model.backupLetters.length, "each entry was taken and the pad emptied")
        }
        assertEquals(Screen.Working, rig.screen, "core opens the file behind Working...")
        rig.worker.run()
        val result = rig.model.state.value
        assertEquals(Screen.BackupCheckResult, result.screen)
        assertFalse(isProtected(Screen.BackupCheckResult))
        val opened = assertNotNull(result.opened)
        assertTrue(opened.fingerprint.contentEquals(saved.fingerprint), "the backup's fingerprint is the ceremony's")
        assertEquals(DICE_50_SEAL_ID, opened.seal.sealId)
        assertTrue(zeroed(file.given), "the file read was zeroed once the entry was over")
        rig.model.back()
        assertSame(result, rig.model.state.value, "Back does nothing on the result")
    }

    @Test
    fun aWrongPassphraseAnEntryThatNamesNoWordAndAFileThatDoesNotReadAreRefusedWithCoresText() {
        val (rig, file) = picked()
        rig.model.passGate()
        val right = firstFours(saved.passphrase)
        val other = if (right[0] == "aban") "zoo" else "aban"
        type(rig, listOf(other) + right.drop(1))
        rig.worker.run()
        val wrong = rig.model.state.value
        assertEquals(Screen.BackupCheckEntry, wrong.screen)
        assertEquals(0, wrong.page, "the entry again from word 1")
        assertEquals(Refusal.WrongPassphrase, wrong.entryRefusal)
        assertEquals("the passphrase does not open this backup", backupRefusalText(Refusal.WrongPassphrase))
        assertFalse(zeroed(file.given), "the file is kept for another try")
        type(rig, List(PASSPHRASE_WORDS) { "zzzz" })
        rig.worker.run()
        assertEquals(Refusal.PassphraseWords, rig.model.state.value.entryRefusal, "an entry that names no word")
        type(rig, right)
        rig.worker.run()
        assertEquals(Screen.BackupCheckResult, rig.screen, "the right passphrase after two refusals")
        rig.model.closeBackup()

        val (bad, _) = picked(bytes = "age-encryption.org/v1\nnot a backup\n".encodeToByteArray())
        bad.model.passGate()
        type(bad, right)
        bad.worker.run()
        val refusal = assertNotNull(bad.model.state.value.entryRefusal)
        assertEquals(Screen.BackupCheckEntry, bad.screen)
        assertEquals(RefusalGroup.Backup, refusal.group, "a file that does not read: " + refusal.name)
        assertTrue(backupRefusalText(refusal).orEmpty().startsWith("backup rejected: "))
    }

    @Test
    fun theWordsShowThroughTheGateWithNoReadbackAndTheLastInsertsDoneLeadsBackToTheResult() {
        val rig = atResult()
        val words = kcrWords(DICE_50)
        rig.model.showBackupWords()
        val first = rig.model.state.value
        assertEquals(Screen.Words, first.screen)
        assertTrue(first.gate, "the words show through the privacy gate")
        assertNotNull(first.opened, "the words are the checked backup's")
        rig.model.passGate()
        for (index in words.indices) {
            val insert = assertNotNull(rig.model.state.value.insert)
            assertEquals(index + 1, insert.position)
            assertTrue(sameWord(insert, words[index]), "insert " + (index + 1) + " is the seed's word")
            if (index + 1 < words.size) {
                rig.model.backupWordsDone()
                assertEquals(index, rig.model.state.value.page, "Done is on the last insert only")
                rig.model.nextPage()
            }
        }
        rig.model.startReadback()
        assertEquals(Screen.Words, rig.screen, "a checked backup's words have no read-back")
        rig.model.toOverview()
        assertEquals(Screen.WordsOverview, rig.screen)
        assertNotNull(rig.model.state.value.opened)
        rig.model.toInsertView()
        repeat(words.size - 1) { rig.model.nextPage() }
        val last = assertNotNull(rig.model.state.value.insert)
        rig.model.backupWordsDone()
        val result = rig.model.state.value
        assertEquals(Screen.BackupCheckResult, result.screen)
        assertFalse(result.gate)
        assertTrue(wiped(last), "the last page was wiped")
    }

    @Test
    fun theRecheckQrAndItsBackThenDoneEndsTheCheckInCoreAndReturnsHome() {
        val rig = atResult()
        val opened = assertNotNull(rig.model.state.value.opened)
        rig.model.showRecheck()
        val recheck = rig.model.state.value
        assertEquals(Screen.BackupRecheck, recheck.screen)
        assertFalse(isProtected(Screen.BackupRecheck))
        assertSame(opened, recheck.opened)
        assertTrue(opened.recheck.side >= 21)
        rig.model.back()
        assertEquals(Screen.BackupCheckResult, rig.screen)
        assertSame(opened, rig.model.state.value.opened)
        rig.model.closeBackup()
        assertEquals(Screen.Home, rig.screen)
        assertTrue((0 until opened.recheck.side).none { x -> (0 until opened.recheck.side).any { y -> opened.recheck.isDark(x, y) } }, "the re-check QR was wiped")
        assertNoSession("Done left the checked backup in core")
    }

    @Test
    fun backFromTheEntryGoesHomeWithTheFileZeroedAndTheLettersWiped() {
        val (rig, file) = picked()
        rig.model.passGate()
        type(rig, listOf(firstFours(saved.passphrase)[0]))
        rig.model.backupLetters.type('a')
        rig.model.back()
        assertEquals(Screen.Home, rig.screen)
        assertTrue(zeroed(file.given), "the file read was zeroed")
        assertEquals(0, rig.model.backupLetters.length)
        assertTrue(rig.model.backupLetters.zeroPastLength())
        assertNoSession("Back from the entry left something in core")
    }

    @Test
    fun leavingTheEntryDiscardsAtOnceAndTheResultIsHeldUnderTheTimersAndTheOfflineRule() {
        val (rig, file) = picked()
        rig.model.appReturned()
        rig.model.passGate()
        rig.model.appLeft()
        assertEquals(Screen.GoOffline, rig.screen)
        assertEquals(Notice.Left, rig.model.state.value.notice)
        assertTrue(zeroed(file.given), "the file read was zeroed")

        val away = atResult()
        away.model.appReturned()
        away.model.appLeft()
        assertEquals(Screen.BackupCheckResult, away.screen, "the result is Public: covered, not discarded")
        assertEquals(Overlay.Cover, away.model.state.value.overlay)
        away.clock.now += Timers.BACKGROUND_MILLIS
        away.model.tick()
        assertEquals(Screen.GoOffline, away.screen)
        assertEquals(Notice.Background, away.model.state.value.notice)
        assertNoSession("60 s away left the checked backup in core")

        val online = atResult()
        online.model.appReturned()
        online.offline.set(false)
        assertEquals(Screen.GoOffline, online.screen)
        assertEquals(Notice.Offline, online.model.state.value.notice)
        assertNoSession("going online left the checked backup in core")
    }

    @Test
    fun aLateFileFromThePickerDoesNothing() {
        val rig = Rig().toHome()
        rig.model.checkBackup(FakePickers())
        rig.model.chooseMode(Mode.DiceOnly)
        val file = FakeFile("keepcrypt-backup-0123abcd.age", 10L, ByteArray(10))
        rig.model.backupPicked(file)
        assertEquals(Screen.Length, rig.screen)
        assertEquals(0, file.reads, "a file that comes after Home has gone is never read")
    }

    private companion object {
        const val DICE_50 = "dice-50-words12"

        /** kcr.json's dice-50-words12's Seal ID (a public gate-seed vector). */
        const val DICE_50_SEAL_ID = "YVM9CPP3"

        /**
         * The backup the class's tests open, saved once in this JVM (the class's one process) by a ceremony
         * of the first test that asks, which then ends it (Finish), so the slot is at home again.
         */
        val shared: Saved by lazy {
            val rig = Rig().toHome().toSummary(DICE_50)
            val fingerprint = assertNotNull(rig.model.state.value.summary).fingerprint.copyOf()
            val passphrase = rig.toConfirm()
            rig.confirm(passphrase)
            val place = FakePlace()
            rig.model.saveBackup(FakePickers())
            rig.model.backupPlaced(place)
            rig.worker.run()
            assertEquals(Screen.BackupVerified, rig.screen)
            rig.model.backupVerifiedDone()
            rig.model.finishCeremony()
            Saved(assertNotNull(place.saved), passphrase, fingerprint)
        }
    }
}
