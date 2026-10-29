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
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel

/**
 * The CeremonyModel transitions of Check a backup (tasks/todo.md, M5 group 18; lead decision M5-48;
 * docs/mobile-apps.md, "Checking a backup"; the Pi's Home flow), over the real slot through Core and the
 * host library, on a backup the test's own ceremony saved (vectors/kcr.json's dice-50-words12, its
 * passphrase read from the screen in-process, compared and never printed): Home's Check a backup opening
 * the open-document picker under the picker rule; a file refused before any byte is read when its name
 * does not end in .age or its provider gives no size or one past core's limit, and after the read when
 * the read fails or runs past the limit (its bytes zeroed); the read on the worker behind "Working..."
 * (lead decision M5-70 (g)): a slow read holding no input and no second file, a leave or going online
 * during it, or after it but before the main thread takes its reply, zeroing what it read with no entry
 * shown, the holder's end in that gap zeroing it too, and a file longer or shorter than its provider
 * reports read whole and opened; the passphrase's entry behind the privacy
 * gate, eight first-fours on the letter pad, then core's opening behind "Working...": "Backup OK" with
 * the ceremony's fingerprint and the seed's Seal ID; a wrong passphrase, an entry that names no word and
 * a file that does not read refused with core's text, the entry emptied from word 1 and the file kept;
 * the backup's words through the gate equal to the seed's, with no read-back, the last insert's Done
 * back to the result; the re-check QR and Back; Done ending it in core; Back from the entry Home with
 * the file zeroed; leaving the entry discarding at once, and the result under the 60 s rule and the
 * offline rule as a session is; a checked backup so discarded leaving the next ceremony's words their
 * own, with their read-back; a late answer from the picker doing nothing; and wipeAll on the entry (its
 * entries, file and letters) and on the result (the re-check QR). Each test leaves the slot at home.
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

    /**
     * A new model at Home, Check a backup's picker opened, and the saved backup picked under its name (its
     * provider reporting size), its read on the worker run.
     */
    private fun picked(
        name: String = "keepcrypt-backup-0123abcd.age",
        bytes: ByteArray = saved.file,
        size: Long = bytes.size.toLong(),
    ): Pair<Rig, FakeFile> {
        val file = FakeFile(name, size, bytes)
        val rig = Rig().toHome()
        rig.model.checkBackup(FakePickers())
        rig.model.backupPicked(file)
        rig.worker.run()
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
            assertEquals(0, rig.worker.waiting, "no read waits on the worker: " + file.name)
        }
        assertEquals("That file was not opened: a KeepCrypt backup's name ends in .age.", fileRefusalText(FileRefusal.NotAge))
        // A provider that sized it within the limit and then gave more: refused, its bytes zeroed.
        val liar = FakeFile("keepcrypt-backup-0123abcd.age", 100L, ByteArray(Core.BACKUP_MAX_BYTES + 1) { 1 })
        rig.model.backupPicked(liar)
        rig.worker.run()
        assertEquals(FileRefusal.TooLarge, rig.model.state.value.fileRefusal)
        assertEquals(1, liar.reads)
        assertEquals(Core.BACKUP_MAX_BYTES, liar.readLimit)
        assertTrue(zeroed(liar.given), "the bytes past the limit were zeroed")
        val unreadable = FakeFile("keepcrypt-backup-0123abcd.AGE", 100L, null)
        rig.model.backupPicked(unreadable)
        rig.worker.run()
        assertEquals(FileRefusal.Unreadable, rig.model.state.value.fileRefusal, "an upper-case .AGE passes the name, then a read that fails")
        assertEquals(Screen.Home, rig.screen)
        rig.model.chooseMode(Mode.Mixed)
        assertEquals(Screen.Length, rig.screen, "Home's other choices stay")
    }

    /**
     * A picked backup is read on the worker behind "Working...", never on the main thread (lead decision
     * M5-70 (g)): while a slow read lasts, Home's choices and a second file do nothing; a leave or going
     * online during it (the picker over and the app back, as on the phone) zeroes what it read, shows no
     * entry and ends on the start screen saying why, as any long call's discard does.
     */
    @Test
    fun theReadRunsOnTheWorkerAndADiscardDuringItZeroesWhatItReadAndShowsNoEntry() {
        val bytes = saved.file
        val rig = Rig().toHome()
        var during: Screen? = null
        val slow = FakeFile(NAME, bytes.size.toLong(), bytes) { during = rig.screen }
        rig.model.checkBackup(FakePickers())
        rig.model.backupPicked(slow)
        assertEquals(Screen.Working, rig.screen, "the file is read behind Working...")
        assertEquals(0, slow.reads, "the main thread returned before any byte was read")
        assertEquals(1, rig.worker.waiting, "the read waits on the worker")
        rig.model.chooseMode(Mode.Mixed)
        val second = FakeFile(NAME, bytes.size.toLong(), bytes)
        rig.model.backupPicked(second)
        assertEquals(Screen.Working, rig.screen, "Home's choices do nothing while the read runs")
        assertEquals(0, second.reads, "a second file picked while the read runs is never read")
        rig.worker.run()
        assertEquals(Screen.Working, during, "the read ran while Working... showed")
        assertEquals(1, slow.reads)
        assertEquals(Screen.BackupCheckEntry, rig.screen)
        assertTrue(rig.model.state.value.gate, "the entry shows through the privacy gate")
        assertFalse(zeroed(slow.given), "the bytes read are kept for core")

        val discards = listOf(
            Notice.Left to { away: Rig -> away.model.appLeft() },
            Notice.Offline to { away: Rig -> away.offline.set(false) },
        )
        for ((notice, discard) in discards) {
            val away = Rig().toHome()
            val file = FakeFile(NAME, bytes.size.toLong(), bytes) { discard(away) }
            away.model.checkBackup(FakePickers())
            away.model.appLeft()
            away.model.appReturned()
            away.model.backupPicked(file)
            away.worker.run()
            assertEquals(1, file.reads, notice.name)
            assertTrue(zeroed(file.given), notice.name + ": what the read gave was zeroed")
            assertEquals(Screen.GoOffline, away.screen, notice.name + ": no entry, the start screen")
            assertEquals(notice, away.model.state.value.notice)
            assertNoSession(notice.name + ": a discard during the read left something in core")
        }
    }

    /**
     * A model at Home over a main thread the test holds, Check a backup's picker opened and closed (the
     * app back, as on the phone), and file picked; its read made on the worker and its reply kept for the
     * main thread, which has not run it.
     */
    private fun readReplyWaiting(main: HeldMain, scope: CoroutineScope, file: FakeFile): Rig {
        val rig = Rig(scope).toHome()
        rig.model.checkBackup(FakePickers())
        rig.model.appLeft()
        rig.model.appReturned()
        main.holding = true
        rig.model.backupPicked(file)
        main.run()
        assertEquals(1, rig.worker.waiting, "the read waits on the worker")
        rig.worker.runNext()
        assertEquals(1, file.reads)
        assertEquals(1, main.waiting, "the read's reply waits for the main thread")
        assertEquals(Screen.Working, rig.screen)
        assertFalse(zeroed(file.given), "the bytes read wait for the main thread")
        return rig
    }

    /**
     * A leave or going online after the worker's second look found no discard, before the main thread
     * takes the read's reply: the main thread finds the discard and zeroes what the read gave, shows no
     * entry and ends on the start screen saying why (the main thread's drop, work).
     */
    @Test
    fun aDiscardAfterTheWorkersSecondLookIsFoundOnTheMainThreadAndZeroesWhatItRead() {
        val bytes = saved.file
        val discards = listOf(
            Notice.Left to { away: Rig -> away.model.appLeft() },
            Notice.Offline to { away: Rig -> away.offline.set(false) },
        )
        for ((notice, discard) in discards) {
            val main = HeldMain()
            val file = FakeFile(NAME, bytes.size.toLong(), bytes)
            val rig = readReplyWaiting(main, CoroutineScope(Job() + main), file)
            discard(rig)
            assertEquals(Screen.Working, rig.screen, notice.name + ": the reply is still to come")
            main.run()
            assertTrue(zeroed(file.given), notice.name + ": what the read gave was zeroed")
            assertEquals(Screen.GoOffline, rig.screen, notice.name + ": no entry, the start screen")
            assertEquals(notice, rig.model.state.value.notice)
            assertNoSession(notice.name + ": a discard after the read left something in core")
        }
    }

    /**
     * The holder's end (CeremonyHolder.onCleared: the scope cancelled, then wipeAll) after the worker's
     * second look, before the main thread takes the read's reply: the main thread's part is cancelled,
     * and its cancellation zeroes what the read gave.
     */
    @Test
    fun theHoldersEndAfterTheWorkersSecondLookZeroesWhatItRead() {
        val bytes = saved.file
        val main = HeldMain()
        val scope = CoroutineScope(Job() + main)
        val file = FakeFile(NAME, bytes.size.toLong(), bytes)
        val rig = readReplyWaiting(main, scope, file)
        scope.cancel()
        rig.model.wipeAll()
        main.run()
        assertTrue(zeroed(file.given), "what the read gave was zeroed")
        assertNoSession("the holder's end left something in core")
    }

    /**
     * A file its provider sized wrongly but within core's limit (longer than reported, or shorter) is read
     * whole on the worker, so it opens; the read's buffer itself is Documents.kt's (ReadUpToTest).
     */
    @Test
    fun aFileLongerOrShorterThanItsProviderReportsIsReadWholeAndOpens() {
        for ((what, size) in listOf("longer than reported" to 10L, "shorter than reported" to saved.file.size + 1000L)) {
            val (rig, file) = picked(size = size)
            assertEquals(Screen.BackupCheckEntry, rig.screen, what)
            rig.model.passGate()
            type(rig, firstFours(saved.passphrase))
            rig.worker.run()
            assertEquals(Screen.BackupCheckResult, rig.screen, what)
            assertEquals(DICE_50_SEAL_ID, assertNotNull(rig.model.state.value.opened, what).seal.sealId, what)
            assertTrue(zeroed(file.given), what + ": the file read was zeroed once the entry was over")
            rig.model.closeBackup()
        }
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

    /**
     * A checked backup discarded on its result (60 s away, going online) or on its words (leaving them) leaves
     * nothing of it in the model: the next ceremony's words, from Go offline's Start, are its own (no opened
     * backup marks them), the backup's Done does nothing on its last insert, and its read-back starts there, so
     * the mandatory read-back is not skipped.
     */
    @Test
    fun aDiscardedCheckedBackupLeavesTheNextCeremonysWordsTheirOwnWithTheirReadback() {
        val away = atResult()
        away.model.appReturned()
        away.model.appLeft()
        away.clock.now += Timers.BACKGROUND_MILLIS
        away.model.tick()
        assertEquals(Screen.GoOffline, away.screen)
        away.model.appReturned()
        away.model.dismissOverlay()
        assertTheNextCeremonysWordsAreTheirOwn(away, "60 s away")

        val online = atResult()
        online.model.appReturned()
        online.offline.set(false)
        assertEquals(Screen.GoOffline, online.screen)
        online.offline.set(true)
        assertTheNextCeremonysWordsAreTheirOwn(online, "going online")

        val left = atResult()
        left.model.appReturned()
        left.model.showBackupWords()
        left.model.passGate()
        assertNotNull(left.model.state.value.opened)
        left.model.appLeft()
        assertEquals(Screen.GoOffline, left.screen)
        assertEquals(Notice.Left, left.model.state.value.notice)
        left.model.appReturned()
        left.model.dismissOverlay()
        assertTheNextCeremonysWordsAreTheirOwn(left, "leaving the backup's words")
    }

    /**
     * After a discard, from Go offline: Start, dice-50-words12 by Skip to its words, which no checked backup marks,
     * to the last insert's read-back, then a leave, which discards it (the next model's start finds the slot at home).
     */
    private fun assertTheNextCeremonysWordsAreTheirOwn(rig: Rig, discard: String) {
        rig.model.startOffline()
        assertEquals(Screen.Home, rig.screen, discard)
        rig.toSkippedResult(DICE_50).toWords()
        assertNull(rig.model.state.value.opened, "after " + discard + ", the ceremony's words are marked as a checked backup's")
        repeat(INSERTS_PER_DEVICE - 1) { rig.model.nextPage() }
        val last = rig.model.state.value
        assertEquals(Screen.Words, last.screen)
        assertNull(last.opened, "after " + discard + ", the ceremony's last insert is marked as a checked backup's")
        rig.model.backupWordsDone()
        assertSame(last, rig.model.state.value, "the backup's Done on a ceremony's last insert, after " + discard)
        rig.model.startReadback()
        assertEquals(Screen.ReadbackEntry, rig.screen, "after " + discard + ", the ceremony's read-back does not start")
        rig.model.appLeft()
        assertNoSession("leaving the read-back left the ceremony in core")
    }

    @Test
    fun wipeAllWipesTheEntryItsEntriesAndItsFileAndTheCheckedBackupsRecheckQr() {
        val (rig, file) = picked()
        rig.model.passGate()
        type(rig, firstFours(saved.passphrase).take(3))
        rig.model.backupLetters.type('a')
        val entries = rig.model.entriesHeld
        assertEquals(3, entries.size)
        rig.model.wipeAll()
        assertTrue(entries.all { entry -> (0 until entry.size).all { entry[it] == 0.toByte() } }, "wipeAll wiped the entries typed")
        assertTrue(rig.model.entriesHeld.isEmpty(), "wipeAll dropped the entries")
        assertTrue(zeroed(file.given), "wipeAll zeroed the file read")
        assertEquals(0, rig.model.backupLetters.length, "wipeAll wiped the letters typed")
        assertTrue(rig.model.backupLetters.zeroPastLength())
        assertNoSession("wipeAll left something in core")

        val result = atResult()
        val recheck = assertNotNull(result.model.state.value.opened).recheck
        result.model.wipeAll()
        assertTrue((0 until recheck.side).none { x -> (0 until recheck.side).any { y -> recheck.isDark(x, y) } }, "wipeAll wiped the re-check QR")
        assertNoSession("wipeAll left the checked backup in core")
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

        /** A backup's name as core suggests them. */
        const val NAME = "keepcrypt-backup-0123abcd.age"

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
            rig.skipExports()
            rig.model.finishCeremony()
            Saved(assertNotNull(place.saved), passphrase, fingerprint)
        }
    }
}
