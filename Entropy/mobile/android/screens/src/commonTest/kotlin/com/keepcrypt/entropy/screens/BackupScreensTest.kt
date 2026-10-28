package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Question
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
 * The CeremonyModel transitions of the encrypted backup (tasks/todo.md, M5 group 18; docs/mobile-apps.md,
 * "Encrypted backup only" and step 13; the Pi's step 11), over the real slot through Core and the host
 * library, for vectors/kcr.json's dice-50-words12 read back to its wallet summary: the summary's Next to
 * the offer, whose Skip goes on to the watch-only offer (commit 21); "Make an encrypted backup" generating the passphrase, its
 * two pages of four behind the privacy gate, paged and their copies wiped; the confirm on the letter pad,
 * each answer matched to one of core's four choices by its first four letters, a wrong one (no choice, three
 * letters of a longer word, or the wrong choice) showing the passphrase again with the same questions, both right encrypting the
 * backup behind "Working..." to the save screen with core's suggested name; Save opening the
 * create-document picker under the picker rule, the place written once, read back at most one byte past
 * core's limit and verified by core before "Backup verified", whose Next is the watch-only offer, the bytes
 * read back and the file zeroed afterwards, and no word of the seed in the file; a failed write, read-back or verify naming its step,
 * the session kept, and Save again; a cancelled picker; leaving the app on the passphrase or the confirm
 * discarding at once with their Secrets wiped, going online on the save screen discarding and zeroing
 * the file, a late place doing nothing; a discard during the encryption; and wipeAll. The passphrase is
 * read from the screen's state in-process, compared and never printed. Each test leaves the slot at home.
 */
class BackupScreensTest {
    @AfterTest
    fun emptyTheSlot() {
        assertTrue(Core.wipeAll() is Reply.Done)
    }

    private fun assertNoSession(message: String) {
        assertTrue(Core.selfTest() is Reply.Done, message)
    }

    /** A new model at dice-50-words12's wallet summary. */
    private fun atSummary(): Rig {
        val rig = Rig().toHome().toSummary(DICE_50)
        assertEquals(Screen.Wallet, rig.screen)
        return rig
    }

    /** A new model at the save screen, the passphrase's words returned with it. */
    private fun atSave(): Pair<Rig, List<String>> {
        val rig = atSummary()
        val passphrase = rig.toConfirm()
        rig.confirm(passphrase)
        assertEquals(Screen.BackupSave, rig.screen)
        return rig to passphrase
    }

    @Test
    fun theSummaryLeadsToTheOfferWhoseSkipGoesToTheWatchOnlyOfferWithNoPassphrase() {
        val rig = atSummary()
        rig.model.summaryDone()
        val offer = rig.model.state.value
        assertEquals(Screen.BackupOffer, offer.screen)
        assertFalse(isProtected(Screen.BackupOffer))
        assertFalse(offer.gate)
        rig.model.back()
        assertSame(offer, rig.model.state.value, "Back does nothing on the offer")
        rig.model.skipBackup()
        assertEquals(Screen.WatchOffer, rig.screen, "Skip goes on to the other exports (the Pi's step 12)")
        // No passphrase was generated: core still offers its generation (a second would halt).
        assertTrue(Core.generateBackupPassphrase() is Reply.Done)
        rig.skipExports()
        rig.model.finishCeremony()
        assertEquals(Screen.Home, rig.screen)
        assertNoSession("Finish after Skip ended the session")
    }

    @Test
    fun theOffersMakeShowsThePassphraseBehindTheGateTwoPagesOfFourEachWipedWhenItGoes() {
        val rig = atSummary()
        rig.model.summaryDone()
        rig.model.makeBackup()
        val first = rig.model.state.value
        assertEquals(Screen.BackupPassphrase, first.screen)
        assertTrue(isProtected(Screen.BackupPassphrase))
        assertTrue(first.gate, "the passphrase shows through the privacy gate")
        assertFalse(first.wrongConfirm)
        rig.model.makeBackup()
        assertSame(first, rig.model.state.value, "a second Make (the gate up) does nothing")
        rig.model.passGate()
        val page0 = assertNotNull(rig.model.state.value.passphrase)
        val lines = passphraseLines(0, page0)
        assertEquals(PASSPHRASE_PAGE_WORDS, lines.size)
        for ((index, line) in lines.withIndex()) {
            assertTrue(Regex("^" + (index + 1) + " [a-z]{3,8}$").matches(line), "line " + (index + 1) + " is its number and a word")
        }
        rig.model.passphraseWritten()
        assertEquals(Screen.BackupPassphrase, rig.screen, "I wrote it down is on the second page only")
        rig.model.previousPage()
        assertSame(page0, rig.model.state.value.passphrase, "no page before the first")
        rig.model.nextPage()
        val second = rig.model.state.value
        assertEquals(1, second.page)
        assertFalse(second.gate, "Protected to Protected: no gate")
        assertTrue(zeroed(ByteArray(page0.size) { page0[it] }), "the first page's copy was wiped")
        val page1 = assertNotNull(second.passphrase)
        assertTrue(passphraseLines(1, page1).withIndex().all { (i, line) -> line.startsWith((i + 5).toString() + " ") })
        rig.model.nextPage()
        assertSame(second, rig.model.state.value, "no page after the second")
        rig.model.back()
        assertEquals(0, rig.model.state.value.page, "Back is Previous on the passphrase")
        assertTrue(zeroed(ByteArray(page1.size) { page1[it] }), "the second page's copy was wiped")
        rig.model.nextPage()
        rig.model.passphraseWritten()
        val confirm = rig.model.state.value
        assertEquals(Screen.BackupConfirm, confirm.screen)
        assertTrue(isProtected(Screen.BackupConfirm))
        assertFalse(confirm.gate)
        assertNull(confirm.passphrase)
        assertEquals(0, confirm.page)
        val questions = assertNotNull(confirm.challenge).questions
        assertEquals(2, questions.size)
        for (question in questions) {
            assertTrue(question.position in 1..PASSPHRASE_WORDS)
            assertEquals(4, question.choices.size)
        }
    }

    @Test
    fun theConfirmMatchesEachAnswersFirstFourLettersToAChoiceAndBothRightEncryptsInMemoryToTheSave() {
        val rig = atSummary()
        val summary = assertNotNull(rig.model.state.value.summary)
        val passphrase = rig.toConfirm()
        assertEquals(PASSPHRASE_WORDS, passphrase.size)
        val challenge = assertNotNull(rig.model.state.value.challenge)
        val question = challenge.questions[0]
        val word = passphrase[question.position - 1]
        // Done below three letters does nothing, and the letters stay.
        for (letter in word.take(2)) rig.model.backupLetters.type(letter)
        rig.model.confirmTyped()
        assertEquals(2, rig.model.backupLetters.length)
        assertEquals(0, rig.model.state.value.page)
        rig.model.backupLetters.wipe()
        rig.answer(word)
        val second = rig.model.state.value
        assertEquals(Screen.BackupConfirm, second.screen)
        assertEquals(1, second.page)
        assertSame(challenge, second.challenge, "the same questions")
        assertEquals(0, rig.model.backupLetters.length, "the first answer's letters were handed over and wiped")
        assertTrue(rig.model.backupLetters.zeroPastLength())
        rig.answer(passphrase[challenge.questions[1].position - 1])
        assertEquals(Screen.Working, rig.screen, "the encryption runs behind Working...")
        assertEquals(1, rig.worker.waiting)
        rig.worker.run()
        val save = rig.model.state.value
        assertEquals(Screen.BackupSave, save.screen)
        assertFalse(isProtected(Screen.BackupSave))
        val name = assertNotNull(save.backupName)
        assertTrue(Regex("^keepcrypt-backup-[0-9a-f]{8}\\.age$").matches(name), "core's suggested name")
        assertNull(save.challenge)
        assertTrue(challenge.questions.all { q -> q.choices.all { c -> (0 until c.size).all { c[it] == 0.toByte() } } }, "the choices were wiped")
        rig.model.back()
        assertEquals(Screen.BackupSave, rig.screen, "Back does nothing on the save screen")
        val held = Core.summary()
        assertTrue(held is Reply.Done && held.value.firstAddress == summary.firstAddress, "the session is still held")
    }

    @Test
    fun aWrongAnswerShowsThePassphraseAgainFromItsFirstPageWithTheSameQuestions() {
        val rig = atSummary()
        val passphrase = rig.toConfirm()
        val challenge = assertNotNull(rig.model.state.value.challenge)
        val positions = challenge.questions.map { it.position }
        // Three letters of a choice of four or more (no three-letter choice spelled so) are no choice: a word of four
        // or more is matched by its first four letters alone, so the answer is wrong at once (on the first question
        // with such a choice; the first is answered right to reach the second).
        val at = challenge.questions.indexOfFirst { longerChoice(it) != null }
        if (at == 1) rig.answer(passphrase[challenge.questions[0].position - 1])
        for (letter in checkNotNull(longerChoice(challenge.questions[at])).take(3)) rig.model.backupLetters.type(letter)
        rig.model.confirmTyped()
        assertEquals(Screen.BackupPassphrase, rig.screen, "three letters of a longer word are no choice")
        assertTrue(rig.model.state.value.wrongConfirm)
        rig.model.nextPage()
        rig.model.passphraseWritten()
        // An answer that is none of the four choices: wrong at once, with no call to core.
        rig.answer("zzzz")
        val again = rig.model.state.value
        assertEquals(Screen.BackupPassphrase, again.screen)
        assertEquals(0, again.page)
        assertTrue(again.wrongConfirm, "the passphrase says the answer was wrong")
        assertFalse(again.gate, "Protected to Protected: no gate")
        rig.model.nextPage()
        assertFalse(rig.model.state.value.wrongConfirm, "the note is on the first page")
        rig.model.passphraseWritten()
        val asked = assertNotNull(rig.model.state.value.challenge)
        assertEquals(positions, asked.questions.map { it.position }, "the questions stay the same")
        // The first right, the second another of its four choices: core says wrong.
        rig.answer(passphrase[asked.questions[0].position - 1])
        val second = asked.questions[1]
        val right = passphrase[second.position - 1]
        val wrong = second.choices.map { choiceText(it) }.first { it.take(4) != right.take(4) }
        rig.answer(wrong)
        assertEquals(Screen.BackupPassphrase, rig.screen)
        assertTrue(rig.model.state.value.wrongConfirm)
        rig.model.nextPage()
        rig.model.passphraseWritten()
        assertEquals(positions, assertNotNull(rig.model.state.value.challenge).questions.map { it.position })
        rig.confirm(passphrase)
        assertEquals(Screen.BackupSave, rig.screen, "both right after two wrong tries")
    }

    @Test
    fun saveWritesTheFileOnceReadsItBackAndCoreVerifiesItBeforeBackupVerified() {
        val (rig, passphrase) = atSave()
        val name = assertNotNull(rig.model.state.value.backupName)
        val pickers = FakePickers()
        rig.model.saveBackup(pickers)
        assertEquals(listOf(name), pickers.created, "the create-document picker with core's suggested name")
        // The picker over the app stops it without leaving it (the picker rule).
        rig.model.appLeft()
        assertEquals(Screen.BackupSave, rig.screen)
        assertNull(rig.model.state.value.overlay)
        rig.model.appReturned()
        val place = FakePlace()
        rig.model.backupPlaced(place)
        assertEquals(1, place.writeCalls, "one write")
        assertEquals(1, place.readCalls, "one read-back")
        assertEquals(Core.BACKUP_MAX_BYTES, place.readLimit)
        assertEquals(Screen.Working, rig.screen, "core verifies it behind Working...")
        rig.worker.run()
        assertEquals(Screen.BackupVerified, rig.screen)
        assertTrue(zeroed(place.given), "the bytes read back were zeroed once core had them")
        val saved = assertNotNull(place.saved)
        val text = saved.decodeToString()
        assertTrue(text.startsWith("-----BEGIN AGE ENCRYPTED FILE-----") || text.startsWith("age-encryption.org/v1"), "an age file")
        assertTrue((kcrWords(DICE_50) + passphrase).none { text.contains(it) }, "no word of the seed or the passphrase in the file")
        rig.model.backupVerifiedDone()
        assertEquals(Screen.WatchOffer, rig.screen, "Backup verified's Next is the watch-only offer")
        assertTrue(zeroed(place.handed), "the encrypted file was zeroed once the save was over")
        rig.skipExports()
        rig.model.finishCeremony()
        assertEquals(Screen.Home, rig.screen)
        assertNoSession("Finish after the backup ended the session")
    }

    @Test
    fun aFailedWriteReadBackOrVerifyNamesItsStepTheSessionStaysAndSaveAgainSaves() {
        val (rig, _) = atSave()
        val name = assertNotNull(rig.model.state.value.backupName)
        val pickers = FakePickers()
        rig.model.saveBackup(pickers)
        rig.model.backupPlaced(null)
        assertEquals(Screen.BackupSave, rig.screen, "a picker left with no place: the save screen stays")
        assertNull(rig.model.state.value.saveFailure)
        rig.model.saveBackup(pickers)
        rig.model.backupPlaced(FakePlace(writes = false))
        val write = rig.model.state.value
        assertEquals(Screen.BackupSave, write.screen)
        assertEquals(SaveStep.Write, assertNotNull(write.saveFailure).step)
        assertEquals("Backup not saved: writing the file failed.", saveFailureText(assertNotNull(write.saveFailure)))
        assertEquals(name, write.backupName)
        rig.model.saveBackup(pickers)
        rig.model.backupPlaced(FakePlace(reads = { null }))
        assertEquals(SaveStep.ReadBack, assertNotNull(rig.model.state.value.saveFailure).step)
        rig.model.saveBackup(pickers)
        val changed = FakePlace(reads = { bytes -> bytes.also { it[it.size / 2] = (it[it.size / 2] + 1).toByte() } })
        rig.model.backupPlaced(changed)
        rig.worker.run()
        val verify = assertNotNull(rig.model.state.value.saveFailure)
        assertEquals(Screen.BackupSave, rig.screen)
        assertEquals(SaveStep.Verify, verify.step)
        val refusal = assertNotNull(verify.refusal)
        assertTrue(isBackupRefusal(refusal), "core refused the changed file as a backup that does not read")
        assertEquals("Backup not saved: the file read back does not verify (" + backupRefusalText(refusal) + ").", saveFailureText(verify))
        assertTrue(zeroed(changed.given), "the refused bytes were zeroed too")
        assertEquals(4, pickers.created.size, "each Save again opened the picker")
        rig.model.saveBackup(pickers)
        rig.model.backupPlaced(FakePlace())
        rig.worker.run()
        assertEquals(Screen.BackupVerified, rig.screen, "Save again saved")
    }

    @Test
    fun skipOnTheSaveScreenGoesToTheWatchOnlyOfferAndZeroesTheFile() {
        val (rig, _) = atSave()
        val place = FakePlace(writes = false)
        rig.model.saveBackup(FakePickers())
        rig.model.backupPlaced(place)
        rig.model.skipBackup()
        assertEquals(Screen.WatchOffer, rig.screen)
        assertTrue(zeroed(place.handed), "the encrypted file was zeroed")
        rig.model.backupPlaced(FakePlace())
        assertEquals(Screen.WatchOffer, rig.screen, "a late place does nothing")
    }

    @Test
    fun leavingTheAppOnThePassphraseOrTheConfirmDiscardsAtOnceWithTheirSecretsWiped() {
        val rig = atSummary()
        rig.model.appReturned()
        rig.model.summaryDone()
        rig.model.makeBackup()
        rig.model.passGate()
        val page = assertNotNull(rig.model.state.value.passphrase)
        rig.model.appLeft()
        assertEquals(Screen.GoOffline, rig.screen)
        assertEquals(Notice.Left, rig.model.state.value.notice)
        assertTrue(zeroed(ByteArray(page.size) { page[it] }), "the page was wiped")
        assertNoSession("leaving the passphrase did not discard")
        rig.model.appReturned()

        val again = Rig().toHome().toSummary(DICE_50)
        again.model.appReturned()
        val passphrase = again.toConfirm()
        val challenge = assertNotNull(again.model.state.value.challenge)
        for (letter in passphrase[challenge.questions[0].position - 1].take(2)) again.model.backupLetters.type(letter)
        again.model.appLeft()
        assertEquals(Screen.GoOffline, again.screen)
        assertEquals(Notice.Left, again.model.state.value.notice)
        assertEquals(0, again.model.backupLetters.length, "the letters were wiped")
        assertTrue(again.model.backupLetters.zeroPastLength())
        assertTrue(challenge.questions.all { q -> q.choices.all { c -> (0 until c.size).all { c[it] == 0.toByte() } } }, "the choices were wiped")
        assertNoSession("leaving the confirm did not discard")
    }

    @Test
    fun goingOnlineOnTheSaveScreenDiscardsZeroesTheFileAndALatePlaceDoesNothing() {
        val (rig, _) = atSave()
        rig.model.appReturned()
        val first = FakePlace(writes = false)
        rig.model.saveBackup(FakePickers())
        rig.model.backupPlaced(first)
        rig.offline.set(false)
        assertEquals(Screen.GoOffline, rig.screen)
        assertEquals(Notice.Offline, rig.model.state.value.notice)
        assertTrue(zeroed(first.handed), "the encrypted file was zeroed")
        val late = FakePlace()
        rig.model.backupPlaced(late)
        assertEquals(0, late.writeCalls, "a place after the discard is never written")
        assertNoSession("going online did not discard")
    }

    @Test
    fun aDiscardDuringTheEncryptionReturnsToTheStartScreen() {
        val rig = atSummary()
        rig.model.appReturned()
        val passphrase = rig.toConfirm()
        repeat(2) {
            val state = rig.model.state.value
            rig.answer(passphrase[assertNotNull(state.challenge).questions[state.page].position - 1])
        }
        assertEquals(Screen.Working, rig.screen)
        rig.model.appLeft()
        rig.worker.run()
        assertEquals(Screen.GoOffline, rig.screen)
        assertEquals(Notice.Left, rig.model.state.value.notice)
        assertNoSession("the discard during the encryption left a session")
    }

    @Test
    fun wipeAllWipesThePassphrasesPageTheConfirmsChoicesAndTheLettersTyped() {
        val rig = atSummary()
        rig.model.summaryDone()
        rig.model.makeBackup()
        rig.model.passGate()
        val page = assertNotNull(rig.model.state.value.passphrase)
        rig.model.wipeAll()
        assertTrue(zeroed(ByteArray(page.size) { page[it] }), "wipeAll wiped the passphrase's page")
        assertNoSession("wipeAll left a session")

        val again = atSummary()
        val passphrase = again.toConfirm()
        val challenge = assertNotNull(again.model.state.value.challenge)
        for (letter in passphrase[challenge.questions[0].position - 1].take(2)) again.model.backupLetters.type(letter)
        again.model.wipeAll()
        assertTrue(challenge.questions.all { q -> q.choices.all { c -> (0 until c.size).all { c[it] == 0.toByte() } } }, "wipeAll wiped the choices")
        assertEquals(0, again.model.backupLetters.length, "wipeAll wiped the letters typed")
        assertTrue(again.model.backupLetters.zeroPastLength())
        assertNoSession("wipeAll left a session")
    }

    @Test
    fun wipeAllOnTheSaveScreenZeroesTheFile() {
        val (rig, _) = atSave()
        val place = FakePlace(writes = false)
        rig.model.saveBackup(FakePickers())
        rig.model.backupPlaced(place)
        rig.model.wipeAll()
        assertTrue(zeroed(place.handed), "wipeAll zeroed the encrypted file")
        assertNoSession("wipeAll left a session")
    }

    /**
     * The backup screens' refusal texts are core's Display texts (core/src/error.rs's #[error(...)]
     * attribute over each variant, which thiserror prints), so the phone shows core's text verbatim as
     * the Pi does: the passphrase that does not open the file, the file that holds another seed, and
     * "backup rejected: " (CoreError::Backup's) before each BackupError's; every other refusal has none.
     */
    @Test
    fun theRefusalTextsAreCoresOwn() {
        val source = entropyFile("core/src/error.rs")
        fun text(variant: String): String {
            val found = Regex("#\\[error\\(\"([^\"]*)\"\\)\\]\\s*" + Regex.escape(variant) + "[,(]").findAll(source).toList()
            assertEquals(1, found.size, "core/src/error.rs's " + variant)
            return found[0].groupValues[1]
        }
        assertEquals(text("WrongPassphrase"), backupRefusalText(Refusal.WrongPassphrase))
        assertEquals(text("ReadbackMismatch"), backupRefusalText(Refusal.ReadbackMismatch))
        val backup = text("Backup")
        assertEquals("backup rejected: {0}", backup)
        for (refusal in Refusal.entries) {
            val shown = backupRefusalText(refusal)
            when {
                refusal.group == RefusalGroup.Backup -> {
                    assertEquals(backup.replace("{0}", text(refusal.name)), shown, refusal.name)
                    assertTrue(isBackupRefusal(refusal), refusal.name)
                }
                refusal == Refusal.WrongPassphrase || refusal == Refusal.ReadbackMismatch -> assertTrue(isBackupRefusal(refusal))
                else -> {
                    assertNull(shown, refusal.name)
                    assertFalse(isBackupRefusal(refusal), refusal.name)
                }
            }
        }
    }

    /** A choice of question of four letters or more whose first three are no three-letter choice, or null (never printed). */
    private fun longerChoice(question: Question): String? {
        val choices = question.choices.map { choiceText(it) }
        return choices.firstOrNull { choice -> choice.length >= 4 && choices.none { it == choice.take(3) } }
    }

    private companion object {
        const val DICE_50 = "dice-50-words12"
    }
}
