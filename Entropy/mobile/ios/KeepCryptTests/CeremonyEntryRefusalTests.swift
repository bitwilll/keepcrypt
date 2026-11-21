// The refusals of what the user types or picks (tasks/todo.md, M6 item D2; docs/pi-firmware.md, "Finish and
// halts": only refusals of what the user or a file supplied return to their own screen), the ones
// RefusalTablesTest.kt leaves to the screens' own classes, ported from them, over the real slot: a wrong
// go-ahead code (CheckScreensTest.kt), a wrong confirm answer (BackupScreensTest.kt), a picked file refused by
// its name, its size or its read and a wrong passphrase, an entry that names no word or a file that does not
// read on Check a backup's entry (CheckBackupScreensTest.kt), and an empty BIP39 passphrase (ExportScreensTest.kt).
// Each test leaves the slot at home.

import XCTest

final class CeremonyEntryRefusalTests: XCTestCase {
    override func setUpWithError() throws {
        try KcrVectors.load()
        assertLiveSlot()
    }

    override func tearDown() {
        assertSlotEmptied()
    }

    /// CheckScreensTest.kt's aWrongTypedCodeIsRefusedAndTheCheckItsNonceAndActionsStay.
    func testAWrongTypedCodeIsRefusedAndTheCheckItsNonceAndActionsStay() throws {
        let rig = Walk.to(.checkQr)
        let request = try XCTUnwrap(rig.model.state.checkRequest)
        rig.model.typeCode()
        XCTAssertEqual(rig.screen, .codeEntry)
        XCTAssertTrue(rig.model.state.checkRequest === request, "the code entry keeps the check QR")
        rig.press("0000000")
        XCTAssertEqual(rig.model.goAheadCode.length, 7)
        rig.model.codeDone()
        XCTAssertEqual(rig.screen, .codeEntry)
        XCTAssertFalse(rig.model.state.codeRefused, "Done with 7 symbols does nothing")
        rig.press("0")
        rig.model.codeDone()
        let refused = rig.model.state
        XCTAssertEqual(refused.screen, .codeEntry, "a wrong code returns to its screen")
        XCTAssertTrue(refused.codeRefused, "the code entry says it was refused")
        XCTAssertEqual(rig.model.goAheadCode.length, 0, "the refused code was handed to core, the entry emptied")
        XCTAssertTrue(rig.model.goAheadCode.zeroPastLength(), "and its bytes zeroed")
        XCTAssertTrue(rig.model.held, "the session stays")
        rig.model.back()
        let back = rig.model.state
        XCTAssertEqual(back.screen, .checkQr)
        XCTAssertFalse(back.codeRefused)
        XCTAssertTrue(back.checkRequest === request, "the same check QR")
        rig.model.matchFound()
        XCTAssertEqual(rig.screen, .matchFoundConfirm, "the check QR's actions stay")
    }

    /// A confirm choice's text (public test words, compared, never printed).
    private func text(_ choice: Secret) -> String {
        String(decoding: (0..<choice.count).map { choice[$0] }, as: UTF8.self)
    }

    /// BackupScreensTest.kt's aWrongAnswerShowsThePassphraseAgainFromItsFirstPageWithTheSameQuestions.
    func testAWrongAnswerShowsThePassphraseAgainFromItsFirstPageWithTheSameQuestions() throws {
        let rig = Rig().toHome().toSummary("dice-50-words12")
        let passphrase = rig.toConfirm()
        let challenge = try XCTUnwrap(rig.model.state.challenge)
        let positions = challenge.questions.map(\.position)
        // Three letters of a choice of four or more are no choice: wrong at once (on the first question with
        // such a choice; the first is answered right to reach the second).
        let longer = challenge.questions.map { question in question.choices.map(text).first { $0.count >= 4 } }
        let at = try XCTUnwrap(longer.firstIndex { $0 != nil })
        if at == 1 { rig.answer(passphrase[challenge.questions[0].position - 1]) }
        rig.press(String(try XCTUnwrap(longer[at]).prefix(3)))
        rig.model.confirmTyped()
        XCTAssertEqual(rig.screen, .backupPassphrase, "three letters of a longer word are no choice")
        XCTAssertTrue(rig.model.state.wrongConfirm)
        rig.model.nextPage()
        rig.model.passphraseWritten()
        rig.answer("zzzz")
        let again = rig.model.state
        XCTAssertEqual(again.screen, .backupPassphrase, "an answer that is none of the four choices")
        XCTAssertEqual(again.page, 0)
        XCTAssertTrue(again.wrongConfirm, "the passphrase says the answer was wrong")
        XCTAssertFalse(again.gate, "Protected to Protected: no gate")
        rig.model.nextPage()
        XCTAssertFalse(rig.model.state.wrongConfirm, "the note is on the first page")
        rig.model.passphraseWritten()
        let asked = try XCTUnwrap(rig.model.state.challenge)
        XCTAssertEqual(asked.questions.map(\.position), positions, "the questions stay the same")
        rig.answer(passphrase[asked.questions[0].position - 1])
        let second = asked.questions[1]
        let right = passphrase[second.position - 1]
        let wrong = try XCTUnwrap(second.choices.map(text).first { $0.prefix(4) != right.prefix(4) })
        rig.answer(wrong)
        XCTAssertEqual(rig.screen, .backupPassphrase, "core says the second answer is wrong")
        XCTAssertTrue(rig.model.state.wrongConfirm)
        rig.model.nextPage()
        rig.model.passphraseWritten()
        XCTAssertEqual(rig.model.state.challenge?.questions.map(\.position), positions)
        rig.confirm(passphrase)
        XCTAssertEqual(rig.screen, .backupSave, "both right after two wrong tries")
    }

    /// CheckBackupScreensTest.kt's aFileIsRefusedByItsNameOrSizeBeforeAnyByteIsReadAndByItsReadAfter.
    func testAFileIsRefusedByItsNameOrSizeBeforeAnyByteIsReadAndByItsReadAfter() {
        let bytes = SavedBackup.shared.file
        let rig = Rig().toHome()
        let size = Int64(bytes.count)
        let cases: [(FakeFile, FileRefusal)] = [
            (FakeFile(name: "keepcrypt-backup-0123abcd.age.txt", size: size, bytes: bytes), .notAge),
            (FakeFile(name: "backup.txt", size: size, bytes: bytes), .notAge),
            (FakeFile(name: "age", size: size, bytes: bytes), .notAge),
            (FakeFile(name: nil, size: size, bytes: bytes), .notAge),
            (FakeFile(name: SavedBackup.name, size: nil, bytes: bytes), .noSize),
            (FakeFile(name: SavedBackup.name, size: Int64(Core.backupMaxBytes + 1), bytes: bytes), .tooLarge),
            (FakeFile(name: SavedBackup.name, size: -1, bytes: bytes), .tooLarge),
        ]
        for (file, refusal) in cases {
            let what = file.name ?? "no name"
            rig.model.checkBackup(FakePickers())
            rig.model.backupPicked(file)
            XCTAssertEqual(rig.screen, .home, what)
            XCTAssertEqual(rig.model.state.fileRefusal, refusal, what)
            XCTAssertEqual(file.reads, 0, "no byte of a refused file is read: \(what)")
            XCTAssertEqual(rig.worker.waiting, 0, "no read waits on the worker: \(what)")
        }
        let liar = FakeFile(name: SavedBackup.name, size: 100, bytes: [UInt8](repeating: 1, count: Core.backupMaxBytes + 1))
        rig.model.checkBackup(FakePickers())
        rig.model.backupPicked(liar)
        rig.worker.run()
        XCTAssertEqual(rig.model.state.fileRefusal, .tooLarge, "a provider that sized it within the limit, then gave more")
        XCTAssertEqual(liar.reads, 1)
        XCTAssertEqual(liar.readLimit, Core.backupMaxBytes)
        XCTAssertTrue(zeroed(liar.given), "the bytes past the limit were wiped")
        let unreadable = FakeFile(name: "keepcrypt-backup-0123abcd.AGE", size: 100, bytes: nil)
        rig.model.checkBackup(FakePickers())
        rig.model.backupPicked(unreadable)
        rig.worker.run()
        XCTAssertEqual(rig.model.state.fileRefusal, .unreadable, "an upper-case .AGE passes the name, then a read that fails")
        XCTAssertEqual(rig.screen, .home)
        rig.model.chooseMode(.mixed)
        XCTAssertEqual(rig.screen, .length, "Home's other choices stay")
    }

    /// Check a backup's entry with the saved backup, or bytes of the test's, picked: past its gate.
    private func picked(_ bytes: [UInt8]? = nil) -> (Rig, FakeFile) {
        let file = bytes ?? SavedBackup.shared.file
        let rig = Rig().toHome()
        let picked = FakeFile(name: SavedBackup.name, size: Int64(file.count), bytes: file)
        rig.model.checkBackup(FakePickers())
        rig.model.backupPicked(picked)
        rig.worker.run()
        XCTAssertEqual(rig.screen, .backupCheckEntry)
        rig.model.passGate()
        return (rig, picked)
    }

    /// The eight entries typed, each then Done, and the opening run.
    private func type(_ rig: Rig, _ entries: [String]) {
        for entry in entries {
            rig.press(entry)
            rig.model.entryTyped()
        }
        rig.worker.run()
    }

    /// CheckBackupScreensTest.kt's aWrongPassphraseAnEntryThatNamesNoWordAndAFileThatDoesNotReadAreRefusedWithCoresText.
    func testAWrongPassphraseAnEntryThatNamesNoWordAndAFileThatDoesNotReadAreRefused() throws {
        let (rig, file) = picked()
        let right = SavedBackup.shared.passphrase.map { String($0.prefix(4)) }
        type(rig, [right[0] == "aban" ? "zoo" : "aban"] + right.dropFirst())
        let wrong = rig.model.state
        XCTAssertEqual(wrong.screen, .backupCheckEntry)
        XCTAssertEqual(wrong.page, 0, "the entry again from word 1")
        XCTAssertEqual(wrong.entryRefusal, .wrongPassphrase)
        XCTAssertFalse(zeroed(file.given), "the file is kept for another try")
        type(rig, [String](repeating: "zzzz", count: passphraseWords))
        XCTAssertEqual(rig.model.state.entryRefusal, .passphraseWords, "an entry that names no word")
        type(rig, right)
        XCTAssertEqual(rig.screen, .backupCheckResult, "the right passphrase after two refusals")
        rig.model.closeBackup()
        XCTAssertEqual(rig.screen, .home)

        let (bad, _) = picked(Array("age-encryption.org/v1\nnot a backup\n".utf8))
        type(bad, right)
        let refusal = try XCTUnwrap(bad.model.state.entryRefusal)
        XCTAssertEqual(bad.screen, .backupCheckEntry)
        XCTAssertEqual(refusal.group, .backup, "a file that does not read")
    }

    /// ExportScreensTest.kt's empty passphrase: Done with nothing typed on the BIP39 entry does nothing
    /// (core refuses an empty passphrase; "No BIP39 passphrase" leaves it out).
    func testTheBip39EntrysDoneWithNothingTypedDoesNothing() {
        let rig = Walk.to(.bip39Entry)
        rig.model.bip39Typed()
        XCTAssertEqual(rig.screen, .bip39Entry, "Done with nothing typed does nothing")
        XCTAssertNil(rig.model.state.watch)
        rig.press("1")
        rig.model.bip39Typed()
        XCTAssertEqual(rig.screen, .watchSummary, "one character typed: that passphrase's wallet")
        XCTAssertEqual(rig.model.state.watch?.passphraseUsed, true)
        XCTAssertEqual(rig.model.bip39Letters.length, 0, "the passphrase handed over and wiped")
    }
}
