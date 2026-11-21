// Check a backup against backup.json (tasks/todo.md, M6 item D7; :screens' CheckBackupScreensTest.kt), over
// the real slot: every age file backup.json carries, picked under a .age name (any letter case) and opened
// with its passphrase's first four letters on the letter pad. A KeepCrypt backup opens to "Backup OK" with
// its plaintext's fingerprint, its words shown only through the privacy gate and equal to its mnemonic, a
// 24-word one on two devices; a file whose contents are no KeepCrypt backup (the C2SP age files, the 4096-byte
// chunk) and a wrong passphrase (another file's) are refused with a text BackupScreens.kt has, the entry
// emptied and the file kept. A name not ending in .age, and a size past backup.json's limit (Core's), are
// refused before any byte is read. The re-check QR of the abandon backup is kcr.json's check text for that
// seed's T, and its Seal ID kcr.json's. The damaged files of age_refused are CeremonyRefusalTablesTests'.
// Each test leaves the slot at home.

import XCTest

final class CeremonyCheckBackupTests: XCTestCase {
    override func setUpWithError() throws {
        try KcrVectors.load()
        assertLiveSlot()
    }

    override func tearDown() {
        assertSlotEmptied()
    }

    /// The registry's origin in every QR's text until M9 (core's seal module; Android's Checker.ORIGIN).
    private let origin = "https://registry.invalid"

    private func backup() throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: Vectors.resource("backup", "json")) as? [String: Any])
    }

    /// An age_files entry's bytes: its file_hex, or its file text's UTF-8.
    private func bytes(_ entry: [String: Any]) throws -> [UInt8] {
        if let hex = entry["file_hex"] as? String { return hexBytes(hex) }
        return Array(try XCTUnwrap(entry["file"] as? String).utf8)
    }

    /// Home's Check a backup with file picked under name, its read run: the entry, or Home with a refusal.
    private func pick(_ rig: Rig, _ file: [UInt8], name: String, size: Int64? = nil) -> FakeFile {
        let picked = FakeFile(name: name, size: size ?? Int64(file.count), bytes: file)
        rig.model.checkBackup(FakePickers())
        rig.model.backupPicked(picked)
        rig.worker.run()
        return picked
    }

    /// The eight entries typed on the letter pad (each word's first four letters), each then Done, and the
    /// opening run.
    private func type(_ rig: Rig, _ passphrase: String) {
        for word in passphrase.split(separator: " ") {
            rig.press(String(word.prefix(4)))
            rig.model.entryTyped()
        }
        rig.worker.run()
    }

    /// Every age file of backup.json through Check a backup: right passphrases, a wrong one, and contents that
    /// are no KeepCrypt backup.
    func testEveryBackupJsonFileThroughCheckABackup() throws {
        let doc = try backup()
        let files = try XCTUnwrap(doc["age_files"] as? [[String: Any]])
        let plaintexts = try XCTUnwrap(doc["plaintexts"] as? [[String: Any]])
        XCTAssertEqual((doc["constants"] as? [String: Any])?["max_file_bytes"] as? Int, Core.backupMaxBytes, "backup.json's limit is core's")
        let wrong = "praise bone derive dinner acid winter choose control"
        var opened = 0
        for (index, entry) in files.enumerated() {
            let name = try XCTUnwrap(entry["name"] as? String)
            let passphrase = try XCTUnwrap(entry["passphrase"] as? String)
            let file = try bytes(entry)
            let rig = Rig().toHome()
            // Upper case every other time: the name's suffix matches in any letter case.
            let picked = pick(rig, file, name: "keepcrypt-backup-0123abcd." + (index % 2 == 0 ? "age" : "AGE"))
            XCTAssertEqual(rig.screen, .backupCheckEntry, "\(name): the entry")
            XCTAssertTrue(rig.model.state.gate, "\(name): the entry shows through the privacy gate")
            rig.model.passGate()
            guard passphrase.split(separator: " ").count == passphraseWords else {
                // The C2SP files' passphrase is no 8 words: the letter pad cannot type it, and the file opens
                // under no passphrase the app takes.
                type(rig, wrong)
                let refusal = try XCTUnwrap(rig.model.state.entryRefusal, name)
                XCTAssertNotNil(backupRefusalText(refusal), "\(name): a refusal BackupScreens.kt names")
                rig.model.back()
                XCTAssertEqual(rig.screen, .home)
                continue
            }
            guard let plain = entry["plaintext"] as? String else {
                type(rig, passphrase)
                let refusal = try XCTUnwrap(rig.model.state.entryRefusal, "\(name): no KeepCrypt backup inside")
                XCTAssertEqual(refusal.group, .backup, name)
                XCTAssertNotNil(backupRefusalText(refusal), name)
                XCTAssertFalse(zeroed(picked.given), "\(name): the file is kept for another try")
                rig.model.back()
                XCTAssertTrue(zeroed(picked.given), "\(name): Back wiped the file")
                continue
            }
            if passphrase != wrong {
                type(rig, wrong)
                XCTAssertEqual(rig.model.state.entryRefusal, .wrongPassphrase, "\(name): another file's passphrase")
                XCTAssertEqual(rig.model.state.page, 0, "\(name): the entry again from word 1")
                XCTAssertEqual(backupRefusalText(.wrongPassphrase), "the passphrase does not open this backup")
            }
            type(rig, passphrase)
            let result = rig.model.state
            XCTAssertEqual(result.screen, .backupCheckResult, "\(name): Backup OK")
            XCTAssertFalse(Screen.backupCheckResult.isProtected)
            let expected = try XCTUnwrap(plaintexts.first { $0["name"] as? String == plain }, plain)
            XCTAssertEqual(fingerprintHex(try XCTUnwrap(result.opened).fingerprint), expected["fingerprint"] as? String, name)
            let words = try XCTUnwrap(expected["mnemonic"] as? String).split(separator: " ").map(String.init)
            rig.model.showBackupWords()
            for (position, word) in words.enumerated() {
                if rig.screen == .deviceSwap {
                    XCTAssertEqual(position, insertsPerDevice, "\(name): the swap before word 13")
                    rig.model.swapDone()
                }
                XCTAssertEqual(rig.screen, .words, "\(name) word \(position + 1)")
                if position == 0 || position == insertsPerDevice {
                    XCTAssertTrue(rig.model.state.gate, "\(name): the words show only through the privacy gate")
                    rig.model.passGate()
                }
                let insert = try XCTUnwrap(rig.model.state.insert)
                XCTAssertTrue(sameWord(insert, word), "\(name): insert \(position + 1) is the mnemonic's")
                XCTAssertEqual(insert.count, words.count)
                if position + 1 < words.count { rig.model.nextPage() }
            }
            rig.model.backupWordsDone()
            XCTAssertEqual(rig.screen, .backupCheckResult, "\(name): the last insert's Done, with no read-back")
            rig.model.closeBackup()
            XCTAssertEqual(rig.screen, .home)
            XCTAssertFalse(rig.model.held, "\(name): Done leaves nothing held")
            opened += 1
        }
        XCTAssertEqual(opened, files.filter { $0["plaintext"] is String }.count)
        XCTAssertGreaterThanOrEqual(opened, 8, "every KeepCrypt backup of backup.json opened")
    }

    /// A name that does not end in .age, and a size past core's limit (backup.json's max_file_bytes), are
    /// refused at Home before any byte is read, with HomeScreens.kt's lines.
    func testAWrongNameOrAnOversizedFileIsRefusedBeforeAnyByteIsRead() throws {
        let entry = try XCTUnwrap((try backup()["age_files"] as? [[String: Any]])?.first { $0["name"] as? String == "abandon-12" })
        let file = try bytes(entry)
        let rig = Rig().toHome()
        for (name, size, refusal) in [
            ("keepcrypt-backup-0123abcd.age.txt", Int64(file.count), FileRefusal.notAge),
            ("keepcrypt-backup-0123abcd.kcr", Int64(file.count), .notAge),
            ("keepcrypt-backup-0123abcd.age", Int64(Core.backupMaxBytes + 1), .tooLarge),
        ] {
            let picked = pick(rig, file, name: name, size: size)
            XCTAssertEqual(rig.screen, .home, name)
            XCTAssertEqual(rig.model.state.fileRefusal, refusal, name)
            XCTAssertEqual(picked.reads, 0, "\(name): no byte read")
        }
        XCTAssertEqual(fileRefusalText(.notAge), "That file was not opened: a KeepCrypt backup's name ends in .age.")
        XCTAssertEqual(fileRefusalText(.tooLarge), "That file was not opened: it is larger than a backup can be (8 KiB).")
    }

    /// CheckBackupScreensTest.kt's theRecheckQrAndItsBackThenDoneEndsTheCheckInCoreAndReturnsHome, with the
    /// QR's text: the abandon backup's re-check QR is kcr.json's check text for vector-1's T, with no nonce,
    /// and its Seal ID vector-1's.
    func testTheRecheckQrIsTheSealsTagAlone() throws {
        let entry = try XCTUnwrap((try backup()["age_files"] as? [[String: Any]])?.first { $0["name"] as? String == "abandon-12" })
        let seed = try Vectors.seed("vector-1")
        let rig = Rig().toHome()
        _ = pick(rig, try bytes(entry), name: "keepcrypt-backup-0123abcd.age")
        rig.model.passGate()
        type(rig, try XCTUnwrap(entry["passphrase"] as? String))
        let opened = try XCTUnwrap(rig.model.state.opened)
        XCTAssertEqual(opened.seal.sealId, seed["seal_id"] as? String, "kcr.json's Seal ID")
        rig.model.showRecheck()
        XCTAssertEqual(rig.screen, .backupRecheck)
        XCTAssertFalse(Screen.backupRecheck.isProtected, "the re-check QR is Public: T alone")
        let recheck = try XCTUnwrap(rig.model.state.opened?.recheck)
        XCTAssertEqual(try qrText(recheck), origin + "/check#t=" + (try XCTUnwrap(seed["seal_tag_hex"] as? String)), "T, no nonce")
        rig.model.back()
        XCTAssertEqual(rig.screen, .backupCheckResult, "Back on the re-check QR is the result")
        rig.model.closeBackup()
        XCTAssertEqual(rig.screen, .home)
        XCTAssertFalse(rig.model.held)
    }

    /// The entry's and the result's lines, as BackupScreens.kt lays them out.
    func testTheEntrysLine() {
        XCTAssertEqual(entryWordText(0), "Backup passphrase, word 1 of 8")
        XCTAssertEqual(entryWordText(7), "Backup passphrase, word 8 of 8")
        XCTAssertEqual(versionText(), "Version 0.0.0")
        XCTAssertEqual(securityText(), "Security reports: admin@keepcrypt.com")
    }
}
