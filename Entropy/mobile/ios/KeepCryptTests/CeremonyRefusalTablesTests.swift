// Every refusal table the screens show, against vectors/kcr.json, vectors/backup.json and core's own
// verdicts (tasks/todo.md, M6 item D2), ported from :screens' RefusalTablesTest.kt (Stage U's U2g), over the
// real slot: every go-ahead QR text kcr.json carries scanned on the check of its dice-50-words12 and
// dice-99-words12 seeds, each refusal back on the scan screen with the same check, each verdict core gives
// as kcr.json says; every damaged or wrongly opened backup of backup.json's age_refused through Check a
// backup, each refusal back on the entry, emptied; every snapshot kcr.json carries through Load registry
// snapshot, each refusal named on the result, each accepted one loaded with its number, date and count;
// and the metal read-back: every mirror pair the vector seeds' words reach, and each insert read back with
// the next insert's word. JVM's tests run in the test-registry build alone; here the shipping build runs
// them too, where core trusts no registry key: an accepted proof or snapshot is refused NoRegistryKey, and
// a refused one gives its own refusal or NoRegistryKey. Each test leaves the slot at home.

import XCTest

final class CeremonyRefusalTablesTests: XCTestCase {
    override func setUpWithError() throws {
        try KcrVectors.load()
        assertLiveSlot()
    }

    override func tearDown() {
        assertSlotEmptied()
    }

    #if KC_WITH_TEST_REGISTRY
    private let registry = true
    #else
    private let registry = false
    #endif

    /// A core error's name as the Refusal case it is: its inner name ("Ur(TooLong)" is TooLong, and
    /// "Backup(Armor)" Armor) in lower camel case; kcr.json's lookup result wrong_bucket is wrongBucket.
    private func refusal(named name: String) -> Refusal? {
        var inner = name
        for wrapper in ["Ur(", "Backup("] where inner.hasPrefix(wrapper) && inner.hasSuffix(")") {
            inner = String(inner.dropFirst(wrapper.count).dropLast())
        }
        if inner == "wrong_bucket" { return .wrongBucket }
        guard let first = inner.first else { return nil }
        let camel = first.lowercased() + inner.dropFirst()
        return Refusal.allCases.first { String(describing: $0) == camel }
    }

    /// A fresh Rig on the scan screen of the check of kcr.json's 12-word gate seed named seed, no
    /// snapshot loaded.
    private func scanning(_ seed: String) -> Rig {
        let rig = Rig().toHome().begin(.diceOnly, .twelve)
        for face in KcrVectors.rolls(seed) {
            rig.press(face)
            rig.model.confirmRoll()
        }
        rig.model.diceDone()
        rig.worker.run()
        rig.model.checkNow()
        rig.model.showCheckQr()
        rig.model.scanQr()
        XCTAssertEqual(rig.screen, .scan)
        return rig
    }

    /// RefusalTablesTest.kt's everyGoAheadQrVectorOnTheScanScreen.
    func testEveryGoAheadQrVectorOnTheScanScreen() throws {
        let vectors = KcrVectors.all("proofs").filter { $0["ur"] is String }
        let refusedCount = vectors.filter { ($0["expect"] as? [String: Any])?["ok"] as? Bool == false }.count
        XCTAssertTrue(refusedCount >= 7 && vectors.count - refusedCount >= 5, "kcr.json's go-ahead QR texts")
        var verdicts = Set<String>()
        for vector in vectors {
            let name = try XCTUnwrap(vector["name"] as? String)
            let input = try XCTUnwrap(vector["ur"] as? String)
            let expect = try XCTUnwrap(vector["expect"] as? [String: Any])
            for seed in ["dice-50-words12", "dice-99-words12"] {
                let what = name + " on " + seed
                let rig = scanning(seed)
                let request = rig.model.state.checkRequest
                rig.model.onGoAheadText(input)
                XCTAssertEqual(rig.screen, .working, "\(what): core's check of the text, a long call")
                rig.worker.run()
                let state = rig.model.state
                var verdict = expect["error"] as? String
                if verdict == nil {
                    let lookups = try XCTUnwrap(expect["lookups"] as? [[String: Any]])
                    verdict = lookups.first { $0["seed"] as? String == seed }?["result"] as? String
                }
                let said = try XCTUnwrap(verdict, "\(what): kcr.json's verdict")
                verdicts.insert(said)
                if registry, said == "clear" {
                    XCTAssertEqual(state.screen, .checkResult, what)
                    XCTAssertTrue(state.proof, "\(what): the result is the scanned proof's")
                } else if registry, said == "collision" {
                    XCTAssertEqual(state.screen, .collision, what)
                } else {
                    XCTAssertEqual(state.screen, .scan, "\(what): a refused text returns to the scan screen")
                    let expected = registry || expect["error"] is String ? refusal(named: said) : Refusal.noRegistryKey
                    if registry {
                        XCTAssertEqual(state.scanRefusal, expected, what)
                    } else {
                        XCTAssertTrue(state.scanRefusal == expected || state.scanRefusal == .noRegistryKey, "\(what): its refusal in the shipping build")
                    }
                    XCTAssertTrue(state.checkRequest === request, "\(what): the same check and nonce")
                    XCTAssertTrue(rig.model.held, "\(what): the session stays")
                }
                assertSlotEmptied()
            }
        }
        XCTAssertTrue(verdicts.isSuperset(of: ["clear", "collision", "wrong_bucket"]), "every verdict core gives an accepted text")
    }

    /// The UTF-8 bytes of the "file" text of backup.json's age_refused entry named name, its JSON escapes
    /// undone here, as RefusalTablesTest.kt's jsonText does: JSONSerialization drops a byte order mark at
    /// a string's start, which the armor-bom vector's file holds.
    private func fileText(_ raw: String, _ name: String) throws -> [UInt8] {
        let entry = try XCTUnwrap(raw.range(of: "\"name\": \"" + name + "\","), "\(name) in backup.json")
        let open = try XCTUnwrap(raw.range(of: "\"file\": \"", range: entry.upperBound..<raw.endIndex), "\(name)'s file")
        var out = ""
        var at = open.upperBound
        while at < raw.endIndex, raw[at] != "\"" {
            var c = raw[at]
            at = raw.index(after: at)
            if c == "\\" {
                let e = raw[at]
                at = raw.index(after: at)
                switch e {
                case "n": c = "\n"
                case "r": c = "\r"
                case "t": c = "\t"
                case "u":
                    let end = raw.index(at, offsetBy: 4)
                    let scalar = try XCTUnwrap(UInt32(raw[at..<end], radix: 16).flatMap(Unicode.Scalar.init), "\(name): an escape")
                    c = Character(scalar)
                    at = end
                default: c = e
                }
            }
            out.append(c)
        }
        return Array(out.utf8)
    }

    /// RefusalTablesTest.kt's everyDamagedOrWronglyOpenedBackupThroughCheckABackup.
    func testEveryDamagedOrWronglyOpenedBackupThroughCheckABackup() throws {
        let data = try Vectors.resource("backup", "json")
        let raw = try XCTUnwrap(String(data: data, encoding: .utf8))
        let backup = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        let vectors = try XCTUnwrap(backup["age_refused"] as? [[String: Any]])
        XCTAssertFalse(vectors.isEmpty, "backup.json's age_refused")
        let rig = Rig().toHome()
        var refused = Set<Refusal>()
        var expected = Set<Refusal>()
        for vector in vectors {
            let what = try XCTUnwrap(vector["name"] as? String)
            let named = try XCTUnwrap(vector["error"] as? String)
            let want = try XCTUnwrap(refusal(named: named), "\(what): \(named) is a Refusal")
            expected.insert(want)
            let bytes: [UInt8]
            if let hex = vector["file_hex"] as? String {
                bytes = hexBytes(hex)
            } else {
                bytes = try fileText(raw, what)
            }
            let passphrase = try XCTUnwrap(vector["passphrase"] as? String).split(separator: " ").map(String.init)
            let file = FakeFile(name: SavedBackup.name, size: Int64(bytes.count), bytes: bytes)
            rig.model.checkBackup(FakePickers())
            rig.model.backupPicked(file)
            rig.model.appResumed()
            if bytes.count > Core.backupMaxBytes {
                XCTAssertEqual(want, .tooLarge, "\(what): core's TooLarge, met first by the model's refusal by size")
                XCTAssertEqual(rig.screen, .home, what)
                XCTAssertEqual(rig.model.state.fileRefusal, .tooLarge, what)
                XCTAssertEqual(file.reads, 0, "\(what): never read")
                refused.insert(.tooLarge)
                continue
            }
            rig.worker.run()
            XCTAssertEqual(rig.screen, .backupCheckEntry, "\(what): the entry")
            rig.model.passGate()
            for word in passphrase {
                rig.press(String(word.prefix(4)))
                rig.model.entryTyped()
            }
            rig.worker.run()
            let state = rig.model.state
            XCTAssertEqual(state.screen, .backupCheckEntry, "\(what): a refusal returns to the entry")
            XCTAssertEqual(state.entryRefusal, want, what)
            XCTAssertTrue(isBackupRefusal(want), "\(what): a refusal the backup screens name")
            XCTAssertTrue(rig.model.entriesHeld.isEmpty, "\(what): the entry emptied")
            refused.insert(want)
            rig.model.back()
            XCTAssertEqual(rig.screen, .home, "\(what): Back drops the file")
            XCTAssertTrue(zeroed(file.given), "\(what): the file read was wiped")
        }
        XCTAssertEqual(refused, expected, "every refusal of backup.json's age_refused")
        XCTAssertTrue(expected.isSuperset(of: [.wrongPassphrase, .header, .armor]))
    }

    /// RefusalTablesTest.kt's everySnapshotVectorThroughLoadRegistrySnapshot.
    func testEverySnapshotVectorThroughLoadRegistrySnapshot() throws {
        let vectors = KcrVectors.all("snapshots")
        let refusedCount = vectors.filter { ($0["expect"] as? [String: Any])?["ok"] as? Bool == false }.count
        XCTAssertTrue(refusedCount >= 30 && vectors.count - refusedCount >= 2, "kcr.json's snapshots")
        let rig = Rig().toHome()
        for vector in vectors {
            let what = try XCTUnwrap(vector["name"] as? String)
            let bytes = hexBytes(try XCTUnwrap(vector["kcr_hex"] as? String))
            let expect = try XCTUnwrap(vector["expect"] as? [String: Any])
            rig.model.loadSnapshot(FakePickers())
            rig.model.snapshotPicked(FakeFile(name: what + ".kcr", size: Int64(bytes.count), bytes: bytes))
            rig.model.appResumed()
            rig.worker.run()
            let state = rig.model.state
            XCTAssertEqual(state.screen, .snapshot, what)
            if let error = expect["error"] as? String {
                let want = refusal(named: error)
                XCTAssertNotNil(want, "\(what): \(error) is a Refusal")
                if registry {
                    XCTAssertEqual(state.snapshotRefusal, want, what)
                } else {
                    XCTAssertTrue(state.snapshotRefusal == want || state.snapshotRefusal == .noRegistryKey, "\(what): its refusal in the shipping build")
                }
                XCTAssertTrue(state.snapshotRefusal.map(isSnapshotRefusal) ?? false, "\(what): a refusal the result names")
            } else if registry {
                XCTAssertNil(state.snapshotRefusal, "\(what): core accepts it")
                let loaded = try XCTUnwrap(state.loaded, "\(what): loaded")
                XCTAssertEqual(loaded.number, UInt64(try XCTUnwrap(expect["number"] as? Int)), "\(what): its number")
                XCTAssertEqual(loaded.date, UInt32(try XCTUnwrap(expect["date"] as? Int)), "\(what): its date")
                XCTAssertEqual(loaded.count, UInt32(try XCTUnwrap(expect["count"] as? Int)), "\(what): its count")
            } else {
                XCTAssertEqual(state.snapshotRefusal, .noRegistryKey, "\(what): no registry key in the shipping build")
                XCTAssertNil(state.loaded, what)
            }
            rig.model.snapshotDone()
            XCTAssertEqual(rig.screen, .home, what)
        }
    }

    /// The mirror pairs (CLAUDE.md, Braille): each letter and the letter its cell mirrors to.
    private let mirrors: [Character: Character] = ["e": "i", "i": "e", "d": "f", "f": "d", "h": "j", "j": "h", "r": "w", "w": "r"]

    /// On the entry: letters typed and Done; the verdicts on faces 1-4 of the mismatch that follows, or
    /// nil for a match.
    private func readBack(_ rig: Rig, _ letters: String) -> [Verdict]? {
        rig.press(letters)
        rig.model.readbackTyped()
        if rig.screen == .readbackEntry, rig.model.state.matched { return nil }
        XCTAssertEqual(rig.screen, .readbackMismatch, "a read-back that does not match")
        guard let mismatch = rig.model.state.mismatch else { return [] }
        return (1...4).map { mismatch.face($0).verdict }
    }

    /// RefusalTablesTest.kt's everyMirrorPairAndAWrongInsertOnTheReadback.
    func testEveryMirrorPairAndAWrongInsertOnTheReadback() throws {
        let words = KcrVectors.words("dice-99-words12")
        let rig = Rig().toHome().toSkippedResult("dice-99-words12").toWords()
        for _ in 0..<(insertsPerDevice - 1) {
            rig.model.nextPage()
        }
        rig.model.startReadback()
        XCTAssertEqual(rig.screen, .readbackEntry)
        var flipped = Set<Character>()
        for (index, word) in words.enumerated() {
            let insert = index + 1
            let letters = Array(word.prefix(4))
            for (at, letter) in letters.enumerated() {
                guard let mirror = mirrors[letter] else { continue }
                var misread = letters
                misread[at] = mirror
                let verdicts = try XCTUnwrap(readBack(rig, String(misread)), "insert \(insert): a mirror misread matched")
                XCTAssertEqual(verdicts[at], .mirrorMisread, "insert \(insert): the face read mirrored")
                XCTAssertTrue(verdicts.enumerated().allSatisfy { $0.offset == at || $0.element == .ok }, "insert \(insert): the other faces")
                rig.model.readbackAgain()
                flipped.insert(letter)
            }
            let next = String(words[insert % words.count].prefix(4))
            let wrong = try XCTUnwrap(readBack(rig, next), "insert \(insert) read with the next insert's word matched")
            XCTAssertFalse(wrong.allSatisfy { $0 == .ok }, "insert \(insert): the wrong insert's faces")
            rig.model.readbackAgain()
            XCTAssertEqual(rig.screen, .readbackEntry, "insert \(insert): Read it again")
            XCTAssertNil(readBack(rig, String(letters)), "insert \(insert): its own letters after the wrong ones")
            rig.model.readbackNext()
        }
        XCTAssertEqual(rig.screen, .readbackDone, "every insert read back")
        XCTAssertEqual(flipped, ["e", "i", "d", "f", "h", "r"], "the mirror flips the vector words reach")
    }
}
