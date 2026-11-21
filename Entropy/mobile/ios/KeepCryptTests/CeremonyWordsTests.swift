// The words' screens and their texts (tasks/todo.md, M6 item D5), ported from :screens' WordsScreensTest.kt,
// ReadbackScreensTest.kt and WordVectors.kt, over the real slot: the insert view's texts (Android's and the
// Pi's), every insert of the 24-word gate seed against vectors/braille.json face by face (each face's letter,
// a blank face as none, its dots, the lighter face, the mirror partner, and the label the insert view draws
// under it), CLAUDE.md's SeedBook cross-checks (ABANDON 0001, ACT 0020 with two blank faces, ACTION 0021,
// METAL 1121, WIRE 2018, ZOO 2048) and the mirror pairs e/i, d/f, h/j, r/w as braille.json gives them, the
// read-back's typed faces, a wrong letter's verdict line and the summary's fingerprint. The braille cells
// are core's (WordPage's faces) and braille.json's, never a table of the app's. Each test leaves the slot
// at home.

import XCTest

final class CeremonyWordsTests: XCTestCase {
    override func setUpWithError() throws {
        try KcrVectors.load()
        assertLiveSlot()
    }

    override func tearDown() {
        assertSlotEmptied()
    }

    /// braille.json's dots of letter (its cells' code points), dot d at bit d - 1.
    private func dots(_ entry: [String: Any], _ face: Int) throws -> UInt8 {
        let cells = Array(try XCTUnwrap(entry["cells"] as? String).unicodeScalars)
        return UInt8(cells[face - 1].value - 0x2800)
    }

    /// Whether insert is braille.json's insert of word, face by face, as WordVectors.kt's assertInsertOf.
    private func assertInsert(_ insert: WordPage, _ word: String, _ entry: [String: Any], _ what: String) throws {
        XCTAssertEqual(insert.seedbook, entry["number"] as? Int, "\(what): the SeedBook number")
        let faces = try XCTUnwrap(entry["faces"] as? [Any])
        let partners = try XCTUnwrap(entry["mirror_partners"] as? [Any])
        for n in 1...5 {
            let face = insert.face(n)
            let letter = (faces[n - 1] as? String).map { Array($0.utf8)[0] }
            XCTAssertEqual(face.isBlank, letter == nil, "\(what): face \(n) blank or not")
            XCTAssertEqual(face.letter, letter ?? 0, "\(what): face \(n)'s letter")
            XCTAssertEqual(face.dots, letter == nil ? 0 : try dots(entry, n), "\(what): face \(n)'s dots")
            XCTAssertEqual(face.isLighter, entry["lighter_face"] as? Int == n, "\(what): face \(n) lighter or not")
            let partner = (partners[n - 1] as? String).map { Array($0.utf8)[0] }
            XCTAssertEqual(face.mirrorPartner, partner ?? 0, "\(what): face \(n)'s mirror partner")
            let label = faceLabel(blank: face.isBlank, mirror: face.mirrorPartner != 0)
            XCTAssertEqual(label, letter == nil ? "leave blank" : (partner == nil ? "" : "mirror"), "\(what): face \(n)'s label")
        }
    }

    /// WordsScreensTest.kt's theInsertViewsTextsAreThePis and everyInsertPageIsTheVectorsWord, on the 24-word
    /// gate seed: every page is braille.json's insert of its word, its headers the Pi's, device 2 of 2 from 13.
    func testEveryInsertIsBrailleJsonsAndItsTextsAreThePis() throws {
        let braille = try Vectors.braille()
        let words = KcrVectors.words("dice-99-words24")
        XCTAssertEqual(words.count, 24)
        XCTAssertTrue(words.contains { $0.count == 3 }, "a three-letter word, whose faces 4 and 5 are blank")
        let rig = Rig().toHome().toSkippedResult("dice-99-words24").toWords()
        let first = try XCTUnwrap(rig.model.state.insert)
        XCTAssertEqual(insertHeader(first), "Insert 01 \u{00B7} device 1 of 2")
        XCTAssertEqual(readbackHeader(first), "Read back insert 01 \u{00B7} device 1 of 2")
        XCTAssertEqual(mismatchHeader(first), "Insert 01 does not match \u{00B7} device 1 of 2")
        XCTAssertEqual(faceSixText(first.sequence), "Face 6: the engraved number 01")
        let line = overviewLine(first)
        XCTAssertTrue(line.count == 16 && line.hasPrefix("01 ") && line.hasSuffix(digits(first.seedbook, 4)), "the overview line's layout")
        for (index, word) in words.enumerated() {
            if index == insertsPerDevice {
                XCTAssertEqual(rig.screen, .deviceSwap, "the device swap before word 13")
                rig.model.swapDone()
                rig.model.passGate()
            }
            let insert = try XCTUnwrap(rig.model.state.insert)
            XCTAssertEqual(insert.position, index + 1)
            XCTAssertTrue(sameWord(insert, word), "insert \(index + 1)'s word")
            try assertInsert(insert, word, try XCTUnwrap(braille[word]), "insert \(index + 1)")
            XCTAssertEqual(insert.sequence, index % insertsPerDevice + 1, "insert \(index + 1)'s engraved number")
            if index == insertsPerDevice {
                XCTAssertEqual(insertHeader(insert), "Insert 13 \u{00B7} device 2 of 2")
                XCTAssertEqual(faceSixText(insert.sequence), "Face 6: the engraved number 01")
            }
            rig.model.nextPage()
        }
    }

    /// CLAUDE.md's SeedBook cross-checks and its mirror pairs, against braille.json (WordsScreensTest.kt's).
    func testTheSeedBookCrossChecksAndTheMirrorPairs() throws {
        let braille = try Vectors.braille()
        for (word, number) in [("abandon", 1), ("act", 20), ("action", 21), ("metal", 1121), ("wire", 2018), ("zoo", 2048)] {
            let entry = try XCTUnwrap(braille[word])
            XCTAssertEqual(entry["number"] as? Int, number, word)
            XCTAssertEqual(seedbookText(number), "SeedBook " + digits(number, 4))
        }
        XCTAssertEqual(seedbookText(1), "SeedBook 0001")
        XCTAssertEqual(seedbookText(2048), "SeedBook 2048")
        let act = try XCTUnwrap(braille["act"]?["faces"] as? [Any])
        XCTAssertEqual(act.map { $0 as? String }, ["a", "c", "t", nil, nil], "act: a c t and two blank faces")
        let mirrors: [String: String] = ["e": "i", "i": "e", "d": "f", "f": "d", "h": "j", "j": "h", "r": "w", "w": "r"]
        for (word, entry) in braille {
            let faces = try XCTUnwrap(entry["faces"] as? [Any])
            let partners = try XCTUnwrap(entry["mirror_partners"] as? [Any])
            for n in 0..<5 {
                let letter = faces[n] as? String
                XCTAssertEqual(partners[n] as? String, letter.flatMap { mirrors[$0] }, "\(word) face \(n + 1): the mirror pairs e/i, d/f, h/j, r/w")
            }
        }
        let wire = try XCTUnwrap(braille["wire"]?["mirror_partners"] as? [Any])
        XCTAssertEqual(wire.map { $0 as? String }, ["r", "e", "w", "i", nil], "WIRE: every letter a mirror")
    }

    /// The read-back's lines: the faces typed, a wrong letter's dots (ReadbackScreensTest.kt's u read as q),
    /// the other verdicts, and the summary's fingerprint as hex.
    func testTheReadbacksLinesAndTheFingerprint() {
        let letters = letterPadEntry()
        XCTAssertEqual(typedFaces(letters), "----")
        letters.type("a")
        letters.type("b")
        XCTAssertEqual(typedFaces(letters), "ab--")
        XCTAssertEqual(verdictLine(1, FaceVerdict(verdict: .wrongLetter, missingDots: 0b100000, extraDots: 0b011010)),
                       "Face 1: wrong letter: missing 6, extra 2 4 5")
        XCTAssertEqual(verdictLine(2, FaceVerdict(verdict: .mirrorMisread, missingDots: 0, extraDots: 0)), "Face 2: mirror misread")
        XCTAssertEqual(verdictLine(4, FaceVerdict(verdict: .shouldBeBlank, missingDots: 0, extraDots: 0)), "Face 4: should be blank")
        XCTAssertEqual(verdictLine(4, FaceVerdict(verdict: .shouldHaveLetter, missingDots: 0, extraDots: 0)), "Face 4: should have a letter")
        XCTAssertEqual(verdictLine(3, FaceVerdict(verdict: .ok, missingDots: 0, extraDots: 0)), "Face 3: ok")
        XCTAssertEqual(verdictLine(1, FaceVerdict(verdict: .wrongLetter, missingDots: 0, extraDots: 1)), "Face 1: wrong letter: missing none, extra 1")
        XCTAssertEqual(fingerprintHex([0x00, 0x1A, 0xB2, 0xFF]), "001ab2ff")
    }

    /// ReadbackScreensTest.kt's summary: core's fingerprint as 8 hex digits, after the read-back of a 12-word seed.
    func testTheSummaryIsCores() throws {
        let rig = Rig().toHome().toSummary("dice-50-words12")
        XCTAssertEqual(rig.screen, .wallet)
        let summary = try XCTUnwrap(rig.model.state.summary)
        let hex = fingerprintHex(summary.fingerprint)
        XCTAssertEqual(hex.count, 8)
        XCTAssertTrue(hex.allSatisfy { "0123456789abcdef".contains($0) })
    }
}
