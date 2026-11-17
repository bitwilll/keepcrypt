// Core over the real kc_call (tasks/todo.md, M6 item C3): this test bundle links the configuration's
// libkeepcrypt_capi.a and compiles the app's Core.swift, Wire.swift and Ceremony.swift itself, so it
// runs in a process of its own with a fresh slot, never the app's. The slot is the process's one and
// its first halt latches, so the whole walk is one test, in order: the self-test, a dice-only
// ceremony refused twice at its check and stopped, the same ceremony again to its 12 words
// (dice-50-words12, against kcr.json's mnemonic and braille.json), Finish, and last the halts, which
// end the slot for good. After every call the reply buffer holds nothing but zeros.

import XCTest

final class CoreTests: XCTestCase {
    private let core = Core.shared

    /// keepcrypt-capi's input cap, a full snapshot with its date (its MAX_INPUT).
    private let maxInput = 4 + 122 + 18 * (1 << 22)

    private func assertWiped(_ step: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertTrue(core.replyBufferIsWiped(), "the reply buffer after \(step)", file: file, line: line)
    }

    /// Gate seed dice-50-words12 from Start to Sealed: 12 words, dice only, its 50 rolls.
    private func sealed(_ rolls: String) throws {
        try done(core.start(.twelve, .diceOnly), "start")
        try done(core.commit(), "commit")
        try done(core.startDice(), "start dice")
        for face in rolls.utf8 {
            try done(core.pushRoll(Int(face - UInt8(ascii: "0"))), "a roll")
            assertWiped("a roll")
        }
        let progress = try done(core.diceProgress(), "dice progress")
        XCTAssertEqual([progress.rolls, progress.minimum], [50, 50])
        XCTAssertEqual(progress.millibits, 50 * 2_585)
        try done(core.finish(), "finish")
        assertWiped("finish")
    }

    func testTheSlotFromStartUpToItsHalt() throws {
        assertWiped("nothing")
        let seed = try Vectors.seed("dice-50-words12")
        let rolls = try XCTUnwrap(seed["rolls"] as? String)
        XCTAssertEqual(rolls.count, 50)

        // The start-up self-test passes.
        XCTAssertEqual(StartScreen(selfTest: core.selfTest()), .passed)
        assertWiped("the self-test")

        // A check: a wrong code and a malformed one are refused (the stage stays Checking), then
        // Cannot check stops it, the seed wiped unseen.
        try sealed(rolls)
        let card = try done(core.seal(), "seal")
        XCTAssertEqual(card.sealId, seed["seal_id"] as? String)
        try done(core.startCheck(), "start check")
        XCTAssertEqual(refusal(core.revealCode(Secret(taking: Array("ZZZZ-ZZZZ".utf8)))), .wrongCode)
        assertWiped("a wrong code")
        XCTAssertEqual(refusal(core.revealCode(Secret(taking: Array("0000".utf8)))), .malformedCode)
        assertWiped("a malformed code")
        try done(core.cannotCheck(), "cannot check")

        // The restart to Ready by Skip, and its 12 words pages.
        try sealed(rolls)
        try done(core.skipCheck(), "skip")
        let mnemonic = try XCTUnwrap(seed["mnemonic"] as? String).split(separator: " ").map(String.init)
        XCTAssertEqual(mnemonic.count, 12)
        let braille = try Vectors.braille()
        for (index, expected) in mnemonic.enumerated() {
            let position = index + 1
            let page = try done(core.wordPage(position), "words page \(position)")
            assertWiped("words page \(position)")
            try checkPage(page, position: position, word: expected, braille: try XCTUnwrap(braille[expected]))
            page.wipe()
            let wiped = page.word()
            XCTAssertTrue((0..<wiped.count).allSatisfy { wiped[$0] == 0 }, "page \(position) wiped")
        }
        try done(core.end(), "finish the ceremony")
        try done(core.selfTest(), "the self-test at home again")

        // kc_call's -1: a snapshot one byte past the input cap halts before a byte is read, and the
        // call gives the halt the slot latched, internal; every later call gives it too, and the
        // start-up screen is the stop screen.
        let tooLong = [UInt8](repeating: 0, count: maxInput - 4 + 1)
        XCTAssertEqual(haltReason(core.loadSnapshot(today: 20_261_117, file: tooLong)), .internal)
        assertWiped("the halt")
        XCTAssertEqual(haltReason(core.selfTest()), .internal)
        XCTAssertEqual(StartScreen(selfTest: core.selfTest()), .stopped(.internal))
        XCTAssertEqual(haltReason(core.start(.twelve, .diceOnly)), .internal)
        assertWiped("a call after the halt")
    }

    /// A words page as wire.rs lays it out, against kcr.json's word and braille.json's entry: insert
    /// position of 12 on device 1 of 1, face 6's sequence, the SeedBook number, the word, and faces
    /// 1-5 (the letter, its dots from the word's cells, the lighter flag, the mirror partner).
    private func checkPage(_ page: WordPage, position: Int, word: String, braille: [String: Any]) throws {
        XCTAssertEqual([page.position, page.count, page.device, page.devices, page.sequence], [position, 12, 1, 1, position])
        XCTAssertEqual(page.seedbook, braille["number"] as? Int, "insert \(position)")
        let secret = page.word()
        XCTAssertEqual((0..<secret.count).map { secret[$0] }, Array(word.utf8), "insert \(position)")
        let faces = try XCTUnwrap(braille["faces"] as? [Any])
        let partners = try XCTUnwrap(braille["mirror_partners"] as? [Any])
        let cells = Array(try XCTUnwrap(braille["cells"] as? String).unicodeScalars)
        let lighter = braille["lighter_face"] as? Int
        for n in 1...5 {
            let face = page.face(n)
            let letter = faces[n - 1] as? String
            XCTAssertEqual(face.letter, letter.map { Array($0.utf8)[0] } ?? 0, "insert \(position) face \(n)")
            XCTAssertEqual(face.dots, letter == nil ? 0 : UInt8(cells[n - 1].value - 0x2800), "insert \(position) face \(n)")
            XCTAssertEqual(face.isLighter, lighter == n, "insert \(position) face \(n)")
            let partner = partners[n - 1] as? String
            XCTAssertEqual(face.mirrorPartner, partner.map { Array($0.utf8)[0] } ?? 0, "insert \(position) face \(n)")
        }
    }
}
