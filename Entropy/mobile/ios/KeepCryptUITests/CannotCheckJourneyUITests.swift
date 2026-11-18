// Cannot check to Start again, then a scanned collision to Add fresh entropy at 99, and the new seed checked by
// its typed code to Finish (tasks/todo.md, M6 item U1; Android's JourneyTest cannotCheckStartsAgain... and
// ScanUITests' collision): a dice-only seed of kcr.json's dice-50-words12 by its 50 rolls, Check now's check QR,
// Cannot check and its confirm's Back, then its confirm: the seed wiped unseen and a new ceremony at once, its
// dice at 0 / 50; dice-50-words12's 50 rolls again, the check QR's Scan go-ahead QR with kcr.json's
// collision-dice-50 handed by the Scan hook: the collision, its report behind the gate, and Add fresh entropy at
// 0 / 99; dice-99-words12's 99 rolls, the check QR's code typed (built from the drawn QR's T and nonce): the
// check passed; the 12 words, the vector's, read back; the summary; every export skipped; the checklist and
// Finish. Through the UI alone but the offline path and the scan (the hooks).

#if KC_TEST_HOOKS
import XCTest

final class CannotCheckJourneyUITests: XCTestCase {
    /// One cause, one failure (U2f): a journey stops at its first failure, so a lost press is not followed by
    /// every later step failing for it.
    override func setUp() {
        continueAfterFailure = false
    }

    func testCannotCheckStartsAgainAScannedCollisionRestartsAt99AndATypedCodeChecksToFinish() throws {
        let first = try JourneyVectors.seed("dice-50-words12")
        let second = try JourneyVectors.seed("dice-99-words12")
        let app = XCUIApplication()
        app.launchEnvironment["KC_HOOK_SCAN_TEXT"] = try JourneyVectors.proof("collision-dice-50")
        let started = Date()
        app.toHome()
        app.press("dice_only_seed")
        app.on("length", "Length")
        app.press("words_12")
        app.on("dice", "the dice")
        app.roll(first.rolls)
        app.press("check_now")
        app.on("seal_card", "the seal card")
        let sealId = app.element("seal_id").label
        app.press("show_check_qr")
        app.on("check_qr", "the check QR")
        // U3b: the check QR's Back, the seal card again with the same check (Android's system Back; the note
        // says "compare ... with the seal card (Back)"). Before U3b the iPhone drew no Back here.
        app.pressTo("back", "seal_card")
        XCTAssertEqual(app.element("seal_id").label, sealId, "the same seal")
        app.pressTo("show_check_qr", "check_qr")
        app.press("cannot_check")
        app.on("cannot_check_confirm", "Cannot check's confirm")
        app.press("back")
        app.on("check_qr", "Back: the check QR, the check kept")
        app.press("cannot_check")
        app.on("cannot_check_confirm", "Cannot check's confirm again")
        app.press("confirm_action")
        app.on("dice", "a new ceremony's dice")
        app.waitLabel("dice_count", "0 / 50 rolls, 0.0 bits")
        pass("cannot check: dice-50-words12's 50 rolls, Cannot check, Back, Start again: a new ceremony at 0 / 50 (\(Int(Date().timeIntervalSince(started))) s)")
        app.roll(first.rolls)
        app.press("check_now")
        app.on("seal_card", "the seal card again")
        XCTAssertEqual(app.element("seal_id").label, first.sealId)
        app.press("show_check_qr")
        app.on("check_qr", "the check QR again")
        app.press("scan_qr")
        app.on("scan", "the scan screen")
        app.press("hook_scan")
        app.on("collision", "the scanned collision")
        XCTAssertTrue(app.element("proof_line").label.hasPrefix("Proof from snapshot No. 4, dated 2026-03-01"))
        app.press("show_report")
        app.passGate("the collision report")
        app.on("collision_report", "the collision report")
        app.press("add_fresh_entropy")
        app.on("dice", "the fresh dice")
        app.waitLabel("dice_count", "0 / 99 rolls, 0.0 bits")
        pass("cannot check: the same 50 rolls, a scanned collision (collision-dice-50), its report, Add fresh entropy at 0 / 99 (\(Int(Date().timeIntervalSince(started))) s)")
        app.roll(second.rolls)
        app.press("check_now")
        app.on("seal_card", "the new seal card")
        XCTAssertEqual(app.element("seal_id").label, second.sealId)
        app.press("show_check_qr")
        app.on("check_qr", "the new check QR")
        try app.typeGoAhead()
        app.press("show_words")
        app.passGate("the words")
        app.on("words", "insert 1")
        app.wordsAndReadback(12, expected: second.words)
        app.skipExports()
        app.checklistToFinish()
        pass("cannot check: dice-99-words12's 99 rolls, the typed code passed, its 12 words read back, the summary, every export skipped, Finish: Home (\(Int(Date().timeIntervalSince(started))) s in all)")
    }
}
#endif
