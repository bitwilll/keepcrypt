// Match found to Add fresh entropy at 99, then the new seed checked by a scanned proof to Finish (tasks/todo.md,
// M6 item U1; Android's JourneyTest matchFoundRestartsAt99Rolls...): a dice-only seed of kcr.json's
// dice-50-words12 by its 50 rolls on the dice pad, Check now's seal card with its Seal ID, the check QR's Match
// found and its confirm, the collision with the report behind its gate (the report QR named by its kind), and
// Add fresh entropy, whose dice need 99 rolls; dice-99-words12's 99 rolls, Check now's seal card, the check
// QR's Scan go-ahead QR with kcr.json's clear-empty-bucket (clear for that seal) handed by the Scan hook, the
// check passed; the 12 words, the vector's, and their read-back on the letter pad; the summary; the backup and
// watch-only skipped; the registration QR behind its gate (named by its kind); the checklist and Finish.
// Through the UI alone but the offline path and the scan (the hooks).

#if KC_TEST_HOOKS
import XCTest

final class MatchFoundJourneyUITests: XCTestCase {
    /// One cause, one failure (U2f): a journey stops at its first failure, so a lost press is not followed by
    /// every later step failing for it.
    override func setUp() {
        continueAfterFailure = false
    }

    func testMatchFoundRestartsAt99AndAScannedProofChecksTheNewSeedToFinish() throws {
        let first = try JourneyVectors.seed("dice-50-words12")
        let second = try JourneyVectors.seed("dice-99-words12")
        let app = XCUIApplication()
        app.launchEnvironment["KC_HOOK_SCAN_TEXT"] = try JourneyVectors.proof("clear-empty-bucket")
        let started = Date()
        app.toHome()
        app.press("dice_only_seed")
        app.on("length", "Length")
        app.press("words_12")
        app.on("dice", "the dice")
        app.roll(first.rolls)
        app.press("check_now")
        app.on("seal_card", "the seal card")
        XCTAssertEqual(app.element("seal_id").label, first.sealId)
        app.press("show_check_qr")
        app.on("check_qr", "the check QR")
        app.press("match_found")
        app.on("match_found_confirm", "Match found's confirm")
        app.press("confirm_action")
        app.on("collision", "the collision")
        app.waitLabel("collision_text", "Collision found. This seed is not unique and has been destroyed.")
        app.press("show_report")
        app.passGate("the collision report")
        app.on("collision_report", "the collision report")
        XCTAssertTrue(app.images["Collision report QR code"].exists, "the report QR, named by its kind")
        app.press("add_fresh_entropy")
        app.on("dice", "the fresh dice")
        app.waitLabel("dice_count", "0 / 99 rolls, 0.0 bits")
        pass("match found: dice-50-words12's 50 rolls, Match found and its confirm, the collision and its report, Add fresh entropy at 0 / 99 (\(Int(Date().timeIntervalSince(started))) s)")
        app.roll(second.rolls)
        app.press("check_now")
        app.on("seal_card", "the new seal card")
        XCTAssertEqual(app.element("seal_id").label, second.sealId)
        app.press("show_check_qr")
        app.on("check_qr", "the new check QR")
        app.press("scan_qr")
        app.on("scan", "the scan screen")
        app.press("hook_scan")
        app.on("check_result", "the check passed by the scanned proof")
        XCTAssertTrue(app.element("proof_line").label.hasPrefix("Proof from snapshot No. 2, dated 2026-03-01"))
        app.press("show_words")
        app.passGate("the words")
        app.on("words", "insert 1")
        app.wordsAndReadback(12, expected: second.words)
        app.press("summary_next")
        app.on("backup_offer", "the backup's offer")
        app.press("skip_backup")
        app.on("watch_offer", "the watch-only offer")
        app.press("skip_watch_only")
        app.on("register_offer", "the registration's offer")
        app.press("show_registration")
        app.passGate("the registration QR")
        app.on("register_qr", "the registration QR")
        XCTAssertTrue(app.images["Registration QR code"].exists, "the registration QR, named by its kind")
        app.press("registration_done")
        app.checklistToFinish()
        pass("match found: dice-99-words12's 99 rolls, a scanned proof (clear-empty-bucket) passed, its 12 words and read-back, the summary, Skip twice, the registration QR, the checklist and Finish: Home (\(Int(Date().timeIntervalSince(started))) s in all)")
    }
}
#endif
