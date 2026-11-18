// The check's, the read-back's and the save's edges on the phone (tasks/todo.md, M6 item U2), the model's tests
// holding every vector (every go-ahead text, every mirror pair, every damaged backup and snapshot): a dice-only
// seed of kcr.json's dice-50-words12; the scan with no Scan hook text, so the app's own scanner runs: it asks for
// the camera first, as Android's asks before it looks for one, and the simulator shows iOS's camera prompt, which
// this test refuses (Don't Allow): the scan screen says the camera was not allowed, offers Open Settings (M6-9)
// and the code (run 44212919474 left the prompt unanswered, which covered the app for the tests after it); the
// code typed from the drawn check
// QR; the read-back of insert 1 misread on a mirror pair (e for i: "mirror misread" on face 4) and read again,
// insert 2 read as insert 3's word (a wrong insert) and read again, the rest matched; and the backup saved
// through the Save hook in its corrupt mode (a byte of the read-back changed): the save names the verify's
// refusal, and Skip goes on. The simulator has no camera, so a camera allowed but absent (scanMissing) and one
// that fails are the model's tests' (CeremonyScanStopTests) and I2's. Through the UI alone but the hooks and iOS's
// prompt.

#if KC_TEST_HOOKS
import XCTest

final class CheckEdgesUITests: XCTestCase {
    func testARefusedCameraOffersSettingsAndTheCodeAMirrorMisreadAndAWrongInsertAreReadAgainAndACorruptSaveIsRefused() throws {
        let seed = try JourneyVectors.seed("dice-50-words12")
        let app = XCUIApplication()
        app.launchEnvironment["KC_HOOK_SAVE"] = "corrupt"
        let started = Date()
        app.toHome()
        app.toDice()
        app.roll(seed.rolls)
        app.press("check_now")
        app.on("seal_card", "the seal card")
        app.press("show_check_qr")
        app.on("check_qr", "the check QR")
        app.press("scan_qr")
        // iOS's camera prompt, from SpringBoard: refused, as a person may.
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        let refuse = springboard.alerts.buttons.matching(NSPredicate(format: "label BEGINSWITH %@", "Don")).firstMatch
        XCTAssertTrue(refuse.waitForExistence(timeout: 30), "iOS's camera prompt as the scan starts")
        refuse.tap()
        app.on("scan", "the scan screen")
        app.waitLabel(
            "scan_line", "The camera was not allowed, so the go-ahead QR cannot be scanned. Type the go-ahead code instead: the check stays open.")
        XCTAssertTrue(app.buttons["open_settings"].exists, "Open Settings after a refusal (M6-9)")
        XCTAssertTrue(app.buttons["type_code"].exists, "the code is offered")
        app.press("back")
        app.on("check_qr", "the check QR, the check kept")
        try app.typeGoAhead()
        pass("check edges: the camera refused at iOS's prompt, Open Settings and the code offered, the code typed (\(Int(Date().timeIntervalSince(started))) s)")
        app.press("show_words")
        app.passGate("the words")
        app.on("words", "insert 1")
        for position in 1..<seed.words.count {
            app.press("next")
            app.waitLabel("insert_header", String(format: "Insert %02d \u{00B7} device 1 of 1", position + 1))
        }
        app.press("start_readback")
        app.on("readback_entry", "the read-back")
        for (index, word) in seed.words.enumerated() {
            let position = index + 1
            app.waitLabel("readback_header", String(format: "Read back insert %02d \u{00B7} device 1 of 1", position))
            if position <= 2 {
                // Insert 1: its fourth face's e/i read as its mirror partner; insert 2: insert 3's word.
                var wrong = Array(word.prefix(4))
                if position == 1 {
                    let mirror: [Character: Character] = ["e": "i", "i": "e", "d": "f", "f": "d", "h": "j", "j": "h", "r": "w", "w": "r"]
                    let at = try XCTUnwrap(wrong.lastIndex { mirror[$0] != nil }, "a mirror-pair letter in insert 1's first four")
                    wrong[at] = try XCTUnwrap(mirror[wrong[at]])
                } else {
                    wrong = Array(seed.words[2].prefix(4))
                }
                app.letters(String(wrong))
                app.pressEnabled("letters_done")
                app.on("readback_mismatch", "insert \(position)'s mismatch")
                app.waitLabel("mismatch_header", String(format: "Insert %02d does not match \u{00B7} device 1 of 1", position))
                if position == 1 {
                    let misread = app.staticTexts.matching(NSPredicate(format: "label ENDSWITH %@", ": mirror misread")).firstMatch
                    XCTAssertTrue(misread.waitForExistence(timeout: 10), "a face named a mirror misread")
                }
                app.press("readback_again")
                app.on("readback_entry", "insert \(position)'s entry again")
            }
            app.letters(word)
            app.pressEnabled("letters_done")
            XCTAssertTrue(app.element("readback_matched").waitForExistence(timeout: 10), "insert \(position) matches")
            app.press("readback_next")
        }
        app.on("readback_done", "the read-back's end")
        app.press("show_summary")
        app.on("wallet", "the summary")
        pass("check edges: a mirror misread and a wrong insert each read again, all 12 matched (\(Int(Date().timeIntervalSince(started))) s)")
        _ = try app.backupMadeAndSaved(verified: false)
        XCTAssertFalse(app.element("backup_verified").exists)
        app.press("skip_watch_only")
        app.on("register_offer", "the registration's offer")
        app.press("skip_registration")
        app.checklistToFinish()
        pass("check edges: a corrupt save refused by the verify and skipped, Finish (\(Int(Date().timeIntervalSince(started))) s in all)")
    }
}
#endif
