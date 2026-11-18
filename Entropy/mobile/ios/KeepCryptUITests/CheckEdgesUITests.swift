// The check's, the read-back's and the save's edges on the phone (tasks/todo.md, M6 item U2), the model's tests
// holding every vector (every go-ahead text, every mirror pair, every damaged backup and snapshot): a dice-only
// seed of kcr.json's dice-50-words12; on the scan screen the simulator's missing camera (no Scan hook text, so the
// app's own scanner runs: this phone has no camera, and the code is offered); the code typed from the drawn check
// QR; the read-back of insert 1 misread on a mirror pair (e for i: "mirror misread" on face 4) and read again,
// insert 2 read as insert 3's word (a wrong insert) and read again, the rest matched; and the backup saved
// through the Save hook in its corrupt mode (a byte of the read-back changed): the save names the verify's
// refusal, and Skip goes on. The camera refused (M6-9's Open Settings) needs a camera, which the simulator has
// not: the model's tests and I2 hold it. Through the UI alone but the hooks.

#if KC_TEST_HOOKS
import XCTest

final class CheckEdgesUITests: XCTestCase {
    func testNoCameraOffersTheCodeAMirrorMisreadAndAWrongInsertAreReadAgainAndACorruptSaveIsRefused() throws {
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
        app.on("scan", "the scan screen")
        app.waitLabel("scan_line", "This phone has no camera the app can use. Type the go-ahead code instead: the check stays open.")
        XCTAssertTrue(app.buttons["type_code"].exists, "the code is offered")
        app.press("back")
        app.on("check_qr", "the check QR, the check kept")
        try app.typeGoAhead()
        pass("check edges: no camera on the simulator, the code offered and typed (\(Int(Date().timeIntervalSince(started))) s)")
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
