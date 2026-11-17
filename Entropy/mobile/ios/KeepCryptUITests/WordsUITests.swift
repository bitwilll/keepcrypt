// The words through the privacy gate to the read-back (tasks/todo.md, M6 item D5), on the app itself: vectors/
// kcr.json's gate seed dice-50-words12 rolled on the dice pad as a dice-only 12-word seed, the check skipped
// and confirmed, Show words, the privacy gate's "I'm alone, show words", insert 1 (its header outside the
// secure layer; the word, SeedBook number and faces are inside it, and D8 checks only that a SeedBook line is
// reachable there, by its prefix), the pages to insert 12, the read-back started, the letter pad's keys each
// labelled with its letter (D8), insert 1's first four letters pressed on it (buttons, never the system
// keyboard), its match, and Next to insert 2's entry. The journeys past it are Stage U's.
// Compiled only where the UI tests' TestHooks configuration sets KC_TEST_HOOKS (the TestHooks scheme alone
// runs it, to keep the shipped schemes' runs short).

#if KC_TEST_HOOKS
import XCTest

final class WordsUITests: XCTestCase {
    private final class Anchor {}

    /// kcr.json's gate seed dice-50-words12: its rolls and its words.
    private func seed() throws -> (rolls: String, words: [String]) {
        let file = try XCTUnwrap(Bundle(for: Anchor.self).url(forResource: "kcr", withExtension: "json"))
        let kcr = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
        let seeds = try XCTUnwrap(kcr["seeds"] as? [[String: Any]])
        let entry = try XCTUnwrap(seeds.first { $0["name"] as? String == "dice-50-words12" })
        let mnemonic = try XCTUnwrap(entry["mnemonic"] as? String)
        return (try XCTUnwrap(entry["rolls"] as? String), mnemonic.split(separator: " ").map(String.init))
    }

    /// Waits for the screen whose root is id, then past the press guard.
    private func on(_ app: XCUIApplication, _ id: String, _ what: String) {
        XCTAssertTrue(app.element(id).waitForExistence(timeout: 60), what)
        pastPressGuard()
    }

    func testTheWordsThroughThePrivacyGateToTheReadback() throws {
        let (rolls, words) = try seed()
        let app = XCUIApplication()
        app.launchedToGoOffline()
        app.buttons["hook_path_none"].tap()
        pastPressGuard()
        app.buttons["start"].tap()
        on(app, "home", "Home")
        app.buttons["dice_only_seed"].tap()
        on(app, "length", "Length")
        app.buttons["words_12"].tap()
        on(app, "dice", "the dice")
        for face in rolls {
            app.buttons["key_" + String(face)].tap()
            app.buttons["confirm"].tap()
        }
        app.buttons["dice_done"].tap()
        on(app, "check_prompt", "the check prompt")
        app.buttons["skip"].tap()
        on(app, "skip_confirm", "Skip's confirm")
        app.buttons["confirm_action"].tap()
        on(app, "check_result", "the result before the words")
        app.buttons["show_words"].tap()
        on(app, "privacy_gate", "the privacy gate before the words")
        XCTAssertTrue(app.element("seedbook_rules").exists, "the SeedBook's rules on the gate before the words")
        XCTAssertFalse(app.element("insert_header").exists, "nothing of the words behind the gate")
        app.buttons["pass_gate"].tap()
        on(app, "words", "insert 1")
        XCTAssertEqual(app.element("insert_header").label, "Insert 01 \u{00B7} device 1 of 1")
        XCTAssertEqual(app.element("face_six").label, "Face 6: the engraved number 01")
        // D8: what SecureLayer draws is reachable to VoiceOver (the iPhone's residual: no sensitive mark), as
        // the words are to TalkBack: the SeedBook number drawn inside it is in the accessibility tree. Its
        // value is compared by prefix alone and never printed.
        let seedbook = app.staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@", "SeedBook "))
        XCTAssertEqual(seedbook.count, 1, "the secure layer's content is not reachable to VoiceOver")
        for _ in 1..<words.count {
            app.buttons["next"].tap()
        }
        XCTAssertEqual(app.element("insert_header").label, "Insert 12 \u{00B7} device 1 of 1")
        app.buttons["start_readback"].tap()
        on(app, "readback_entry", "the read-back's entry")
        XCTAssertEqual(app.element("readback_header").label, "Read back insert 01 \u{00B7} device 1 of 1")
        // D8: each Protected pad key is a button whose VoiceOver label is its letter (and no identifier).
        for letter in "abcdefghijklmnopqrstuvwxyz" {
            let key = app.buttons[String(letter)]
            XCTAssertTrue(key.exists && key.label == String(letter), "the letter pad's key " + String(letter))
        }
        for letter in words[0].prefix(4) {
            app.buttons[String(letter)].tap()
        }
        app.buttons["letters_done"].tap()
        XCTAssertTrue(app.element("readback_matched").waitForExistence(timeout: 10), "insert 1 matches")
        app.buttons["readback_next"].tap()
        let next = NSPredicate(format: "label == %@", "Read back insert 02 \u{00B7} device 1 of 1")
        let moved = expectation(for: next, evaluatedWith: app.element("readback_header"))
        XCTAssertEqual(XCTWaiter.wait(for: [moved], timeout: 10), .completed, "insert 2's entry")
    }
}
#endif
