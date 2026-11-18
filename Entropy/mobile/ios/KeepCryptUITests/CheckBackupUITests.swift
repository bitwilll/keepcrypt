// Check a backup to "Backup OK" and its words behind the privacy gate (tasks/todo.md, M6 item D7), on the app
// itself: vectors/backup.json's abandon-12 file (work factor 10, a public test vector) handed to Check a
// backup's picker by the TestHooks build's Backup file hook (KC_HOOK_BACKUP_NAME and KC_HOOK_BACKUP_HEX in
// the launch environment; the system's document browser is not the app's to drive), the privacy gate before
// the entry, its passphrase's first four letters of each of the 8 words pressed on the letter pad (buttons,
// never the system keyboard), "Backup OK" with backup.json's fingerprint and kcr.json's Seal ID for that
// seed, Show the words, the privacy gate again (nothing of the words behind it), and insert 1. Compiled only
// where the UI tests' TestHooks configuration sets KC_TEST_HOOKS (the TestHooks scheme alone runs it).

#if KC_TEST_HOOKS
import XCTest

final class CheckBackupUITests: XCTestCase {
    /// One cause, one failure (U2f): a journey stops at its first failure, so a lost press is not followed by
    /// every later step failing for it.
    override func setUp() {
        continueAfterFailure = false
    }

    private final class Anchor {}

    private func json(_ name: String) throws -> [String: Any] {
        let file = try XCTUnwrap(Bundle(for: Anchor.self).url(forResource: name, withExtension: "json"))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
    }

    /// Waits for the element id, then past the press guard.
    private func on(_ app: XCUIApplication, _ id: String, _ what: String) {
        XCTAssertTrue(app.element(id).waitForExistence(timeout: 60), what)
        pastPressGuard()
    }

    /// Waits until the element id's label is label.
    private func label(_ app: XCUIApplication, _ id: String, _ label: String) {
        let shows = expectation(for: NSPredicate(format: "label == %@", label), evaluatedWith: app.element(id))
        XCTAssertEqual(XCTWaiter.wait(for: [shows], timeout: 30), .completed, label)
    }

    func testABackupFileOpensToBackupOkAndItsWordsShowOnlyPastTheGate() throws {
        let backup = try json("backup")
        let files = try XCTUnwrap(backup["age_files"] as? [[String: Any]])
        let entry = try XCTUnwrap(files.first { $0["name"] as? String == "abandon-12" })
        let file = Array(try XCTUnwrap(entry["file"] as? String).utf8)
        let words = try XCTUnwrap(entry["passphrase"] as? String).split(separator: " ").map(String.init)
        let plaintexts = try XCTUnwrap(backup["plaintexts"] as? [[String: Any]])
        let plain = try XCTUnwrap(plaintexts.first { $0["name"] as? String == "abandon-12" })
        let seeds = try XCTUnwrap(try json("kcr")["seeds"] as? [[String: Any]])
        let seed = try XCTUnwrap(seeds.first { $0["name"] as? String == "vector-1" })

        let app = XCUIApplication()
        app.launchEnvironment["KC_HOOK_BACKUP_NAME"] = "keepcrypt-backup-0123abcd.age"
        app.launchEnvironment["KC_HOOK_BACKUP_HEX"] = file.map { String(format: "%02x", $0) }.joined()
        app.launchedToGoOffline()
        app.buttons["hook_path_none"].tap()
        pastPressGuard()
        app.buttons["start"].tap()
        on(app, "home", "Home")
        app.buttons["check_backup"].tap()
        app.buttons["hook_backup_file"].tap()
        on(app, "privacy_gate", "the privacy gate before the entry")
        XCTAssertTrue(app.element("headphones_warning").exists)
        XCTAssertFalse(app.element("entry_word").exists, "nothing of the entry behind the gate")
        app.buttons["pass_gate"].tap()
        on(app, "backup_check_entry", "the passphrase's entry")
        for (index, word) in words.enumerated() {
            label(app, "entry_word", "Backup passphrase, word \(index + 1) of 8")
            app.letters(word)
            app.pressEnabled("entry_done")
        }
        on(app, "backup_check_result", "Backup OK")
        label(app, "backup_fingerprint", try XCTUnwrap(plain["fingerprint"] as? String))
        label(app, "backup_seal_id", try XCTUnwrap(seed["seal_id"] as? String))
        app.buttons["show_backup_words"].tap()
        on(app, "privacy_gate", "the privacy gate before the words")
        XCTAssertTrue(app.element("seedbook_rules").exists, "the SeedBook's rules on the gate before the words")
        XCTAssertFalse(app.element("insert_header").exists, "nothing of the words behind the gate")
        app.buttons["pass_gate"].tap()
        on(app, "words", "insert 1")
        XCTAssertEqual(app.element("insert_header").label, "Insert 01 \u{00B7} device 1 of 1")
    }
}
#endif
