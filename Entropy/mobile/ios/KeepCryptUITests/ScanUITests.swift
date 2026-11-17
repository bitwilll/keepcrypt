// A go-ahead QR from the test registry, scanned (tasks/todo.md, M6 item D4; the Verification list's "the
// decoder on canned frames in CI"): the simulator has no camera, so the TestHooks build's scanner hands the
// launch environment's text (KC_HOOK_SCAN_TEXT) to the scan screen's found callback when the hook panel's
// Scan is pressed, the path a QR code before the camera takes; core parses and judges it. The test rolls
// vectors/kcr.json's gate seed dice-50-words12 on the dice pad, as a dice-only 12-word seed, checks it, and
// scans the proof collision-dice-50 (bundled kcr.json, rule 12): the collision result shows, with the
// proof's line. The TestHooks app links the test-registry core (D4's plan, (6)), whose key verifies the
// proof. Compiled only where the UI tests' TestHooks configuration sets KC_TEST_HOOKS.

#if KC_TEST_HOOKS
import XCTest

final class ScanUITests: XCTestCase {
    private final class Anchor {}

    /// kcr.json's entry named name in list.
    private func vector(_ list: String, _ name: String) throws -> [String: Any] {
        let file = try XCTUnwrap(Bundle(for: Anchor.self).url(forResource: "kcr", withExtension: "json"))
        let kcr = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
        let entries = try XCTUnwrap(kcr[list] as? [[String: Any]])
        return try XCTUnwrap(entries.first { $0["name"] as? String == name }, name)
    }

    func testAGoAheadQrFromTheTestRegistryRevealsItsResult() throws {
        let rolls = try XCTUnwrap(vector("seeds", "dice-50-words12")["rolls"] as? String)
        let text = try XCTUnwrap(vector("proofs", "collision-dice-50")["ur"] as? String)
        let app = XCUIApplication()
        app.launchEnvironment["KC_HOOK_SCAN_TEXT"] = text
        app.launchedToGoOffline()
        app.buttons["hook_path_none"].tap()
        let start = app.buttons["start"]
        XCTAssertTrue(start.waitForExistence(timeout: 10))
        pastPressGuard()
        start.tap()
        XCTAssertTrue(app.element("home").waitForExistence(timeout: 10), "Home")
        pastPressGuard()
        app.buttons["dice_only_seed"].tap()
        XCTAssertTrue(app.element("length").waitForExistence(timeout: 10), "Length")
        pastPressGuard()
        app.buttons["words_12"].tap()
        XCTAssertTrue(app.element("dice").waitForExistence(timeout: 60), "the dice")
        pastPressGuard()
        for face in rolls {
            app.buttons["key_" + String(face)].tap()
            app.buttons["confirm"].tap()
        }
        XCTAssertEqual(app.element("dice_count").label, "50 / 50 rolls, 129.2 bits")
        app.buttons["dice_done"].tap()
        XCTAssertTrue(app.element("check_prompt").waitForExistence(timeout: 60), "the check prompt")
        pastPressGuard()
        app.buttons["check_now"].tap()
        XCTAssertTrue(app.element("seal_card").waitForExistence(timeout: 10), "the seal card")
        XCTAssertEqual(app.element("seal_id").label, try XCTUnwrap(vector("seeds", "dice-50-words12")["seal_id"] as? String))
        pastPressGuard()
        app.buttons["show_check_qr"].tap()
        XCTAssertTrue(app.element("check_qr").waitForExistence(timeout: 10), "the check QR")
        // D8: a QR code is an image named by its kind, never by its data.
        let request = app.element("check_request")
        XCTAssertEqual(request.label, "Check QR code", "the check QR's VoiceOver label is its kind")
        XCTAssertEqual(request.elementType, .image, "the check QR is an image to VoiceOver")
        pastPressGuard()
        app.buttons["scan_qr"].tap()
        XCTAssertTrue(app.element("scan").waitForExistence(timeout: 10), "the scan screen")
        app.buttons["hook_scan"].tap()
        XCTAssertTrue(app.element("collision").waitForExistence(timeout: 60), "the collision result")
        XCTAssertEqual(app.element("collision_text").label, "Collision found. This seed is not unique and has been destroyed.")
        XCTAssertTrue(app.element("proof_line").label.hasPrefix("Proof from snapshot No. "), app.element("proof_line").label)
        XCTAssertFalse(app.element("stop").exists)
    }
}
#endif
