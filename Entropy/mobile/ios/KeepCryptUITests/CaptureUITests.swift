// The capture layers in the running app (tasks/todo.md, M6 item C5), through the TestHooks build's hook
// panel, since a simulator cannot record or mirror its own screen or take a hardware screenshot: the
// capture cover and the privacy cover each replace the whole scene and go when their state ends, and a
// screenshot discards the session (Core's discard, whose done reply alone puts up the notice) on a
// Public screen with no secret held. Compiled only where the UI tests' TestHooks configuration sets
// KC_TEST_HOOKS; the shipped schemes' apps hold no hooks.

#if KC_TEST_HOOKS
import XCTest

final class CaptureUITests: XCTestCase {
    private func launched() -> XCUIApplication {
        let app = XCUIApplication()
        app.launchedToGoOffline()
        return app
    }

    func testTheCaptureCoverReplacesTheSceneWhileCaptured() {
        let app = launched()
        XCTAssertFalse(app.element("capture_cover").exists)
        app.buttons["hook_capture"].tap()
        XCTAssertTrue(app.element("capture_cover").waitForExistence(timeout: 10), "the capture cover")
        XCTAssertFalse(app.element("go_offline").exists, "nothing of the screen under it")
        XCTAssertFalse(app.buttons["start"].exists, "nor its Start")
        app.buttons["hook_capture"].tap()
        XCTAssertTrue(app.element("go_offline").waitForExistence(timeout: 10), "the screen again")
        XCTAssertFalse(app.element("capture_cover").exists)
    }

    func testThePrivacyCoverReplacesTheSceneWhileInactive() {
        let app = launched()
        app.buttons["hook_inactive"].tap()
        XCTAssertTrue(app.element("privacy_cover").waitForExistence(timeout: 10), "the privacy cover")
        XCTAssertFalse(app.element("go_offline").exists, "nothing of the screen under it")
        app.buttons["hook_capture"].tap()
        XCTAssertTrue(app.element("capture_cover").waitForExistence(timeout: 10), "capture first")
        app.buttons["hook_capture"].tap()
        XCTAssertTrue(app.element("privacy_cover").waitForExistence(timeout: 10))
        app.buttons["hook_inactive"].tap()
        XCTAssertTrue(app.element("go_offline").waitForExistence(timeout: 10), "the screen again")
        XCTAssertFalse(app.element("privacy_cover").exists)
    }

    func testAScreenshotDiscardsTheSessionAndSaysWhy() {
        let app = launched()
        XCTAssertFalse(app.element("notice").exists)
        app.buttons["hook_screenshot"].tap()
        let notice = app.element("notice")
        XCTAssertTrue(notice.waitForExistence(timeout: 10), "the discard's notice")
        XCTAssertTrue(notice.label.hasPrefix("The session was wiped: a screenshot was taken."), notice.label)
        XCTAssertTrue(app.element("go_offline").exists, "the app goes on, on its start screen")
        XCTAssertFalse(app.element("stop").exists, "Core's discard was done, not halted")
    }
}
#endif
