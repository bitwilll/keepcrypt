// The offline check in the running app (tasks/todo.md, M6 item C5), through the TestHooks build's path
// hooks (the offline check's state forced, since the runners' simulators are online): Go offline's
// Start is disabled while a path is usable and enabled only once none is, and going online on Home,
// with nothing held, brings Go offline back with nothing to say. Compiled only where the UI tests'
// TestHooks configuration sets KC_TEST_HOOKS.

#if KC_TEST_HOOKS
import XCTest

final class OfflineUITests: XCTestCase {
    private func enabled(_ element: XCUIElement, _ want: Bool) -> Bool {
        let done = expectation(for: NSPredicate(format: "isEnabled == %@", NSNumber(value: want)), evaluatedWith: element)
        return XCTWaiter.wait(for: [done], timeout: 10) == .completed
    }

    func testStartOnlyOfflineAndGoingOnlineBringsGoOfflineBack() {
        let app = XCUIApplication()
        app.launchedToGoOffline()
        let start = app.buttons["start"]
        app.buttons["hook_path_usable"].tap()
        XCTAssertTrue(enabled(start, false), "Start disabled while a path is usable")
        start.tap()
        XCTAssertFalse(app.element("home").exists, "and a press does nothing")
        app.buttons["hook_path_none"].tap()
        XCTAssertTrue(enabled(start, true), "Start enabled with no usable path")
        app.pressTo("start", "home")
        app.buttons["hook_path_usable"].tap()
        XCTAssertTrue(start.waitForExistence(timeout: 10), "Go offline again")
        XCTAssertTrue(enabled(start, false))
        XCTAssertFalse(app.element("home").exists)
        XCTAssertFalse(app.element("notice").exists, "nothing was held, so nothing to say")
    }
}
#endif
