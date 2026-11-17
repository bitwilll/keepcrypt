// The app as its user starts it (tasks/todo.md, M6 items C2, C3 and D2): XCUITest launches the built app,
// which shows First launch first, before any core call, and whose start-up self-test, run by its
// Continue, must pass; the test-registry build alone shows its TEST REGISTRY strip, and
// the TestHooks build alone (C5, M6-5) its hook panel.

import XCTest

final class StartUpUITests: XCTestCase {
    func testTheStartUpSelfTestPasses() {
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.staticTexts["first_launch"].waitForExistence(timeout: 30), "First launch first")
        XCTAssertFalse(app.staticTexts["self_test_passed"].exists, "no self-test before Continue")
        app.buttons["continue"].tap()
        XCTAssertTrue(app.staticTexts["self_test_passed"].waitForExistence(timeout: 60), "Self-test passed")
        XCTAssertEqual(app.staticTexts["self_test_passed"].label, "Self-test passed")
        XCTAssertFalse(app.staticTexts["stopped"].exists, "no stop screen")
        #if KC_TEST_HOOKS
        XCTAssertTrue(app.staticTexts["KC_TEST_HOOKS_DO_NOT_SHIP"].exists, "the hook panel in the TestHooks build")
        #else
        XCTAssertFalse(app.staticTexts["KC_TEST_HOOKS_DO_NOT_SHIP"].exists, "no hook panel in a shipped build")
        #endif
        #if KC_WITH_TEST_REGISTRY
        XCTAssertTrue(app.staticTexts["test_registry_strip"].exists, "the TEST REGISTRY strip")
        #else
        XCTAssertFalse(app.staticTexts["test_registry_strip"].exists, "no TEST REGISTRY strip in the shipping app")
        #endif
    }
}
