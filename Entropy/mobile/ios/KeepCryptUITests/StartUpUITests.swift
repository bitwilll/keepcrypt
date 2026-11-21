// The app as its user starts it (tasks/todo.md, M6 items C2, C3, D2 and D3): XCUITest launches the built app,
// which shows First launch first, before any core call, and whose start-up self-test, run by its
// Continue, must pass; the test-registry build alone shows its TEST REGISTRY strip, and
// the TestHooks build alone (C5, M6-5) its hook panel.

import XCTest

final class StartUpUITests: XCTestCase {
    func testTheStartUpSelfTestPasses() {
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.element("first_launch").waitForExistence(timeout: 30), "First launch first")
        XCTAssertFalse(app.element("go_offline").exists, "no self-test before Continue")
        pastPressGuard()
        app.buttons["first_launch_continue"].tap()
        XCTAssertTrue(app.element("go_offline").waitForExistence(timeout: 60), "the self-test passed: Go offline")
        XCTAssertFalse(app.element("stop").exists, "no stop screen")
        #if KC_TEST_HOOKS
        XCTAssertTrue(app.staticTexts["KC_TEST_HOOKS_DO_NOT_SHIP"].exists, "the hook panel in the TestHooks build")
        #else
        XCTAssertFalse(app.staticTexts["KC_TEST_HOOKS_DO_NOT_SHIP"].exists, "no hook panel in a shipped build")
        #endif
        #if KC_WITH_TEST_REGISTRY
        XCTAssertTrue(app.element("test_registry_strip").exists, "the TEST REGISTRY strip")
        #else
        XCTAssertFalse(app.element("test_registry_strip").exists, "no TEST REGISTRY strip in the shipping app")
        #endif
    }
}
