// The app as its user starts it (tasks/todo.md, M6 items C2 and C3): XCUITest launches the built app,
// whose start-up self-test must pass, and the test-registry build alone shows its TEST REGISTRY strip.

import XCTest

final class StartUpUITests: XCTestCase {
    func testTheStartUpSelfTestPasses() {
        let app = XCUIApplication()
        app.launch()
        XCTAssertTrue(app.staticTexts["self_test_passed"].waitForExistence(timeout: 60), "Self-test passed")
        XCTAssertEqual(app.staticTexts["self_test_passed"].label, "Self-test passed")
        XCTAssertFalse(app.staticTexts["stopped"].exists, "no stop screen")
        #if KC_WITH_TEST_REGISTRY
        XCTAssertTrue(app.staticTexts["test_registry_strip"].exists, "the TEST REGISTRY strip")
        #else
        XCTAssertFalse(app.staticTexts["test_registry_strip"].exists, "no TEST REGISTRY strip in the shipping app")
        #endif
    }
}
