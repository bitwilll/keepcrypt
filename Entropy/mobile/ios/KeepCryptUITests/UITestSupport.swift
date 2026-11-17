// What the UI tests share (tasks/todo.md, M6 item D3): an element found by its accessibility identifier,
// whatever its kind (a screen's root carries its screen id, as Android's root carries its test tag), the
// way past First launch, and the wait past the press guard before a deliberate press (PressGuard.swift:
// a view admits no touch until 300 ms after it was shown, as a person's first look takes).

import XCTest

extension XCUIApplication {
    /// The element whose identifier is id, of any kind.
    func element(_ id: String) -> XCUIElement {
        descendants(matching: .any).matching(identifier: id).firstMatch
    }

    /// Launched, First launch's Continue pressed, the start-up self-test passed: Go offline.
    func launchedToGoOffline(file: StaticString = #filePath, line: UInt = #line) {
        launch()
        XCTAssertTrue(element("first_launch").waitForExistence(timeout: 30), "First launch first", file: file, line: line)
        pastPressGuard()
        buttons["first_launch_continue"].tap()
        XCTAssertTrue(element("go_offline").waitForExistence(timeout: 60), "the self-test passed: Go offline", file: file, line: line)
        pastPressGuard()
    }
}

/// Waits past the press guard's 300 ms after a screen appeared, before a deliberate press.
func pastPressGuard() {
    usleep(500_000)
}
