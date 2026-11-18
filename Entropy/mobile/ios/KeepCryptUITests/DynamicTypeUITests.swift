// Dynamic Type at its largest accessibility size (tasks/todo.md, M6 item U2; Q78's full range on Android, its
// font scale to 2.0; MA's 360 dp rule: actions scroll and nothing is cut): the app's text is measured at the
// default size and at UICTContentSizeCategoryAccessibilityXXXL (a launch argument, as the system's setting sets
// it), and must grow (KitType scales with the text size, at most twice); then, at that size, every control of
// First launch, Go offline, Home, About, Length and the dice is reached (scrolled into view where the screen
// scrolls) and hittable. Before U2b the kit's sizes were fixed points, so the text did not grow and this test
// failed at its first assertion. Through the UI alone but the offline path (the hook).

#if KC_TEST_HOOKS
import XCTest

final class DynamicTypeUITests: XCTestCase {
    /// The First launch title's height, launched with arguments.
    private func titleHeight(_ app: XCUIApplication) -> CGFloat {
        app.launch()
        XCTAssertTrue(app.element("first_launch").waitForExistence(timeout: 30), "First launch")
        // First launch's own title (the privacy cover, should the scene not be active, says KeepCrypt too).
        let title = app.element("first_launch").staticTexts["KeepCrypt"].firstMatch
        XCTAssertTrue(title.waitForExistence(timeout: 10), "the app's name")
        return title.frame.height
    }

    /// The control id scrolled into view (the screen's column swiped up, at most six times) and hittable.
    private func reach(_ app: XCUIApplication, _ id: String) {
        let control = app.buttons[id]
        XCTAssertTrue(control.waitForExistence(timeout: 30), id)
        var swipes = 0
        while !control.isHittable, swipes < 6 {
            app.swipeUp()
            swipes += 1
        }
        XCTAssertTrue(control.isHittable, id + " cut: not reachable at the largest text size")
    }

    func testTheLargestTextSizeGrowsTheTextAndEveryControlStaysReachable() {
        let plain = XCUIApplication()
        let small = titleHeight(plain)
        plain.terminate()
        let app = XCUIApplication()
        app.launchArguments += ["-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL"]
        let large = titleHeight(app)
        XCTAssertGreaterThan(large, small * 1.5, "the text did not grow with the text size (\(small) to \(large) points)")
        pastPressGuard()
        reach(app, "first_launch_continue")
        app.buttons["first_launch_continue"].tap()
        app.on("go_offline", "Go offline", timeout: 60)
        app.buttons["hook_path_none"].tap()
        reach(app, "start")
        app.buttons["start"].tap()
        app.on("home", "Home")
        for id in ["new_seed", "dice_only_seed", "check_backup", "load_snapshot", "show_about"] {
            reach(app, id)
        }
        app.buttons["show_about"].tap()
        app.on("about", "About")
        reach(app, "back")
        app.buttons["back"].tap()
        app.on("home", "Home")
        reach(app, "dice_only_seed")
        app.buttons["dice_only_seed"].tap()
        app.on("length", "Length")
        reach(app, "words_24")
        reach(app, "words_12")
        app.buttons["words_12"].tap()
        app.on("dice", "the dice")
        for id in ["key_1", "key_2", "key_3", "key_4", "key_5", "key_6", "undo", "confirm", "dice_done"] {
            reach(app, id)
        }
        pass("dynamic type: the text \(Int(small)) to \(Int(large)) points tall at the largest size, every control of six screens reachable")
    }
}
#endif
