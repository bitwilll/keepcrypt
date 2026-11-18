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
    /// One cause, one failure (U2f): a journey stops at its first failure, so a lost press is not followed by
    /// every later step failing for it.
    override func setUp() {
        continueAfterFailure = false
    }

    /// The First launch title's height, launched with arguments.
    private func titleHeight(_ app: XCUIApplication) -> CGFloat {
        app.launch()
        XCTAssertTrue(app.element("first_launch").waitForExistence(timeout: 30), "First launch")
        // First launch's own title (the privacy cover, should the scene not be active, says KeepCrypt too).
        let title = app.element("first_launch").staticTexts["KeepCrypt"].firstMatch
        XCTAssertTrue(title.waitForExistence(timeout: 10), "the app's name")
        return title.frame.height
    }

    /// The control id scrolled into view as a person scrolls it, whole: the screen's column swiped up (at most
    /// six times) until the control is hittable, then, where it scrolls with the column, dragged slowly until it
    /// is wholly shown above the TestHooks panel (JourneySupport's bringIntoView). U2h: the column's scroll view
    /// runs on under the panel, so a control there is hittable to XCUITest while its tap lands on the panel (run
    /// 44306763928: Dice-only seed at 23,579 329x82 inside a scroll view at 0,57 375x609, the panel over it, and
    /// three presses that never reached the app); the probe line names each drag.
    private func reach(_ app: XCUIApplication, _ id: String) {
        let control = app.buttons[id]
        XCTAssertTrue(control.waitForExistence(timeout: 30), id)
        var swipes = 0
        while !control.isHittable, swipes < 6 {
            app.swipeUp()
            swipes += 1
        }
        XCTAssertTrue(control.isHittable, id + " cut: not reachable at the largest text size")
        app.bringIntoView(control, id, placed: true)
        XCTAssertTrue(app.wholeInView(control), id + " not wholly shown above the hooks panel: " + app.place(control))
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
        app.pressTo("first_launch_continue", "go_offline", passing: ["self_test"])
        app.buttons["hook_path_none"].tap()
        app.waitEnabled("start")
        reach(app, "start")
        app.pressTo("start", "home")
        for id in ["new_seed", "dice_only_seed", "check_backup", "load_snapshot", "show_about"] {
            reach(app, id)
        }
        app.pressTo("show_about", "about")
        reach(app, "back")
        app.pressTo("back", "home")
        // U2g's probe: KitScreen's layout changes as Home shows again (its actions moved into or out of the
        // column, "More below" shown or gone, U2f's count and the last one's uptime), now and 2 s on, so a
        // layout that keeps changing under the next press shows in the log; and where Dice-only seed lies
        // against the scroll view that holds it, the press U2f's run lost here.
        pass("probe: Home again: " + app.facts())
        _ = app.within(2) { false }
        pass("probe: Home again, 2 s on: " + app.facts() + "; dice_only_seed " + app.place(app.buttons["dice_only_seed"]))
        reach(app, "dice_only_seed")
        app.pressTo("dice_only_seed", "length")
        reach(app, "words_24")
        reach(app, "words_12")
        app.pressTo("words_12", "dice")
        for id in ["key_1", "key_2", "key_3", "key_4", "key_5", "key_6", "undo", "confirm", "dice_done"] {
            reach(app, id)
        }
        pass("dynamic type: the text \(Int(small)) to \(Int(large)) points tall at the largest size, every control of six screens reachable")
    }
}
#endif
