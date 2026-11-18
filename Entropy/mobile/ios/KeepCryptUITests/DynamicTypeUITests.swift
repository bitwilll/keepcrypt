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

    /// The First launch title's height, launched with arguments, and the notice bar's once a screenshot (the
    /// hook) has put it up there (lead decision M6-26: the bar's 16 was a fixed size before U3f, so it did not
    /// grow and the second assertion below failed). U3j: each wait 30 s or more, as the journeys' (run 44398792169's
    /// macos-26 runner took 54 s to set up automation and 154 s to show First launch, and the notice was not found in
    /// the 10 s then given); a miss says what the facts line holds ("notice ..." among it), so a slow runner is told
    /// from a notice that never came, and a notice drawn with no height fails as such.
    private func heights(_ app: XCUIApplication) -> (title: CGFloat, notice: CGFloat) {
        app.launch()
        XCTAssertTrue(app.element("first_launch").waitForExistence(timeout: 60), "First launch")
        // First launch's own title (the privacy cover, should the scene not be active, says KeepCrypt too).
        let title = app.element("first_launch").staticTexts["KeepCrypt"].firstMatch
        XCTAssertTrue(title.waitForExistence(timeout: 30), "the app's name; " + app.facts())
        let titleHeight = title.frame.height
        app.buttons["hook_screenshot"].tap()
        let notice = app.element("notice")
        XCTAssertTrue(notice.waitForExistence(timeout: 30), "the screenshot's notice never came; " + app.facts())
        let noticeHeight = notice.frame.height
        XCTAssertGreaterThan(noticeHeight, 0, "the screenshot's notice has no height; " + app.facts())
        return (titleHeight, noticeHeight)
    }

    /// The control id brought into view as a person scrolls it, whole and above the TestHooks panel. In a column's
    /// scroll view it is dragged there slowly, up or down by what is cut (JourneySupport's bringIntoView, at most ten
    /// drags of half the shown region), whether hittable or not; elsewhere (a fixed action) it must be hittable as it
    /// stands. U3j: reach() swiped up until the control was hittable, and a swipe glides: at the largest size on the
    /// narrow iPhone, Home's Back (U3d) lengthened its column and run 44398792169's swipes carried Dice-only seed from
    /// under the panel past the column's top, six times over, so it was never hittable. Test-only: a person scrolls
    /// to what they see. U2h: the column's scroll view runs on under the panel, so a control there is hittable to
    /// XCUITest while its tap lands on the panel; the probe line names each drag. A failure gives the facts and
    /// where the control, its scroll view and the panel lie.
    private func reach(_ app: XCUIApplication, _ id: String) {
        // A pad's key is named "a pad key" and never placed (U3a).
        let name = app.lineName(id)
        let placed = !app.isPadKey(id)
        let control = app.buttons[id]
        XCTAssertTrue(control.waitForExistence(timeout: 30), name + " never came; " + app.facts())
        func whereItIs() -> String {
            app.facts() + "; " + name + (placed ? " " + app.place(control) : "")
        }
        if app.scrollViewHolding(id) != nil {
            app.bringIntoView(control, name, placed: placed, limit: 10)
            XCTAssertTrue(app.wholeInView(control), name + " cut: not wholly shown above the hooks panel at the largest text size; " + whereItIs())
        }
        XCTAssertTrue(control.isHittable, name + " cut: not reachable at the largest text size; " + whereItIs())
    }

    func testTheLargestTextSizeGrowsTheTextAndEveryControlStaysReachable() {
        let plain = XCUIApplication()
        let (small, smallNotice) = heights(plain)
        plain.terminate()
        let app = XCUIApplication()
        app.launchArguments += ["-UIPreferredContentSizeCategoryName", "UICTContentSizeCategoryAccessibilityXXXL"]
        let (large, largeNotice) = heights(app)
        XCTAssertGreaterThan(large, small * 1.5, "the text did not grow with the text size (\(small) to \(large) points)")
        XCTAssertGreaterThan(
            largeNotice, smallNotice * 1.5, "the notice bar did not grow with the text size (\(smallNotice) to \(largeNotice) points)")
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
        // Q97: no label breaks inside a word. At the largest size the word "Confirm" is wider than half the row's text
        // width, so the pair stands one per row and each one-word label is one line high, as Done is: no word broken
        // (before U3g they shared the row and "Confirm" broke inside the word, two lines high).
        let oneLine = app.buttons["dice_done"].frame.height
        for id in ["undo", "confirm"] {
            let height = app.buttons[id].frame.height
            XCTAssertLessThanOrEqual(height, oneLine + 1, id + " is \(Int(height)) points high, more than one line's \(Int(oneLine))")
        }
        pass("dynamic type: the text \(Int(small)) to \(Int(large)) points tall at the largest size, every control of six screens reachable")
    }
}
#endif
