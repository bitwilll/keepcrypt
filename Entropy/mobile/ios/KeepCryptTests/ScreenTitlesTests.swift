// The names VoiceOver is given and the kit's layout rule (tasks/todo.md, M6 item D3), ported from :screens'
// ScreenTitlesTest.kt and KitTest.kt: every screen's title is its own, fixed and non-blank, and neither the
// privacy gate's, the cover's nor the idle warning's; the pane title of a state is the overlay's while one
// is up, the gate's while a gate stands, and the screen's otherwise; D3's screens are Public, entered with
// no gate, each titled by Screen.swift; and a screen's actions scroll with its text once they are taller
// than half of it. No slot is used.

import XCTest

final class ScreenTitlesTests: XCTestCase {
    /// ScreenTitlesTest.kt's eachScreenHasAFixedPaneTitleOfItsOwn, and the overlays' titles over it.
    func testEachScreenHasAFixedPaneTitleOfItsOwn() {
        let titles = Screen.allCases.map(\.title)
        XCTAssertFalse(titles.contains { $0.trimmingCharacters(in: .whitespaces).isEmpty }, "a blank title")
        XCTAssertEqual(Set(titles).count, Screen.allCases.count, "each screen has a title of its own")
        let others: Set = [privacyGateTitle, coverTitle, idleWarningTitle]
        XCTAssertEqual(others.count, 3)
        XCTAssertTrue(others.isDisjoint(with: titles), "a screen's title is the gate's, the cover's or the warning's")
        for screen in Screen.allCases {
            var state = UiState(screen: screen)
            XCTAssertEqual(paneTitle(of: state), screen.title, screen.id)
            state.gate = true
            XCTAssertEqual(paneTitle(of: state), privacyGateTitle, "\(screen.id) behind a gate")
            state.overlay = .cover
            XCTAssertEqual(paneTitle(of: state), coverTitle, "\(screen.id) under the cover")
            state.overlay = .warning
            XCTAssertEqual(paneTitle(of: state), idleWarningTitle, "\(screen.id) under the warning")
        }
    }

    /// D3's screens are Public, entered with no privacy gate, and their headings are their titles.
    func testTheStartScreensArePublicAndTitledByScreenSwift() {
        let start: [Screen] = [.firstLaunch, .selfTest, .goOffline, .home, .length, .deviceEntropy, .commitment, .dice]
        for screen in start {
            XCTAssertFalse(screen.isProtected, "\(screen.id) is Public")
        }
        XCTAssertEqual(start.map(\.title), [
            "First launch", "Self-test", "Go offline", "Home", "How many words?", "Device entropy", "Commitment C", "Dice",
        ])
    }

    /// KitTest.kt's actionsScrollOnceTallerThanTheirShareOfTheScreen.
    func testActionsScrollOnceTallerThanTheirShareOfTheScreen() {
        XCTAssertEqual(actionsShare, 0.5)
        XCTAssertFalse(actionsScroll(0, 0), "before the first layout the actions stay under the column")
        XCTAssertFalse(actionsScroll(320, 640), "half the screen: under it")
        XCTAssertTrue(actionsScroll(321, 640), "more than half: in the column")
        XCTAssertFalse(actionsScroll(200, 640))
        XCTAssertEqual(ShellTexts.moreBelow, "More below")
    }
}
