// The walk itself (tasks/todo.md, M6 item D2; :screens' Walk.kt): every screen but the stop screen
// reached over the real slot by its branch, each checked on arrival with its privacy gate (Walk.to), and
// the words' states the walk's screens do not name; and the model's kinds against the docs' list of
// Protected screens (LeavingTest.kt's theProtectedScreensAreTheDocsList). Each walk leaves the slot at home.

import XCTest

final class CeremonyWalkTests: XCTestCase {
    override func setUpWithError() throws {
        try KcrVectors.load()
        assertLiveSlot()
    }

    override func tearDown() {
        assertSlotEmptied()
    }

    /// Walk.kt's screens: the 48 screens but Stop, each reached and checked, and its four states.
    func testTheWalkReachesEveryScreenButTheStopScreen() {
        XCTAssertEqual(Walk.screens.count, 48, "Walk.kt's 48 screens")
        for screen in Walk.screens {
            let rig = Walk.to(screen)
            XCTAssertEqual(rig.screen, screen, screen.id)
            XCTAssertFalse(rig.model.state.gate, "\(screen.id): past its gate")
            assertSlotEmptied()
        }
        for screen in Walk.gated.sorted(by: { $0.rawValue < $1.rawValue }) {
            let rig = Walk.to(screen, gate: true)
            XCTAssertTrue(rig.model.state.gate, "\(screen.id): on its gate")
            assertSlotEmptied()
        }
        for (what, reach) in Walk.states {
            let rig = reach()
            XCTAssertTrue(rig.screen.isProtected, "\(what): a Protected screen")
            assertSlotEmptied()
        }
    }

    /// LeavingTest.kt's theProtectedScreensAreTheDocsList.
    func testTheProtectedScreensAreTheDocsList() {
        XCTAssertEqual(Set(Walk.screens.filter(\.isProtected)), Walk.protected, "isProtected against docs/mobile-apps.md's list")
    }
}
