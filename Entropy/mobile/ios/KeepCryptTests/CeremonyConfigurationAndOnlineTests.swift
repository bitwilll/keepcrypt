// Going online on every screen of the walk (tasks/todo.md, M6 item D2), ported from :screens'
// ConfigurationAndOnlineTest.kt (Stage U's U2d), over the real slot: before the start-up self-test passes
// and on Go offline nothing goes; on Home, Length, Load registry snapshot's result and About, which hold
// nothing, Go offline comes back with nothing to say; on every other screen the session, restart or Check a
// backup's file or checked backup is discarded at once, with the Offline notice, every secret on show and
// every pad's entry wiped and the slot at home ("Working..." once its call's reply comes). Each screen's
// walk leaves the slot at home.

import XCTest

final class CeremonyConfigurationAndOnlineTests: XCTestCase {
    override func setUpWithError() throws {
        try KcrVectors.load()
        assertLiveSlot()
    }

    override func tearDown() {
        assertSlotEmptied()
    }

    /// The screens that hold nothing once the start-up self-test has passed.
    private let holdingNothing: Set<Screen> = [.home, .length, .snapshot, .about]

    /// The screens before Go offline needs anything: before the self-test passes, and Go offline itself.
    private let beforeOffline: Set<Screen> = [.firstLaunch, .selfTest, .goOffline]

    /// ConfigurationAndOnlineTest.kt's goingOnlineOnEveryScreenDiscardsWhatIsHeld.
    func testGoingOnlineOnEveryScreenDiscardsWhatIsHeld() {
        for screen in Walk.screens {
            let name = screen.id
            let rig = Walk.to(screen)
            let holds = !holdingNothing.contains(screen) && !beforeOffline.contains(screen) && !screen.isWorking
            XCTAssertEqual(rig.model.held, holds, "\(name): what is held before going online")
            rig.offline.set(false)
            if beforeOffline.contains(screen) {
                XCTAssertEqual(rig.screen, screen, "\(name): going online before Go offline is needed")
                XCTAssertNil(rig.model.state.notice, name)
            } else if holdingNothing.contains(screen) {
                XCTAssertEqual(rig.screen, .goOffline, "\(name): going online, nothing held")
                XCTAssertNil(rig.model.state.notice, "\(name): nothing was held, so nothing was wiped")
            } else {
                if screen == .working {
                    XCTAssertEqual(rig.screen, .working, "\(name): until the call's reply")
                    rig.worker.run()
                }
                rig.assertDiscarded(.offline, "\(name): going online")
                rig.assertNothingSecretShown(name)
                XCTAssertTrue(isDone(Core.shared.selfTest()), "\(name): going online left something in core")
            }
            rig.offline.set(true)
            if rig.screen == .goOffline {
                rig.model.startOffline()
                XCTAssertEqual(rig.screen, .home, "\(name): offline again, Start reaches Home")
            }
            assertSlotEmptied()
        }
    }
}
