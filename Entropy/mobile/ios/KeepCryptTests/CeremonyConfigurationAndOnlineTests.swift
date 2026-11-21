// A configuration change and going online on every screen of the walk (tasks/todo.md, M6 item D2), ported
// from :screens' ConfigurationAndOnlineTest.kt (Stage U's U2d), over the real slot. A configuration change
// (a rotation, a text size, a dark-mode switch) is no leaving: on Android the recreated activity's start
// and resume reach the model while it is in the foreground; on the iPhone the scene stays active and SwiftUI
// redraws, and a repeated active phase reaches the model the same way, as a return and a resume in the
// foreground. Either way the screen, its page, its privacy gate, the cover or warning over it, what is held
// and what a pad holds stay as they were, with no call made; in the words' states too. Going online: before the start-up self-test passes
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

    /// A key each pad screen of the walk shows (the ASCII pad's first page on the BIP39 entry).
    private let padKeys: [Screen: Character] = [
        .dice: "3", .codeEntry: "C", .readbackEntry: "a", .backupConfirm: "a", .bip39Entry: "1", .backupCheckEntry: "a",
    ]

    /// A configuration change: a return and a resume with no leaving before them.
    private func recreate(_ rig: Rig) {
        rig.model.appReturned()
        rig.model.appResumed()
    }

    /// A configuration change leaves rig's state, what it holds, its pads and its calls as they were.
    private func assertRecreationChangesNothing(_ rig: Rig, _ what: String) {
        let before = rig.model.state
        let held = rig.model.held
        let pads = rig.padLengths()
        let waiting = rig.worker.waiting
        recreate(rig)
        XCTAssertTrue(sameState(rig.model.state, before), "\(what): the state changed")
        XCTAssertEqual(rig.model.held, held, "\(what): what is held changed")
        XCTAssertEqual(rig.padLengths(), pads, "\(what): a pad's entry changed")
        XCTAssertEqual(rig.worker.waiting, waiting, "\(what): a call was made")
    }

    /// ConfigurationAndOnlineTest.kt's aConfigurationChangeOnEveryScreenChangesNothing.
    func testAConfigurationChangeOnEveryScreenChangesNothing() {
        for screen in Walk.gated.sorted(by: { $0.rawValue < $1.rawValue }) {
            assertRecreationChangesNothing(Walk.to(screen, gate: true), "\(screen.id) on its privacy gate")
            assertSlotEmptied()
        }
        for screen in Walk.screens {
            let name = screen.id
            let rig = Walk.to(screen)
            if let key = padKeys[screen] {
                rig.press(key)
                XCTAssertGreaterThan(rig.padLengths().reduce(0, +), 0, "\(name): the key typed")
            }
            assertRecreationChangesNothing(rig, name)
            assertSlotEmptied()
            if screen.isWorking { continue }
            let covered = Walk.to(screen)
            if Walk.protected.contains(screen) {
                covered.clock.now += Timers.coverMillis
                covered.model.tick()
                XCTAssertEqual(covered.model.state.overlay, .cover, name)
                assertRecreationChangesNothing(covered, "\(name) under the cover")
            } else if covered.model.held {
                covered.clock.now += Timers.warnMillis
                covered.model.tick()
                XCTAssertEqual(covered.model.state.overlay, .warning, name)
                assertRecreationChangesNothing(covered, "\(name) under the warning")
            }
            assertSlotEmptied()
        }
    }

    /// ConfigurationAndOnlineTest.kt's aConfigurationChangeInTheWordsStatesTheWalksScreensDoNotNameChangesNothing.
    func testAConfigurationChangeInTheWordsStatesTheWalksScreensDoNotNameChangesNothing() {
        for (what, reach) in Walk.states {
            assertRecreationChangesNothing(reach(), what)
            assertSlotEmptied()
        }
    }

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
