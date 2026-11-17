// Back on every screen of the walk (tasks/todo.md, M6 item D2), ported from :screens' BackTest.kt (Stage U's
// U2b), over the real slot: Back once and twice from each of the 48 screens but the stop screen, landing
// only where nothing is lost, by this class's own table (BackTest.kt's, row for row, from
// docs/pi-firmware.md's buttons table and lead decision M5-75). Back never ends a session; the session,
// the check and its nonce are held where Back stays in the ceremony, a typed code or passphrase is wiped by
// the Back that leaves its entry, and Check a backup's file goes with its entry. On the words' states the
// walk's screens do not name, Back does nothing. Each test leaves the slot at home.

import XCTest

final class CeremonyBackTests: XCTestCase {
    override func setUpWithError() throws {
        try KcrVectors.load()
        assertLiveSlot()
    }

    override func tearDown() {
        assertSlotEmptied()
    }

    /// Where Back lands from each screen it leaves (BackTest.kt's landing); every screen not named stays.
    private let landing: [Screen: Screen] = [
        .goOffline: .firstLaunch,
        .home: .goOffline,
        .length: .home,
        .skipConfirm: .checkPrompt,
        .checkQr: .sealCard,
        .scan: .checkQr,
        .codeEntry: .checkQr,
        .matchFoundConfirm: .checkQr,
        .cannotCheckConfirm: .checkQr,
        .bip39Entry: .bip39Ask,
        .watchDescriptorQr: .watchAccountQr,
        .backupCheckEntry: .home,
        .backupRecheck: .backupCheckResult,
        .snapshot: .home,
        .about: .home,
    ]

    private func landsOn(_ screen: Screen) -> Screen { landing[screen] ?? screen }

    /// The pad a screen's Back leaves and wipes, and a key it shows (BackTest.kt's typedOn).
    private func typedOn(_ rig: Rig) -> (PadEntry, Character)? {
        switch rig.screen {
        case .codeEntry: return (rig.model.goAheadCode, "C")
        case .bip39Entry: return (rig.model.bip39Letters, "1")
        case .backupCheckEntry: return (rig.model.backupLetters, "a")
        default: return nil
        }
    }

    /// BackTest.kt's backOnceAndTwiceLandsOnlyWhereNothingIsLost.
    func testBackOnceAndTwiceLandsOnlyWhereNothingIsLost() {
        for screen in Walk.screens {
            let name = screen.id
            let rig = Walk.to(screen)
            let typed = typedOn(rig)
            if let (pad, key) = typed {
                rig.press(key)
                XCTAssertEqual(pad.length, 1, "\(name): the key typed")
            }
            let before = rig.model.state
            let held = rig.model.held
            rig.model.back()
            let once = landsOn(screen)
            let after = rig.model.state
            XCTAssertEqual(after.screen, once, "\(name): Back once")
            XCTAssertEqual(rig.model.held, screen == .backupCheckEntry ? false : held, "\(name): what is held after Back")
            XCTAssertNil(after.notice, "\(name): Back said something was wiped")
            XCTAssertNil(after.overlay, "\(name): Back covered the screen")
            if let (pad, _) = typed { XCTAssertEqual(pad.length, 0, "\(name): Back left what was typed") }
            if once == screen { XCTAssertEqual(after.page, before.page, "\(name): Back moved the page") }
            if once == .checkQr || once == .sealCard {
                XCTAssertTrue(after.checkRequest === before.checkRequest, "\(name): Back changed the check or its nonce")
                XCTAssertEqual(after.seal, before.seal, "\(name): Back changed the seal card")
            }
            rig.model.back()
            XCTAssertEqual(rig.screen, landsOn(once), "\(name): Back twice")
            assertSlotEmptied()
        }
    }

    /// BackTest.kt's onThePagedScreensBackIsThePreviousPage.
    func testOnThePagedScreensBackIsThePreviousPage() {
        for screen in [Screen.words, .wordsOverview, .backupPassphrase] {
            let name = screen.id
            let rig = Walk.to(screen)
            rig.model.nextPage()
            XCTAssertEqual(rig.model.state.page, 1, "\(name): the next page")
            rig.model.back()
            XCTAssertEqual(rig.screen, screen, name)
            XCTAssertEqual(rig.model.state.page, 0, "\(name): Back once is the page before")
            rig.model.back()
            XCTAssertEqual(rig.screen, screen, name)
            XCTAssertEqual(rig.model.state.page, 0, "\(name): Back on the first page does nothing")
            assertSlotEmptied()
        }
    }

    /// BackTest.kt's backDoesNothingUnderAPrivacyGateTheCoverOrTheWarning, its privacy gate half.
    func testBackDoesNothingUnderAPrivacyGate() {
        for screen in Walk.gated.sorted(by: { $0.rawValue < $1.rawValue }) {
            let rig = Walk.to(screen, gate: true)
            rig.model.back()
            XCTAssertEqual(rig.screen, screen, "\(screen.id): Back on its privacy gate")
            XCTAssertTrue(rig.model.state.gate, "\(screen.id): Back passed its privacy gate")
            assertSlotEmptied()
        }
    }

    /// BackTest.kt's backDoesNothingUnderAPrivacyGateTheCoverOrTheWarning, its cover and warning half:
    /// on every screen but the long calls', under the cover (30 s on a Protected screen, a return to a
    /// Public one) and, where something is held, under the warning, Back does nothing.
    func testBackDoesNothingUnderTheCoverOrTheWarning() {
        for screen in Walk.screens where !screen.isWorking {
            let name = screen.id
            let covered = Walk.to(screen)
            if Walk.protected.contains(screen) {
                covered.clock.now += Timers.coverMillis
                covered.model.tick()
            } else {
                covered.model.appLeft()
                covered.clock.now += 1_000
                covered.model.appReturned()
            }
            assertBackDoesNothing(covered, .cover, "\(name) under the cover")
            assertSlotEmptied()
            let warned = Walk.to(screen)
            if !warned.model.held {
                assertSlotEmptied()
                continue
            }
            warned.clock.now += Timers.warnMillis
            warned.model.tick()
            assertBackDoesNothing(warned, .warning, "\(name) under the warning")
            assertSlotEmptied()
        }
    }

    /// overlay shows over rig's screen, and Back leaves the screen, its page, the overlay and what is
    /// held as they were (BackTest.kt's assertBackDoesNothing).
    private func assertBackDoesNothing(_ rig: Rig, _ overlay: Overlay, _ what: String) {
        let before = rig.model.state
        XCTAssertEqual(before.overlay, overlay, what)
        let held = rig.model.held
        rig.model.back()
        let after = rig.model.state
        XCTAssertEqual(after.screen, before.screen, "\(what): Back moved")
        XCTAssertEqual(after.page, before.page, "\(what): Back moved the page")
        XCTAssertEqual(after.overlay, overlay, "\(what): Back took the overlay away")
        XCTAssertEqual(rig.model.held, held, "\(what): Back changed what is held")
        XCTAssertFalse(after.notice != nil && before.notice == nil, "\(what): Back wiped")
    }

    /// BackTest.kt's backDoesNothingInTheWordsStatesTheWalksScreensDoNotName.
    func testBackDoesNothingInTheWordsStatesTheWalksScreensDoNotName() {
        for (what, reach) in Walk.states {
            let rig = reach()
            let before = rig.model.state
            let held = rig.model.held
            rig.model.back()
            rig.model.back()
            let after = rig.model.state
            XCTAssertEqual(after.screen, before.screen, "\(what): Back moved")
            XCTAssertEqual(after.page, before.page, "\(what): Back moved the page")
            XCTAssertEqual(after.gate, before.gate, "\(what): Back passed the gate")
            XCTAssertEqual(after.reviewing, before.reviewing, "\(what): Back left the review")
            XCTAssertEqual(rig.model.held, held, "\(what): Back changed what is held")
            XCTAssertNil(after.notice, what)
            assertSlotEmptied()
        }
    }
}
