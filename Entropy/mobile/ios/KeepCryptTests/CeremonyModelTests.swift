// The model's start and its app-wide rules (tasks/todo.md, M6 items C5 and D2): First launch before any
// core call and its Continue's one self-test (:screens' StartScreensTest.kt and NoCoreCallBeforeContinueTest.kt),
// Start only offline, going online (Android's offlineChanged, as a pure function), the screenshot discard on
// every screen (C5, the iPhone's own rule), and the stop screen taking no more. Over StandInCore, which
// counts the self-tests and discards and gives a test's replies without halting the process's one slot.

import XCTest

final class CeremonyModelTests: XCTestCase {
    override func setUpWithError() throws {
        try KcrVectors.load()
        assertLiveSlot()
    }

    override func tearDown() {
        assertSlotEmptied()
    }

    /// A model over a stand-in for Core, the phone offline or not at the offline check's first report.
    private func rig(offline: Bool = true) -> (Rig, StandInCore) {
        let core = StandInCore()
        let rig = Rig(core: core)
        rig.offline.offline = offline
        return (rig, core)
    }

    /// First launch shows first and makes no core call before its Continue (NoCoreCallBeforeContinueTest.kt);
    /// Continue runs the start-up self-test behind its own screen, then Go offline; a path report before it
    /// only changes the state (C5).
    func testFirstLaunchMakesNoCallAndAPathReportBeforeTheStartUpOnlyChangesTheState() {
        let (rig, core) = rig(offline: false)
        rig.startUp()
        XCTAssertEqual(rig.screen, .firstLaunch)
        rig.offline.set(true)
        rig.offline.set(false)
        XCTAssertEqual(rig.screen, .firstLaunch)
        XCTAssertFalse(rig.model.state.offline)
        XCTAssertEqual(core.selfTests + core.discards, 0, "no core call before Continue")
        rig.model.firstLaunchDone()
        XCTAssertEqual(rig.screen, .selfTest, "the self-test behind its own screen")
        XCTAssertEqual(rig.worker.waiting, 1)
        rig.offline.set(false)
        XCTAssertEqual(rig.screen, .selfTest, "going online before the start-up: only the state")
        rig.worker.run()
        XCTAssertEqual(rig.screen, .goOffline)
        XCTAssertTrue(rig.model.started)
        XCTAssertEqual(core.selfTests, 1)
        XCTAssertEqual(core.discards, 0)
    }

    /// C5's testStartOpensHomeOnlyWhileNoPathIsUsable: Start does nothing online, each report is read
    /// afresh, and going online on Home, holding nothing, brings Go offline back with nothing to say.
    func testStartOpensHomeOnlyWhileNoPathIsUsable() {
        let (rig, core) = rig(offline: false)
        rig.toGoOffline()
        XCTAssertFalse(rig.model.state.offline, "online at the first report")
        rig.model.startOffline()
        XCTAssertEqual(rig.screen, .goOffline, "Start does nothing online")
        rig.offline.set(true)
        rig.model.startOffline()
        XCTAssertEqual(rig.screen, .home)
        rig.offline.set(true)
        XCTAssertEqual(rig.screen, .home, "each report read afresh; offline again changes nothing")
        rig.offline.set(false)
        XCTAssertEqual(rig.screen, .goOffline, "online on Home, holding nothing: Go offline again")
        XCTAssertNil(rig.model.state.notice, "nothing held, nothing to say")
        XCTAssertEqual(core.discards, 0)
    }

    /// Android's offlineChanged as a pure function (C5's testGoingOnlineDecidesAsAndroid).
    func testGoingOnlineDecidesAsAndroid() {
        let step = CeremonyModel.afterPathReport
        for holds in [false, true] {
            for needsOffline in [false, true] {
                XCTAssertEqual(step(true, true, holds, needsOffline), .nothing)
                XCTAssertEqual(step(false, false, holds, needsOffline), .nothing)
                XCTAssertEqual(step(true, false, holds, needsOffline), .nothing)
                if holds { XCTAssertEqual(step(false, true, holds, needsOffline), .discard) }
            }
        }
        XCTAssertEqual(step(false, true, false, true), .goOffline)
        XCTAssertEqual(step(false, true, false, false), .nothing)
    }

    /// The screenshot response on every kind of screen (C5): Core's discard each time. On First launch and
    /// Go offline the screen stays and says so; during the self-test, which holds no session, its reply
    /// returns First launch with nothing to say; on Home the start screen says why; with a session held
    /// (the dice), the start screen says why and nothing is held.
    func testAScreenshotDiscardsWhateverSessionExistsOnEveryScreen() {
        let (rig, core) = rig()
        rig.startUp()
        rig.model.discardAfterScreenshot()
        XCTAssertEqual(core.discards, 1, "on First launch")
        XCTAssertEqual(rig.screen, .firstLaunch)
        XCTAssertEqual(rig.model.state.notice, .screenshot)
        rig.model.firstLaunchDone()
        rig.model.discardAfterScreenshot()
        XCTAssertEqual(core.discards, 2, "during the start-up self-test")
        XCTAssertEqual(rig.screen, .selfTest, "its screen until its reply")
        rig.worker.run()
        XCTAssertEqual(rig.screen, .firstLaunch, "the self-test discarded runs again from First launch")
        XCTAssertNil(rig.model.state.notice, "no session was held")
        XCTAssertFalse(rig.model.started)
        rig.model.firstLaunchDone()
        rig.worker.run()
        XCTAssertEqual(rig.screen, .goOffline)
        rig.model.discardAfterScreenshot()
        XCTAssertEqual(core.discards, 3, "on Go offline")
        XCTAssertEqual(rig.screen, .goOffline)
        XCTAssertEqual(rig.model.state.notice, .screenshot)
        rig.model.startOffline()
        XCTAssertNil(rig.model.state.notice, "Start clears the notice")
        rig.model.discardAfterScreenshot()
        XCTAssertEqual(core.discards, 4, "on Home")
        rig.assertDiscarded(.screenshot, "on Home")
        rig.begin(.diceOnly, .twelve)
        XCTAssertEqual(rig.screen, .dice)
        XCTAssertTrue(rig.model.held)
        rig.press("3")
        rig.model.discardAfterScreenshot()
        XCTAssertEqual(core.discards, 5, "on the dice")
        rig.assertDiscarded(.screenshot, "on the dice")
        rig.assertNothingSecretShown("on the dice")
        XCTAssertTrue(isDone(Core.shared.selfTest()), "the screenshot left something in core")
    }

    /// C5's testAHaltedDiscardStopsTheAppAndNothingActsAfterIt: a discard that halts ends on the stop
    /// screen with its reason, and nothing acts after it.
    func testAHaltedDiscardStopsTheAppAndNothingActsAfterIt() {
        let (rig, core) = rig()
        rig.toHome()
        core.discardReply = .halted(.panic)
        rig.model.discardAfterScreenshot()
        XCTAssertEqual(rig.screen, .stop)
        XCTAssertEqual(rig.model.state.halt, .panic)
        let offline = rig.model.state.offline
        rig.model.discardAfterScreenshot()
        rig.offline.set(!offline)
        rig.model.startOffline()
        rig.model.firstLaunchDone()
        XCTAssertEqual(core.discards, 1, "a stopped app discards nothing more")
        XCTAssertEqual(rig.screen, .stop)
        XCTAssertEqual(rig.model.state.halt, .panic)
        XCTAssertEqual(rig.model.state.offline, offline, "and takes no report")
    }

    /// C5's testADiscardThatBreaksTheContractStopsTheAppAsInternal: a refused or discarded reply to a
    /// discard is the bridge's broken contract, and halts as internal.
    func testADiscardThatBreaksTheContractStopsTheAppAsInternal() {
        for reply: Reply<Void> in [.refused(.wrongCode), .discarded] {
            let (rig, core) = rig()
            rig.toHome()
            core.discardReply = reply
            rig.model.discardAfterScreenshot()
            XCTAssertEqual(rig.screen, .stop)
            XCTAssertEqual(rig.model.state.halt, .internal)
        }
    }

    /// C5's testAFailedSelfTestStopsTheAppBeforeAnyScreen: a self-test that halts ends on the stop screen
    /// with its reason, and a screenshot then discards nothing.
    func testAFailedSelfTestStopsTheApp() {
        let (rig, core) = rig()
        core.selfTestReply = .halted(.knownAnswerTest)
        rig.startUp()
        rig.model.firstLaunchDone()
        rig.worker.run()
        XCTAssertEqual(rig.screen, .stop)
        XCTAssertEqual(rig.model.state.halt, .knownAnswerTest)
        XCTAssertFalse(rig.model.started)
        rig.model.discardAfterScreenshot()
        XCTAssertEqual(core.discards, 0)
    }

    /// The start-up self-test runs once (C5): after it passed, First launch again (Back from Go offline)
    /// and its Continue go to Go offline at once.
    func testTheStartUpSelfTestRunsOnce() {
        let (rig, core) = rig()
        rig.toGoOffline()
        rig.model.back()
        XCTAssertEqual(rig.screen, .firstLaunch)
        rig.model.firstLaunchDone()
        XCTAssertEqual(rig.screen, .goOffline)
        XCTAssertEqual(core.selfTests, 1)
        XCTAssertEqual(rig.worker.ran, 1)
    }

    func testTheNoticeLinesAreFixed() {
        XCTAssertTrue(noticeLine(.screenshot).hasPrefix("The session was wiped: a screenshot was taken."))
        XCTAssertEqual(noticeLine(.offline), "The session was wiped: the phone went online.")
        XCTAssertEqual(noticeLine(.left), "The session was wiped: the app was left during it.")
        XCTAssertEqual(noticeLine(.idle), "The session was wiped after 10 minutes without input.")
        XCTAssertEqual(noticeLine(.background), "The session was wiped after 60 seconds away from the app.")
    }

    /// Check a backup's entry (Protected) reached through the open picker's answer, with the app in the
    /// foreground all along: on iOS the picker is the app's own sheet, so no resume follows its answer.
    private func entryThroughThePicker() -> Rig {
        let bytes = SavedBackup.shared.file
        let rig = Rig().toHome()
        rig.model.checkBackup(FakePickers())
        rig.model.backupPicked(FakeFile(name: SavedBackup.name, size: Int64(bytes.count), bytes: bytes))
        rig.worker.run()
        XCTAssertEqual(rig.screen, .backupCheckEntry)
        return rig
    }

    /// M6 commit U2f, a U4 defect U2 found (lead decision M6-22): the picker rule outlived the picker. Its
    /// exemption ended only at a resume, which an iPhone's in-app picker never brings, so after any answer the
    /// next real leaving counted as none and a Protected screen stayed. The answer ends it.
    func testAPickersAnswerEndsItsExemptionSoAProtectedScreenIsDiscardedOnLeaving() {
        let rig = entryThroughThePicker()
        rig.model.appLeft()
        XCTAssertEqual(rig.screen, .home, "leaving the Protected entry after the picker answered discards it")
        XCTAssertEqual(rig.model.state.notice, .left)
        XCTAssertFalse(rig.model.held)
    }

    /// The converse: a leaving while the picker is up (before its answer) is no leaving.
    func testALeavingWhileThePickerIsUpDiscardsNothing() {
        let rig = Rig().toHome()
        rig.model.checkBackup(FakePickers())
        rig.model.appLeft()
        XCTAssertEqual(rig.screen, .home)
        XCTAssertNil(rig.model.state.notice, "the picker's own leaving is no leaving")
        XCTAssertNil(rig.model.state.overlay, "nor a cover")
        rig.model.backupPicked(nil)
        rig.model.appReturned()
        rig.model.appResumed()
        XCTAssertEqual(rig.screen, .home)
    }
}
