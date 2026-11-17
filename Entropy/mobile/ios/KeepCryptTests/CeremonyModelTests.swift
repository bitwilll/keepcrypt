// The model's app-wide rules (tasks/todo.md, M6 item C5): the screenshot discard on every screen, going
// online (Android's offlineChanged, mirrored), Start only offline, and the stop screen taking no more.
// Core is reached through the two calls the model is given, so these tests count the discards and set
// their replies; the real calls run in CoreTests and, through the app, in the UI tests.

import XCTest

@MainActor
final class CeremonyModelTests: XCTestCase {
    /// A model whose self-test gives outcome and whose discards are counted and answered with reply.
    @MainActor
    private final class Rig {
        var discards = 0
        var reply: Reply<Void> = .done(())
        let model: CeremonyModel

        init(_ outcome: StartScreen = .passed) {
            weak var rig: Rig?
            model = CeremonyModel(selfTest: { outcome }, discard: {
                rig?.discards += 1
                return rig?.reply ?? .halted(.internal)
            })
            rig = self
        }
    }

    func testAPathReportBeforeTheStartUpOnlyChangesTheState() async {
        let rig = Rig()
        rig.model.pathReported(offline: true)
        rig.model.pathReported(offline: false)
        XCTAssertEqual(rig.model.screen, .selfTest)
        XCTAssertFalse(rig.model.offline)
        XCTAssertEqual(rig.discards, 0)
        await rig.model.startUp()
        XCTAssertEqual(rig.model.screen, .goOffline)
        XCTAssertTrue(rig.model.started)
    }

    func testStartOpensHomeOnlyWhileNoPathIsUsable() async {
        let rig = Rig()
        await rig.model.startUp()
        XCTAssertFalse(rig.model.offline, "online until the first report")
        rig.model.startOffline()
        XCTAssertEqual(rig.model.screen, .goOffline, "Start does nothing online")
        rig.model.pathReported(offline: true)
        rig.model.startOffline()
        XCTAssertEqual(rig.model.screen, .home)
        rig.model.pathReported(offline: true)
        XCTAssertEqual(rig.model.screen, .home, "each report read afresh; offline again changes nothing")
        rig.model.pathReported(offline: false)
        XCTAssertEqual(rig.model.screen, .goOffline, "online on Home, holding nothing: Go offline again")
        XCTAssertNil(rig.model.notice, "nothing held, nothing to say")
        XCTAssertEqual(rig.discards, 0)
    }

    func testGoingOnlineDecidesAsAndroid() {
        let step = CeremonyModel.afterPathReport
        // Offline, or before the start-up self-test has passed: only the state changes.
        for holds in [false, true] {
            for needsOffline in [false, true] {
                XCTAssertEqual(step(true, true, holds, needsOffline), .nothing)
                XCTAssertEqual(step(false, false, holds, needsOffline), .nothing)
                XCTAssertEqual(step(true, false, holds, needsOffline), .nothing)
                // Online after it: a session held is discarded at once, wherever it is held.
                if holds { XCTAssertEqual(step(false, true, holds, needsOffline), .discard) }
            }
        }
        // Online after it, nothing held: Go offline again from a screen that needs offline, else nothing.
        XCTAssertEqual(step(false, true, false, true), .goOffline)
        XCTAssertEqual(step(false, true, false, false), .nothing)
    }

    func testAScreenshotDiscardsWhateverSessionExistsOnEveryScreen() async {
        let rig = Rig()
        rig.model.discardAfterScreenshot()
        XCTAssertEqual(rig.discards, 1, "during the start-up self-test")
        XCTAssertEqual(rig.model.notice, .screenshot)
        await rig.model.startUp()
        XCTAssertEqual(rig.model.screen, .goOffline)
        rig.model.discardAfterScreenshot()
        XCTAssertEqual(rig.discards, 2, "on Go offline, a Public screen with no secret held")
        XCTAssertEqual(rig.model.screen, .goOffline)
        rig.model.pathReported(offline: true)
        rig.model.startOffline()
        XCTAssertNil(rig.model.notice, "Start clears the notice")
        rig.model.discardAfterScreenshot()
        XCTAssertEqual(rig.discards, 3, "on Home")
        XCTAssertEqual(rig.model.screen, .home)
        XCTAssertEqual(rig.model.notice, .screenshot)
    }

    func testAHaltedDiscardStopsTheAppAndNothingActsAfterIt() async {
        let rig = Rig()
        await rig.model.startUp()
        rig.reply = .halted(.panic)
        rig.model.discardAfterScreenshot()
        XCTAssertEqual(rig.model.screen, .stop)
        XCTAssertEqual(rig.model.halt, .panic)
        rig.model.discardAfterScreenshot()
        rig.model.pathReported(offline: true)
        rig.model.startOffline()
        XCTAssertEqual(rig.discards, 1, "a stopped app discards nothing more")
        XCTAssertEqual(rig.model.screen, .stop)
        XCTAssertEqual(rig.model.halt, .panic)
        XCTAssertFalse(rig.model.offline, "and takes no report")
    }

    func testADiscardThatBreaksTheContractStopsTheAppAsInternal() async {
        for reply: Reply<Void> in [.refused(.wrongCode), .discarded] {
            let rig = Rig()
            await rig.model.startUp()
            rig.reply = reply
            rig.model.discardAfterScreenshot()
            XCTAssertEqual(rig.model.screen, .stop)
            XCTAssertEqual(rig.model.halt, .internal)
        }
    }

    func testAFailedSelfTestStopsTheAppBeforeAnyScreen() async {
        let rig = Rig(.stopped(.knownAnswerTest))
        await rig.model.startUp()
        XCTAssertEqual(rig.model.screen, .stop)
        XCTAssertEqual(rig.model.halt, .knownAnswerTest)
        XCTAssertFalse(rig.model.started)
        rig.model.discardAfterScreenshot()
        XCTAssertEqual(rig.discards, 0)
    }

    func testTheStartUpSelfTestRunsOnce() async {
        var runs = 0
        let model = CeremonyModel(selfTest: {
            runs += 1
            return .passed
        }, discard: { .done(()) })
        await model.startUp()
        await model.startUp()
        XCTAssertEqual(runs, 1)
    }

    func testTheNoticeLinesAreFixed() {
        XCTAssertTrue(noticeLine(.screenshot).hasPrefix("The session was wiped: a screenshot was taken."))
        XCTAssertEqual(noticeLine(.offline), "The session was wiped: the phone went online.")
    }
}
