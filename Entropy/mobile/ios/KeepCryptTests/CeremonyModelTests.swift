// The model's app-wide rule (tasks/todo.md, M6 item C5): the screenshot discard on every screen, and the
// stop screen taking no more.
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

    func testAScreenshotDiscardsWhateverSessionExistsOnEveryScreen() async {
        let rig = Rig()
        rig.model.discardAfterScreenshot()
        XCTAssertEqual(rig.discards, 1, "during the start-up self-test")
        XCTAssertEqual(rig.model.notice, .screenshot)
        await rig.model.startUp()
        XCTAssertEqual(rig.model.screen, .passed)
        XCTAssertTrue(rig.model.started)
        rig.model.discardAfterScreenshot()
        XCTAssertEqual(rig.discards, 2, "after it, a Public screen with no secret held")
        XCTAssertEqual(rig.model.screen, .passed)
        XCTAssertEqual(rig.model.notice, .screenshot)
    }

    func testAHaltedDiscardStopsTheAppAndNothingActsAfterIt() async {
        let rig = Rig()
        await rig.model.startUp()
        rig.reply = .halted(.panic)
        rig.model.discardAfterScreenshot()
        XCTAssertEqual(rig.model.screen, .stopped(.panic))
        rig.model.discardAfterScreenshot()
        XCTAssertEqual(rig.discards, 1, "a stopped app discards nothing more")
        XCTAssertEqual(rig.model.screen, .stopped(.panic))
    }

    func testADiscardThatBreaksTheContractStopsTheAppAsInternal() async {
        for reply: Reply<Void> in [.refused(.wrongCode), .discarded] {
            let rig = Rig()
            await rig.model.startUp()
            rig.reply = reply
            rig.model.discardAfterScreenshot()
            XCTAssertEqual(rig.model.screen, .stopped(.internal))
        }
    }

    func testAFailedSelfTestStopsTheAppBeforeAnyScreen() async {
        let rig = Rig(.stopped(.knownAnswerTest))
        await rig.model.startUp()
        XCTAssertEqual(rig.model.screen, .stopped(.knownAnswerTest))
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
    }
}
