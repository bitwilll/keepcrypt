// The start screens' model rules (tasks/todo.md, M6 item D3), ported from :screens' StartScreensTest.kt,
// and PadPressTest.kt, over the real slot: the dice pad
// picks, Confirm pushes and Undo takes back; the faces picked are the rolls core takes; Confirm does nothing
// at 256 rolls; Back on the start screens; a dice key under the cover or the warning picks nothing, and a key
// picked is input. Each test leaves the slot at home.

import XCTest

final class CeremonyStartScreensTests: XCTestCase {
    override func setUpWithError() throws {
        try KcrVectors.load()
        assertLiveSlot()
    }

    override func tearDown() {
        assertSlotEmptied()
    }

    private func rolls(_ rig: Rig) -> Int? { rig.model.state.dice?.rolls }

    /// What entry holds, read in-process (test values only, never printed).
    private func typed(_ entry: PadEntry) -> String {
        String((0..<entry.length).map { entry.keyAt($0) })
    }

    /// StartScreensTest.kt's theDicePadPicksConfirmPushesAndUndoTakesBack.
    func testTheDicePadPicksConfirmPushesAndUndoTakesBack() throws {
        let rig = Rig().toHome().begin(.diceOnly, .twelve)
        rig.model.confirmRoll()
        XCTAssertEqual(rolls(rig), 0, "no face picked, nothing pushed")
        XCTAssertTrue(rig.model.dicePick.replace("3"))
        rig.model.confirmRoll()
        let one = try XCTUnwrap(rig.model.state.dice)
        XCTAssertEqual(diceText(one.rolls, one.minimum, one.millibits), "1 / 50 rolls, 2.5 bits")
        XCTAssertEqual(rig.model.dicePick.length, 0, "the pick goes with the confirm")
        XCTAssertTrue(rig.model.dicePick.zeroPastLength(), "and its byte is zeroed")
        rig.model.dicePick.replace("4")
        rig.model.undoRoll()
        XCTAssertEqual(rolls(rig), 0)
        XCTAssertEqual(rig.model.dicePick.length, 1, "undo keeps the pick")
        rig.model.undoRoll()
        XCTAssertEqual(rolls(rig), 0, "undo with no roll does nothing")
        rig.roll(49)
        XCTAssertEqual(rolls(rig), 49)
        rig.roll(1)
        let dice = try XCTUnwrap(rig.model.state.dice)
        XCTAssertEqual(diceText(dice.rolls, dice.minimum, dice.millibits), "50 / 50 rolls, 129.2 bits")
    }

    /// StartScreensTest.kt's theFacesPickedOnThePadAreTheRollsCoreTakes: dice-50-words12's rolls picked on the
    /// pad give its Seal ID only if every face reached core as the face picked.
    func testTheFacesPickedOnThePadAreTheRollsCoreTakes() throws {
        let rig = Rig().toHome().begin(.diceOnly, .twelve)
        let seed = try Vectors.seed("dice-50-words12")
        for face in KcrVectors.rolls("dice-50-words12") {
            XCTAssertTrue(rig.model.dicePick.replace(face))
            rig.model.confirmRoll()
        }
        XCTAssertEqual(rolls(rig), 50)
        XCTAssertTrue(isDone(Core.shared.finish()), "finish")
        let card = try done(Core.shared.seal(), "the seal")
        XCTAssertEqual(card.sealId, seed["seal_id"] as? String, "the rolls core took are not the faces picked")
    }

    /// StartScreensTest.kt's confirmDoesNothingAt256Rolls.
    func testConfirmDoesNothingAt256Rolls() {
        let rig = Rig().toHome().begin(.diceOnly, .twelve)
        rig.roll(maxRolls)
        XCTAssertEqual(rolls(rig), maxRolls)
        rig.model.dicePick.replace("1")
        rig.model.confirmRoll()
        XCTAssertEqual(rolls(rig), maxRolls, "no 257th roll")
        rig.model.undoRoll()
        XCTAssertEqual(rolls(rig), maxRolls - 1, "undo still works")
    }

    /// StartScreensTest.kt's backGoesBackOnlyWhereNothingIsLost.
    func testBackGoesBackOnlyWhereNothingIsLost() {
        let rig = Rig()
        rig.model.back()
        XCTAssertEqual(rig.screen, .firstLaunch)
        rig.startUp()
        rig.model.back()
        XCTAssertEqual(rig.screen, .firstLaunch, "nothing before First launch")
        rig.model.firstLaunchDone()
        rig.model.back()
        XCTAssertEqual(rig.screen, .selfTest, "nothing leaves the self-test but its reply")
        rig.worker.run()
        rig.model.back()
        XCTAssertEqual(rig.screen, .firstLaunch, "Go offline back to First launch")
        rig.model.firstLaunchDone()
        XCTAssertEqual(rig.screen, .goOffline, "the self-test passed, so Continue goes on at once")
        XCTAssertEqual(rig.worker.waiting, 0, "with no second self-test")
        rig.model.startOffline()
        rig.model.back()
        XCTAssertEqual(rig.screen, .goOffline, "Home back to Go offline")
        rig.model.startOffline()
        rig.model.chooseMode(.mixed)
        rig.model.back()
        XCTAssertEqual(rig.screen, .home, "Length back to Home")
        rig.model.chooseMode(.mixed)
        rig.model.appLeft()
        rig.model.appReturned()
        XCTAssertEqual(rig.model.state.overlay, .cover)
        rig.model.back()
        XCTAssertEqual(rig.screen, .length, "the cover takes the press")
        rig.model.dismissOverlay()
        rig.model.chooseLength(.twelve)
        rig.model.back()
        XCTAssertEqual(rig.screen, .working, "nothing leaves Working but its reply")
        rig.worker.run()
        rig.model.back()
        XCTAssertEqual(rig.screen, .deviceEntropy)
        XCTAssertTrue(rig.model.held, "Back kept the session")
        rig.model.deviceEntropyDone()
        rig.model.back()
        XCTAssertEqual(rig.screen, .commitment)
        rig.model.commitmentDone()
        rig.roll(1)
        rig.model.back()
        XCTAssertEqual(rig.screen, .dice)
        XCTAssertEqual(rolls(rig), 1, "Back kept the roll")
    }

    /// PadPressTest.kt's aDiceKeyUnderTheCoverOrTheWarningPicksNothingAndAKeyPickedIsInput.
    func testADiceKeyUnderTheCoverOrTheWarningPicksNothingAndAKeyPickedIsInput() {
        let rig = Rig().toHome().begin(.diceOnly, .twelve)
        XCTAssertEqual(rig.screen, .dice)
        rig.press("3")
        rig.press("5")
        XCTAssertEqual(typed(rig.model.dicePick), "5", "a face replaces the pick")
        rig.pressDelete()
        XCTAssertEqual(typed(rig.model.dicePick), "5", "the dice pad has no Delete")
        rig.model.appLeft()
        rig.model.appReturned()
        XCTAssertEqual(rig.model.state.overlay, .cover, "left on a Public screen, the cover")
        rig.press("2")
        XCTAssertEqual(typed(rig.model.dicePick), "5", "a key under the cover picked nothing")
        rig.model.dismissOverlay()
        rig.clock.now = 100_000
        rig.press("1")
        rig.clock.now = 100_000 + Timers.warnMillis - 1
        rig.model.tick()
        XCTAssertNil(rig.model.state.overlay, "the key started the idle time again")
        rig.clock.now = 100_000 + Timers.warnMillis
        rig.model.tick()
        XCTAssertEqual(rig.model.state.overlay, .warning)
        rig.press("4")
        XCTAssertEqual(typed(rig.model.dicePick), "1", "a key under the warning picked nothing")
        rig.clock.now = 100_000 + Timers.wipeMillis
        rig.model.tick()
        XCTAssertEqual(rig.model.state.notice, .idle, "nor was it input")
    }

    /// PadPressTest.kt's theCodeEntrysPadTypesAndDeletesOnlyUncoveredAndTheDiceAt256RollsPicksNothing.
    func testTheCodeEntrysPadTypesAndDeletesOnlyUncoveredAndTheDiceAt256RollsPicksNothing() {
        let rig = Rig().toHome().begin(.diceOnly, .twelve)
        rig.roll(maxRolls)
        rig.press("1")
        XCTAssertEqual(rig.model.dicePick.length, 0, "a face picked at 256 rolls, where the pad is disabled")
        rig.model.diceDone()
        rig.worker.run()
        rig.model.checkNow()
        rig.model.showCheckQr()
        rig.model.typeCode()
        XCTAssertEqual(rig.screen, .codeEntry)
        rig.press("PBJ")
        rig.pressDelete()
        XCTAssertEqual(typed(rig.model.goAheadCode), "PB")
        rig.model.appLeft()
        rig.model.appReturned()
        XCTAssertEqual(rig.model.state.overlay, .cover)
        rig.press("N")
        rig.pressDelete()
        XCTAssertEqual(typed(rig.model.goAheadCode), "PB", "a key or Delete under the cover acted")
    }
}
