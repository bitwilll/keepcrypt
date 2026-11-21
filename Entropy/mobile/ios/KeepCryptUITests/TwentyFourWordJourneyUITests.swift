// A dice-only seed of 24 words with its check skipped to Finish (tasks/todo.md, M6 item U1; Android's
// JourneyTest aDiceOnlyTwentyFourWordSeedSkipsItsCheck...): kcr.json's dice-99-words24 by its 99 rolls on the
// dice pad, Skip and its confirm, the result saying the check was skipped, the 24 words on two devices with the
// device swap and its second gate before word 13, each the vector's, all 24 read back on the letter pad with
// each insert's device named, the summary, every export skipped, the checklist saying which device holds words
// 1-12, and Finish. Through the UI alone but the offline path (the hook).

#if KC_TEST_HOOKS
import XCTest

final class TwentyFourWordJourneyUITests: XCTestCase {
    /// One cause, one failure (U2f): a journey stops at its first failure, so a lost press is not followed by
    /// every later step failing for it.
    override func setUp() {
        continueAfterFailure = false
    }

    func testADiceOnlyTwentyFourWordSeedSkipsItsCheckAndReachesFinishOnTwoDevices() throws {
        let seed = try JourneyVectors.seed("dice-99-words24")
        let app = XCUIApplication()
        let started = Date()
        app.toHome()
        app.press("dice_only_seed")
        app.on("length", "Length")
        app.press("words_24")
        app.on("dice", "the dice")
        app.roll(seed.rolls)
        app.press("skip")
        app.on("skip_confirm", "Skip's confirm")
        app.press("confirm_action")
        app.on("check_result", "the result")
        app.waitLabel("check_result_text", "You skipped the check: the seal can be checked later from the words.")
        app.press("show_words")
        app.passGate("the words")
        app.on("words", "insert 1")
        app.wordsAndReadback(24, expected: seed.words)
        app.skipExports()
        app.checklistToFinish(twoDevices: true)
        pass("24 words: dice-99-words24's 99 rolls, Skip, its 24 words on two devices with the swap and its gate, all read back, the summary, every export skipped, the checklist's two devices and Finish: Home (\(Int(Date().timeIntervalSince(started))) s)")
    }
}
#endif
