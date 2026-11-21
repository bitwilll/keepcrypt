// A seed checked against a loaded registry snapshot to Finish, About, and the stop screen (tasks/todo.md, M6
// item U1; Android's SnapshotDrillTest and StopJourneyTest): Home's About (its version and this build's
// flavour) and Back; Load registry snapshot answered by the Snapshot file hook with kcr.json's small (its
// number and date, the warning a phone dated after it gives), Done, Home's snapshot line; a dice-only seed of
// dice-50-words12 by its 50 rolls, Check now run against the snapshot on its own: no collision for its Seal
// ID as of the snapshot's date; the 12 words, the vector's, read back; the summary; every export skipped; the
// checklist and Finish; then the Halt hook (the slot halted as core halts it), New seed and 12 words, whose
// start finds the halt: the stop screen naming its reason, and Close app, which ends the process. Through the
// UI alone but the offline path, the open picker and the halt (the hooks).

#if KC_TEST_HOOKS
import XCTest

final class SnapshotJourneyUITests: XCTestCase {
    /// One cause, one failure (U2f): a journey stops at its first failure, so a lost press is not followed by
    /// every later step failing for it.
    override func setUp() {
        continueAfterFailure = false
    }

    func testALoadedSnapshotChecksTheSeedToFinishThenAHaltShowsTheStopScreen() throws {
        let seed = try JourneyVectors.seed("dice-50-words12")
        let app = XCUIApplication()
        app.launchEnvironment["KC_HOOK_SNAPSHOT_NAME"] = "small.kcr"
        app.launchEnvironment["KC_HOOK_SNAPSHOT_HEX"] = try JourneyVectors.snapshotHex("small")
        let started = Date()
        app.toHome()
        app.press("show_about")
        app.on("about", "About")
        app.waitLabel("about_version", "Version 0.0.0")
        app.press("back")
        app.on("home", "Home")
        app.press("load_snapshot")
        app.press("hook_snapshot_file")
        app.on("snapshot", "the snapshot's result", timeout: 120)
        app.waitLabel("snapshot_result", "Snapshot loaded")
        app.waitLabel("snapshot_line", "Snapshot No. 2, dated 2026-03-01, 6 entries.")
        app.press("snapshot_done")
        app.on("home", "Home")
        app.waitLabel("home_snapshot", "Snapshot No. 2, dated 2026-03-01")
        pass("snapshot: About, kcr.json's small loaded by the picker hook, its line on Home (\(Int(Date().timeIntervalSince(started))) s)")
        app.press("dice_only_seed")
        app.on("length", "Length")
        app.press("words_12")
        app.on("dice", "the dice")
        app.roll(seed.rolls)
        app.press("check_now")
        app.on("check_result", "the check against the snapshot", timeout: 120)
        app.waitLabel("check_result_text", "No collision for seal " + seed.sealId + " as of 2026-03-01.")
        app.press("show_words")
        app.passGate("the words")
        app.on("words", "insert 1")
        app.wordsAndReadback(12, expected: seed.words)
        app.skipExports()
        app.checklistToFinish()
        pass("snapshot: dice-50-words12's 50 rolls checked against the snapshot on its own, its 12 words read back, the summary, every export skipped, Finish (\(Int(Date().timeIntervalSince(started))) s)")
        app.press("hook_halt")
        app.press("new_seed")
        app.on("length", "Length")
        app.press("words_12")
        app.on("stop", "the stop screen", timeout: 120)
        app.waitLabel("halt_reason", "An internal check failed.")
        app.press("close_app")
        XCTAssertTrue(app.wait(for: .notRunning, timeout: 30), "Close app ended the process")
        pass("stop: the halt's stop screen names its reason, Close app ends the process (\(Int(Date().timeIntervalSince(started))) s in all)")
    }
}
#endif
