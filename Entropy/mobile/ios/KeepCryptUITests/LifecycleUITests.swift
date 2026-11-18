// The phone's own edges (tasks/todo.md, M6 item U2), each in a few presses, the model's tests holding every
// screen (D2's ported tests: Back's table, leaving, 60 s away, going online, the idle timers, the kill's First
// launch): a trip home from a Public screen kept at 50 s away and wiped at 61 s (the clock hooks move the
// model's clock, never a real wait), a Protected screen discarded at once; the idle warning at 9 minutes and its
// tap, and the idle wipe at 10; the app killed at three stages, back at First launch with nothing kept (a loaded
// snapshot gone, the dice at 0); going online on the dice; a fast double tap on a button that changes the screen,
// on a dice face, on Confirm and on the privacy gate's pass, and the edge swipe (the app has no navigation stack,
// so iOS's back swipe moves nothing); a damaged snapshot and a wrong backup passphrase through the picker hooks.
// Through the UI alone but the hooks.

#if KC_TEST_HOOKS
import XCTest

final class LifecycleUITests: XCTestCase {
    /// One cause, one failure (U2f): a journey stops at its first failure, so a lost press is not followed by
    /// every later step failing for it.
    override func setUp() {
        continueAfterFailure = false
    }

    private let away = "The session was wiped after 60 seconds away from the app."
    private let left = "The session was wiped: the app was left during it."
    private let idle = "The session was wiped after 10 minutes without input."
    private let online = "The session was wiped: the phone went online."

    /// backup.json's abandon-12 file and passphrase.
    private func abandon12() throws -> (file: [UInt8], words: [String]) {
        let files = try XCTUnwrap(try JourneyVectors.json("backup")["age_files"] as? [[String: Any]])
        let entry = try XCTUnwrap(files.first { $0["name"] as? String == "abandon-12" })
        return (Array(try XCTUnwrap(entry["file"] as? String).utf8), try XCTUnwrap(entry["passphrase"] as? String).split(separator: " ").map(String.init))
    }

    private func withBackupFile(_ app: XCUIApplication) throws {
        app.launchEnvironment["KC_HOOK_BACKUP_NAME"] = "keepcrypt-backup-0123abcd.age"
        app.launchEnvironment["KC_HOOK_BACKUP_HEX"] = try abandon12().file.map { String(format: "%02x", $0) }.joined()
    }

    func testATripHomeKeepsAPublicScreenAt50SecondsWipesItAt61AndDiscardsAProtectedOneAtOnce() throws {
        let app = XCUIApplication()
        try withBackupFile(app)
        app.toHome()
        app.toDice(rolls: "1")
        app.press("hook_away_50")
        XCUIDevice.shared.press(.home)
        app.activate()
        app.on("cover", "the privacy cover over the Public dice after a trip home")
        app.element("cover").tap()
        app.on("dice", "the dice kept at 50 s away")
        app.waitLabel("dice_count", "1 / 50 rolls, 2.5 bits")
        app.press("hook_away_61")
        XCUIDevice.shared.press(.home)
        app.activate()
        app.waitNotice(away)
        // The wipe is found as the app comes back, still behind the privacy cover the trip home put up (the
        // model's show: covered until a tap, as Android's), so Home shows after the cover's tap.
        app.on("cover", "the privacy cover over Home after the wipe")
        app.element("cover").tap()
        pass("away: the Public dice kept at 50 s away (behind the cover), wiped at 61 s")
        app.on("home", "Home")
        app.press("check_backup")
        app.press("hook_backup_file")
        app.on("privacy_gate", "the gate before the passphrase's entry (Protected)")
        XCUIDevice.shared.press(.home)
        app.activate()
        app.waitNotice(left)
        pass("away: a Protected screen discarded at once on a trip home")
    }

    func testTheIdleWarningAt9MinutesAndTheWipeAt10() {
        let app = XCUIApplication()
        app.toHome()
        app.toDice(rolls: "2")
        app.press("hook_idle_9")
        app.on("idle_warning", "the idle warning at 9 minutes")
        app.element("idle_warning").tap()
        app.on("dice", "the dice kept by the warning's tap")
        app.waitLabel("dice_count", "1 / 50 rolls, 2.5 bits")
        app.press("hook_idle_9")
        app.press("hook_idle_1")
        app.waitNotice(idle)
        pass("idle: the warning at 9 minutes and its tap, the wipe at 10")
    }

    func testTheAppKilledAtThreeStagesStartsAtFirstLaunchWithNothingKept() throws {
        let app = XCUIApplication()
        try withBackupFile(app)
        app.launchEnvironment["KC_HOOK_SNAPSHOT_NAME"] = "small.kcr"
        app.launchEnvironment["KC_HOOK_SNAPSHOT_HEX"] = try JourneyVectors.snapshotHex("small")
        app.toHome()
        app.press("load_snapshot")
        app.press("hook_snapshot_file")
        app.on("snapshot", "the snapshot loaded", timeout: 120)
        app.press("snapshot_done")
        app.on("home", "Home")
        app.waitLabel("home_snapshot", "Snapshot No. 2, dated 2026-03-01")
        app.terminate()
        app.toHome()
        app.waitLabel("home_snapshot", "No registry snapshot loaded")
        XCTAssertFalse(app.element("notice").exists, "no notice after a kill: nothing was held to wipe")
        app.toDice(rolls: "34")
        app.terminate()
        app.toHome()
        app.toDice()
        app.waitLabel("dice_count", "0 / 50 rolls, 0.0 bits")
        app.terminate()
        app.toHome()
        app.press("check_backup")
        app.press("hook_backup_file")
        app.on("privacy_gate", "the passphrase's entry behind its gate")
        app.terminate()
        app.toHome()
        pass("kill: at Home with a snapshot, on the dice with rolls and on a Protected gate, each back at First launch with nothing kept")
    }

    func testGoingOnlineOnTheDiceWipesTheSession() {
        let app = XCUIApplication()
        app.toHome()
        app.toDice(rolls: "5")
        app.press("hook_path_usable")
        app.on("go_offline", "Go offline after the phone went online")
        app.waitNotice(online)
        pass("online: the dice's session wiped, Go offline with its notice")
    }

    func testFastDoubleTapsTakeOnePressAndTheEdgeSwipeMovesNothing() throws {
        let app = XCUIApplication()
        try withBackupFile(app)
        app.toHome()
        let before = app.touchCounts()
        app.buttons["dice_only_seed"].doubleTap()
        app.on("length", "Length after a double tap on Dice-only seed")
        XCTAssertFalse(app.within(2) { app.element("dice").exists }, "the second tap reached Length's 12 words")
        pass("probe: the double tap's touches \(before) to \(app.touchCounts()) (a refused second touch, or one Home's button no longer took)")
        let edge = app.coordinate(withNormalizedOffset: CGVector(dx: 0.0, dy: 0.5))
        edge.press(forDuration: 0.05, thenDragTo: app.coordinate(withNormalizedOffset: CGVector(dx: 0.9, dy: 0.5)))
        XCTAssertTrue(app.element("length").exists && !app.element("home").exists, "the edge swipe moved nothing")
        app.press("words_12")
        app.on("dice", "the dice")
        app.buttons["key_3"].doubleTap()
        app.waitLabel("kc_secret_dice_pick", "3")
        app.buttons["confirm"].doubleTap()
        app.waitLabel("dice_count", "1 / 50 rolls, 2.5 bits")
        XCTAssertFalse(app.within(2) { app.element("dice_count").label.hasPrefix("2 / ") }, "a double tap on Confirm pushed two rolls")
        pass("double tap: one screen on a changing button, one face and one roll on the pad, and no back swipe")
        app.terminate()
        app.toHome()
        app.press("check_backup")
        app.press("hook_backup_file")
        app.on("privacy_gate", "the gate before the passphrase's entry")
        let gateBefore = app.touchCounts()
        app.buttons["pass_gate"].doubleTap()
        if !app.within(10, { app.element("backup_check_entry").exists }) {
            // Classified as pressUntil classifies (U2g): touches that never reached the app, touches the press
            // guard refused, or touches it admitted that did nothing (the app's defect). The facts first, then the
            // button's place, which reads "gone" when the screen went with it (U2h).
            let facts = app.facts()
            let gateAfter = app.touchCounts()
            let seen = gateAfter.seen - gateBefore.seen
            let refused = gateAfter.refused - gateBefore.refused
            let verdict = seen == 0
                ? "neither touch reached the app"
                : refused == seen ? "the press guard refused every touch it saw" : "\(seen - refused) admitted and did nothing"
            XCTFail("the gate's double tap reached no entry: \(verdict) (touches \(gateBefore) to \(gateAfter)); " + facts
                + "; the button " + app.place(app.buttons["pass_gate"]))
        }
        app.on("backup_check_entry", "the entry")
        app.waitLabel("kc_secret_typed_letters", "----")
        pass("double tap: the privacy gate's pass reaches nothing behind it")
    }

    func testADamagedSnapshotAndAWrongBackupPassphraseAreRefused() throws {
        let app = XCUIApplication()
        try withBackupFile(app)
        app.launchEnvironment["KC_HOOK_SNAPSHOT_NAME"] = "bad-magic.kcr"
        app.launchEnvironment["KC_HOOK_SNAPSHOT_HEX"] = try JourneyVectors.snapshotHex("bad-magic")
        app.toHome()
        app.press("load_snapshot")
        app.press("hook_snapshot_file")
        app.on("snapshot", "the snapshot's result", timeout: 120)
        app.waitLabel("snapshot_result", "Snapshot not loaded")
        app.waitLabel("snapshot_refusal", "registry snapshot or proof rejected: wrong magic")
        app.press("snapshot_done")
        app.on("home", "Home")
        app.waitLabel("home_snapshot", "No registry snapshot loaded")
        app.press("check_backup")
        app.press("hook_backup_file")
        app.passGate("the passphrase's entry")
        app.on("backup_check_entry", "the entry")
        for word in "praise bone derive dinner acid winter choose control".split(separator: " ") {
            app.letters(String(word))
            app.pressEnabled("entry_done")
        }
        app.waitLabel("entry_refusal", "the passphrase does not open this backup", timeout: 120)
        app.waitLabel("entry_word", "Backup passphrase, word 1 of 8")
        app.press("back")
        app.on("home", "Home")
        pass("refused: a damaged snapshot (bad magic) and a wrong backup passphrase, each by its line")
    }
}
#endif
