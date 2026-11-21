// One press opens one picker (tasks/todo.md, M6 item D2), ported from :screens' PickerPressTest.kt (Stage
// U's U2c), over the real slot: while a picker the app opened is up, a press that would open one opens
// none; its answer (a place, a file or none, a late one after Home has gone too) or the app's next resume
// (an answer lost) frees the buttons again, and the picker's leaving, should iOS report one, is no leaving.
// Each test leaves the slot at home.

import XCTest

final class CeremonyPickerPressTests: XCTestCase {
    override func setUpWithError() throws {
        try KcrVectors.load()
        assertLiveSlot()
    }

    override func tearDown() {
        assertSlotEmptied()
    }

    /// PickerPressTest.kt's aSecondPressOnSaveOpensNoSecondPickerUntilTheFirstAnswers.
    func testASecondPressOnSaveOpensNoSecondPickerUntilTheFirstAnswers() {
        let rig = Walk.to(.backupSave)
        let pickers = FakePickers()
        rig.model.saveBackup(pickers)
        rig.model.saveBackup(pickers)
        XCTAssertEqual(pickers.created.count, 1, "a double tap on Save opened one picker")
        rig.model.backupPlaced(nil)
        XCTAssertEqual(rig.screen, .backupSave, "no place: the save screen stays")
        rig.model.saveBackup(pickers)
        XCTAssertEqual(pickers.created.count, 2, "the answer freed Save")
    }

    /// PickerPressTest.kt's homesTwoPickersOpenOneAtATime.
    func testHomesTwoPickersOpenOneAtATime() {
        let rig = Walk.to(.home)
        let pickers = FakePickers()
        rig.model.checkBackup(pickers)
        rig.model.checkBackup(pickers)
        rig.model.loadSnapshot(pickers)
        XCTAssertEqual(pickers.opens, 1, "a double tap on Check a backup opened one picker")
        XCTAssertEqual(pickers.snapshotOpens, 0, "Load registry snapshot opened a second picker over the first")
        rig.model.backupPicked(nil)
        rig.model.loadSnapshot(pickers)
        rig.model.checkBackup(pickers)
        XCTAssertEqual(pickers.snapshotOpens, 1, "the answer freed Load registry snapshot")
        XCTAssertEqual(pickers.opens, 1, "Check a backup opened a second picker over the snapshot's")
        rig.model.snapshotPicked(nil)
        rig.model.checkBackup(pickers)
        XCTAssertEqual(pickers.opens, 2, "the snapshot picker's answer freed Check a backup")
    }

    /// PickerPressTest.kt's aResumeWithNoAnswerFreesThePickersButtons.
    func testAResumeWithNoAnswerFreesThePickersButtons() {
        let rig = Walk.to(.home)
        let pickers = FakePickers()
        rig.model.checkBackup(pickers)
        rig.model.appLeft()
        rig.model.appReturned()
        rig.model.appResumed()
        XCTAssertEqual(rig.screen, .home, "the picker's leaving was no leaving")
        XCTAssertNil(rig.model.state.overlay, "the picker's leaving brought no cover")
        rig.model.checkBackup(pickers)
        XCTAssertEqual(pickers.opens, 2, "a resume with the answer lost freed Check a backup")
    }

    /// PickerPressTest.kt's aLateAnswerFreesThePickersButtons.
    func testALateAnswerFreesThePickersButtons() {
        let rig = Walk.to(.home)
        let pickers = FakePickers()
        rig.model.checkBackup(pickers)
        rig.offline.set(false)
        XCTAssertEqual(rig.screen, .goOffline, "going online while the picker is up: Home needs the phone offline")
        rig.model.backupPicked(nil)
        rig.offline.set(true)
        rig.model.startOffline()
        XCTAssertEqual(rig.screen, .home)
        rig.model.checkBackup(pickers)
        XCTAssertEqual(pickers.opens, 2, "the late answer, with no resume, freed Check a backup")
    }
}
