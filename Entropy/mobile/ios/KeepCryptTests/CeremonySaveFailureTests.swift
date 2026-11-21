// A save that fails names its step and keeps the session (tasks/todo.md, M6 item U2; :screens' BackupScreensTest
// aFailedWriteReadBackOrVerifyNamesItsStepTheSessionStaysAndSaveAgainSaves), over the real slot, as the Save
// hook's fail-write, fail-read and corrupt modes give it on the phone: a write that fails, a read-back that
// fails and a read-back with a byte changed (core's verify refuses it, a backup refusal) each return to the
// save screen with that step's line, the encrypted file kept for Save again, which then saves and verifies.

import XCTest

final class CeremonySaveFailureTests: XCTestCase {
    override func setUpWithError() throws {
        try KcrVectors.load()
        assertLiveSlot()
    }

    override func tearDown() {
        assertSlotEmptied()
    }

    func testAFailedWriteReadBackOrVerifyNamesItsStepAndSaveAgainSaves() throws {
        let rig = Rig().toHome().toSummary("dice-50-words12")
        rig.confirm(rig.toConfirm())
        XCTAssertEqual(rig.screen, .backupSave)
        let changed: ([UInt8]) -> [UInt8]? = { bytes in
            var copy = bytes
            copy[copy.count / 2] ^= 0x01
            return copy
        }
        for (place, step) in [(FakePlace(writes: false), SaveStep.write), (FakePlace(reads: { _ in nil }), .readBack), (FakePlace(reads: changed), .verify)] {
            rig.model.saveBackup(FakePickers())
            rig.model.backupPlaced(place)
            rig.worker.run()
            let state = rig.model.state
            XCTAssertEqual(state.screen, .backupSave, "\(step): back on the save screen")
            XCTAssertEqual(state.saveFailure?.step, step)
            if step == .verify {
                let refusal = try XCTUnwrap(state.saveFailure?.refusal)
                XCTAssertTrue(isBackupRefusal(refusal), "a refusal the backup screens name")
                XCTAssertTrue(saveFailureText(try XCTUnwrap(state.saveFailure)).hasPrefix("Backup not saved: the file read back does not verify ("))
            }
            XCTAssertTrue(rig.model.held, "\(step): the session stays")
            XCTAssertNotNil(state.backupName, "\(step): the file kept for Save again")
        }
        rig.model.saveBackup(FakePickers())
        rig.model.backupPlaced(FakePlace())
        rig.worker.run()
        XCTAssertEqual(rig.screen, .backupVerified, "Save again saves and verifies")
        rig.model.backupVerifiedDone()
        rig.skipExports()
        rig.model.finishCeremony()
        XCTAssertEqual(rig.screen, .home)
    }
}
