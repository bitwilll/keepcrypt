// The camera refused, absent or failed on the scan screen (tasks/todo.md, M6 item U2; M6-9), over the real slot:
// the scanner's stop is the model's scanStopped. Each says why on the scan screen (scanLine), scans no more, and
// keeps the check: its seal and check QR stay, the code entry is offered and opens, and Back returns to the check
// QR; a second stop, or one on another screen, does nothing. Open Settings is drawn after a refusal alone
// (CheckScreens.swift's condition, scanStop == .refused). The simulator has no camera, so CheckEdgesUITests sees
// the absent camera on the phone; a refused or failed one needs a device (I2).

import XCTest

final class CeremonyScanStopTests: XCTestCase {
    override func setUpWithError() throws {
        try KcrVectors.load()
        assertLiveSlot()
    }

    override func tearDown() {
        assertSlotEmptied()
    }

    func testEachCameraStopSaysWhyAndKeepsTheCheck() {
        for (stop, line) in [(ScanStop.refused, CheckTexts.scanRefused), (.missing, CheckTexts.scanMissing), (.failed, CheckTexts.scanFailed)] {
            let rig = Walk.to(.scan)
            let seal = rig.model.state.seal
            XCTAssertNotNil(seal)
            rig.model.scanStopped(stop)
            XCTAssertEqual(rig.screen, .scan, "\(stop): the scan screen stays")
            XCTAssertEqual(rig.model.state.scanStop, stop)
            XCTAssertEqual(scanLine(rig.model.state), line, "\(stop): its line")
            XCTAssertEqual(rig.model.state.scanStop == .refused, stop == .refused, "Open Settings after a refusal alone")
            rig.model.scanStopped(stop == .refused ? .failed : .refused)
            XCTAssertEqual(rig.model.state.scanStop, stop, "\(stop): a second stop does nothing")
            XCTAssertEqual(rig.model.state.seal, seal, "\(stop): the check's seal kept")
            rig.model.typeCode()
            XCTAssertEqual(rig.screen, .codeEntry, "\(stop): the code entry opens")
            rig.model.back()
            XCTAssertEqual(rig.screen, .checkQr, "\(stop): Back is the check QR, the check kept")
            rig.model.scanStopped(stop)
            XCTAssertNil(rig.model.state.scanStop, "\(stop): a stop off the scan screen does nothing")
            assertSlotEmptied()
        }
    }
}
