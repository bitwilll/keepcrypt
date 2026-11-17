// The model on a halt (tasks/todo.md, M6 item D2), ported from :screens' CeremonyModelRefusalTest.kt,
// CeremonyModelHaltTest.kt, CheckBackupHaltTest.kt and the four Residual*HaltTest.kt classes. The JVM runs
// each in a process of its own, since a halt latches the slot for good; XCTest runs every class in one
// process, so here the slot that halts is StandInCore's (CeremonySupport.swift), which forwards each call to
// Core until it halts and then answers every call with that halt, as the slot does, reaching Core no more;
// the real slot is emptied after each test. Core's own rule that a halt latches, and that a call core does
// not offer at home halts the slot (lead decision M5-54's residual), are keepcrypt-ffi's and pinned there
// (ffi/tests/ceremony.rs); the residuals here have StandInCore answer that call with the halt core gives it.

import XCTest

final class CeremonyHaltTests: XCTestCase {
    override func setUpWithError() throws {
        try KcrVectors.load()
        assertLiveSlot()
    }

    override func tearDown() {
        assertSlotEmptied()
    }

    /// CeremonyModelRefusalTest.kt's aRefusalFromACallWithNoHandlerHalts.
    func testARefusalFromACallWithNoHandlerHalts() {
        let core = StandInCore()
        let rig = Rig(core: core).startUp()
        rig.model.work({ _ in Reply<Void>.refused(.wrongCode) }) { _ in XCTFail("a refused call gives no value") }
        rig.worker.run()
        XCTAssertEqual(rig.screen, .stop)
        XCTAssertEqual(core.latched, .internal, "the slot halted")
    }

    /// CeremonyModelHaltTest.kt's aSecondLongCallHaltsAndNothingLeavesTheStopScreen.
    func testASecondLongCallHaltsAndNothingLeavesTheStopScreen() {
        let core = StandInCore()
        let rig = Rig(core: core).startUp()
        XCTAssertEqual(rig.screen, .firstLaunch)
        var first = false
        rig.model.work({ _ in Reply<Void>.done(()) }) { _ in first = true }
        XCTAssertEqual(rig.screen, .working)
        rig.model.work({ _ in Reply<Void>.done(()) }) { _ in XCTFail("the second call is never made") }
        XCTAssertEqual(rig.screen, .stop, "a second long call halts")
        XCTAssertEqual(rig.model.state.halt, .internal, "the shell's own halt is internal")
        XCTAssertEqual(haltReason(core.selfTest()), .internal, "the slot halted")
        rig.worker.run()
        XCTAssertFalse(first, "the first call's reply changes nothing after the halt")
        XCTAssertEqual(rig.screen, .stop)
        rig.model.appLeft()
        rig.model.appReturned()
        rig.offline.set(false)
        rig.model.input()
        rig.model.tick()
        rig.model.discardAfterScreenshot()
        rig.model.wipeAll()
        rig.model.work({ _ in Reply<Void>.done(()) }) { _ in XCTFail("nothing runs on the stop screen") }
        XCTAssertEqual(rig.worker.waiting, 0)
        XCTAssertEqual(rig.screen, .stop)
        XCTAssertEqual(rig.model.state.halt, .internal)
    }

    /// CheckBackupHaltTest.kt's aHaltAfterTheWorkersSecondLookZeroesWhatTheReadGave: Check a backup's read
    /// made on the worker, whose second look found no discard, its reply kept for the main thread, then a
    /// second long call, the shell's bug, which halts; when the main thread takes the reply it finds the
    /// halt, wipes what the read gave and the stop screen stays.
    func testAHaltAfterTheWorkersSecondLookWipesWhatTheReadGave() {
        let core = StandInCore()
        let rig = Rig(core: core).toHome()
        rig.model.checkBackup(FakePickers())
        rig.model.appLeft()
        rig.model.appReturned()
        let file = FakeFile(name: SavedBackup.name, size: 100, bytes: [UInt8](repeating: 1, count: 100))
        rig.model.backupPicked(file)
        let main = rig.worker.runWorkerPart()
        XCTAssertEqual(file.reads, 1)
        XCTAssertFalse(zeroed(file.given), "the bytes read wait for the main thread")
        rig.model.work({ _ in Reply<Void>.done(()) }) { _ in XCTFail("the second call is never made") }
        XCTAssertEqual(rig.screen, .stop, "a second long call halts")
        XCTAssertEqual(haltReason(core.selfTest()), .internal, "the slot halted")
        main()
        XCTAssertTrue(zeroed(file.given), "what the read gave was wiped")
        XCTAssertEqual(rig.screen, .stop, "the read's reply leaves the stop screen as it is")
        XCTAssertEqual(rig.worker.waiting, 0, "nothing more reached the worker")
    }

    /// TestSupport.kt's assertTheResidualHalts: call, a long call core does not offer at home, from rig's
    /// screen, the worker's first look finds no discard, and a discard (going online) lands before core's
    /// call, so the call meets the slot at home, which halts: the stop screen with the slot's halt,
    /// internal, not the start screen a call core offers at home would end on.
    private func assertTheResidualHalts(_ rig: Rig, _ core: StandInCore, _ call: @escaping (CeremonyCore) -> Reply<Void>) {
        let screen = rig.screen
        var refused: Refusal?
        var gave = false
        rig.model.work({ slot in
            rig.offline.set(false)
            core.haltsAtHome = true
            return call(slot)
        }, refused: { refused = $0 }) { _ in gave = true }
        XCTAssertEqual(rig.screen, .working, "\(screen.id): the call's screen")
        rig.worker.run()
        XCTAssertNil(refused, "\(screen.id): core refused the call")
        XCTAssertFalse(gave, "\(screen.id): the call gave a value")
        XCTAssertEqual(rig.screen, .stop, "\(screen.id): a discard in the window halts (M5-54)")
        XCTAssertEqual(rig.model.state.halt, .internal, "\(screen.id): the stage rule's halt")
        XCTAssertEqual(haltReason(core.selfTest()), .internal, "the slot halted")
    }

    /// ResidualFinishHaltTest.kt: the dice's Done, with 99 rolls of a 24-word seed in.
    func testAResidualDiscardBeforeFinishHalts() {
        let core = StandInCore()
        let rig = Walk.to(.dice, core: core)
        rig.roll(99)
        assertTheResidualHalts(rig, core) { $0.finish() }
    }

    /// ResidualRevealProofHaltTest.kt: a scanned go-ahead QR's check.
    func testAResidualDiscardBeforeRevealProofHalts() {
        let core = StandInCore()
        let rig = Walk.to(.scan, core: core)
        let today = rig.date.today()
        assertTheResidualHalts(rig, core) { slot in
            switch slot.revealProof(today: today, text: "not a proof") {
            case .done: return .done(())
            case .refused(let refusal): return .refused(refusal)
            case .discarded: return .discarded
            case .halted(let reason): return .halted(reason)
            }
        }
    }

    /// ResidualEncryptBackupHaltTest.kt: the backup's encryption, from the save screen.
    func testAResidualDiscardBeforeEncryptBackupHalts() {
        let core = StandInCore()
        let rig = Walk.to(.backupSave, core: core)
        assertTheResidualHalts(rig, core) { slot in
            switch slot.encryptBackup() {
            case .done(let file):
                file.bytes.wipe()
                return .done(())
            case .refused(let refusal): return .refused(refusal)
            case .discarded: return .discarded
            case .halted(let reason): return .halted(reason)
            }
        }
    }

    /// ResidualVerifyBackupHaltTest.kt: the saved backup's check, on the save screen.
    func testAResidualDiscardBeforeVerifyBackupHalts() {
        let core = StandInCore()
        let rig = Walk.to(.backupSave, core: core)
        assertTheResidualHalts(rig, core) { $0.verifyBackup(Secret(taking: [UInt8](repeating: 0, count: 16))) }
    }

    /// CeremonyModelBusyScreenTest.kt's aLongCallBehindAScreenThatTakesInputHalts: a long call behind a
    /// screen that takes input (Home) is the shell's bug, and halts before the call is made.
    func testALongCallBehindAScreenThatTakesInputHalts() {
        let core = StandInCore()
        let rig = Rig(core: core).toHome()
        XCTAssertEqual(rig.screen, .home)
        rig.model.work({ _ in Reply<Void>.done(()) }, busy: .home) { _ in XCTFail("the call is never made") }
        XCTAssertEqual(rig.screen, .stop, "a busy screen that takes input halts")
        XCTAssertEqual(rig.worker.waiting, 0, "nothing went to the worker")
        XCTAssertEqual(haltReason(core.selfTest()), .internal, "the slot halted")
    }
}
