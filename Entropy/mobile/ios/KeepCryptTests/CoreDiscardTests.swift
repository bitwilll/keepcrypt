// A discard never waits for a long call (tasks/todo.md, M6 item D2; keepcrypt-ffi's ffi_discard_during_call
// rule, ffi/tests/ceremony.rs): over the real kc_call, Check a backup's opening of SavedBackup.shared (core's
// openBackup at home, scrypt at log2 N = 18, a long call) is timed once, then runs on a thread of its own,
// and a discard, then a wipe, made from the test's thread a third of that time into it, returns at once, done, through Core's small buffer, while
// the long call is still running; the long call then returns discarded, and both buffers are wiped. Named to
// run before CoreTests, whose last steps halt the slot (CeremonySupport.swift).

import XCTest

final class CoreDiscardTests: XCTestCase {
    override func setUpWithError() throws {
        try KcrVectors.load()
        assertLiveSlot()
    }

    override func tearDown() {
        assertSlotEmptied()
    }

    /// The long call's reply and how long it took, handed from its thread.
    private final class Handed {
        var reply: Reply<OpenedBackup>?
        var millis: UInt64 = 0
    }

    private func millisSince(_ start: UInt64) -> UInt64 {
        (DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
    }

    /// The saved backup's eight entries (their first four letters) and its file, as Check a backup hands
    /// them to core.
    private func opening(_ saved: SavedBackup) -> ([Secret], Secret) {
        (saved.passphrase.map { Secret(taking: Array($0.prefix(4).utf8)) }, Secret(taking: saved.file))
    }

    func testADiscardOrAWipeDuringALongCallReturnsAtOnce() {
        let saved = SavedBackup.shared
        // The long call once with nothing in its way, timed, so the cuts below land well inside it.
        let (dryEntries, dryFile) = opening(saved)
        let dryStart = DispatchTime.now().uptimeNanoseconds
        XCTAssertTrue(isDone(Core.shared.openBackup(entries: dryEntries, file: dryFile)), "the backup opens")
        let length = millisSince(dryStart)
        XCTAssertTrue(isDone(Core.shared.end()), "Check a backup's Done")
        XCTAssertGreaterThanOrEqual(length, 30, "the long call takes \(length) ms: too short to land a cut inside it")
        let cuts: [(String, () -> Reply<Void>)] = [("a discard", { Core.shared.discard() }), ("a wipe", { Core.shared.wipeAll() })]
        for (what, cut) in cuts {
            let (entries, file) = opening(saved)
            let handed = Handed()
            let started = DispatchGroup()
            let finished = DispatchGroup()
            started.enter()
            finished.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                started.leave()
                let start = DispatchTime.now().uptimeNanoseconds
                handed.reply = Core.shared.openBackup(entries: entries, file: file)
                handed.millis = (DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
                finished.leave()
            }
            started.wait()
            usleep(useconds_t(length * 1_000 / 3))
            let start = DispatchTime.now().uptimeNanoseconds
            let reply = cut()
            let took = millisSince(start)
            let running = finished.wait(timeout: .now()) == .timedOut
            XCTAssertTrue(isDone(reply), "\(what): done")
            XCTAssertTrue(running, "\(what) returned only once the long call had (\(took) ms): it waited for it")
            if running { finished.wait() }
            var discarded = false
            if case .discarded? = handed.reply { discarded = true }
            XCTAssertTrue(discarded, "\(what): the long call returns discarded")
            XCTAssertLessThan(took * 2, length, "\(what) took \(took) ms, the long call \(length) ms: it waited")
            XCTAssertTrue(Core.shared.replyBufferIsWiped(), "\(what): a reply buffer left unwiped")
            for entry in entries {
                entry.wipe()
            }
            file.wipe()
            XCTAssertTrue(isDone(Core.shared.selfTest()), "\(what): the slot at home again")
        }
    }
}
