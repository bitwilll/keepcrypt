// A discard never waits for a long call (tasks/todo.md, M6 item D2; keepcrypt-ffi's ffi_discard_during_call
// rule, ffi/tests/ceremony.rs): over the real kc_call, Check a backup's opening of SavedBackup.shared (core's
// openBackup at home, scrypt at log2 N = 18, a long call) is timed once, then runs on a thread of its own,
// and a discard, then a wipe, made from the test's thread a third of the fastest of three timed runs into it,
// returns at once, done, through Core's small buffer; the long call then returns discarded, and both buffers
// are wiped. A try whose long call ended before the cut (done, not discarded) proves nothing and is retried
// sooner (run 44131627368: a slow baseline put the cut past the call's end). Named to
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
        // The long call with nothing in its way, timed three times; the fastest is the baseline, so one slow
        // run on a busy simulator cannot stretch the cut past the call's end.
        var length = UInt64.max
        for _ in 0..<3 {
            let (dryEntries, dryFile) = opening(saved)
            let dryStart = DispatchTime.now().uptimeNanoseconds
            XCTAssertTrue(isDone(Core.shared.openBackup(entries: dryEntries, file: dryFile)), "the backup opens")
            length = min(length, millisSince(dryStart))
            XCTAssertTrue(isDone(Core.shared.end()), "Check a backup's Done")
        }
        XCTAssertGreaterThanOrEqual(length, 30, "the long call takes \(length) ms: too short to land a cut inside it")
        let cuts: [(String, () -> Reply<Void>)] = [("a discard", { Core.shared.discard() }), ("a wipe", { Core.shared.wipeAll() })]
        for (what, cut) in cuts {
            // A try is judged by what the long call returns. Discarded: the cut landed inside it, and must have
            // returned at once. Done: the call ended before the cut, which proves nothing, so the next try cuts
            // sooner (half the delay). Anything else fails. At least one try must land inside the call.
            var delay = length / 3
            var landed = false
            for _ in 0..<6 where !landed {
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
                usleep(useconds_t(delay * 1_000))
                let start = DispatchTime.now().uptimeNanoseconds
                let reply = cut()
                let took = millisSince(start)
                finished.wait()
                XCTAssertTrue(isDone(reply), "\(what): done")
                // Every cut returns at once, landed or not: one that waited for the long call's lock lets the call
                // end first, so its try looks inconclusive, and only this names the wait.
                XCTAssertLessThan(took * 2, length, "\(what) took \(took) ms, the long call \(length) ms: it waited")
                switch handed.reply {
                case .discarded?:
                    landed = true
                case .done?:
                    delay /= 2
                default:
                    XCTFail("\(what): the long call returned neither discarded nor done")
                }
                XCTAssertTrue(Core.shared.replyBufferIsWiped(), "\(what): a reply buffer left unwiped")
                for entry in entries {
                    entry.wipe()
                }
                file.wipe()
                XCTAssertTrue(isDone(Core.shared.selfTest()), "\(what): the slot at home again")
            }
            XCTAssertTrue(landed, "\(what): no try landed inside the long call (baseline \(length) ms)")
        }
    }
}
