// The idle rules on every screen of the walk and the 99-roll minimum through every restart path
// (tasks/todo.md, M6 item D2), ported from :screens' IdleTest.kt (Stage U's U2f; docs/pi-firmware.md,
// "Protected screens and idle"), over the real slot and the fake clock. 30 s without input covers a
// Protected screen alone, and a tap only uncovers it; 9 minutes bring the warning on any screen while
// something is held, and a tap keeps everything; 10 minutes wipe what is held, with the Idle notice, and a
// loaded snapshot survives; where nothing is held nothing comes, and during a long call the timers wait.
// After a collision the next ceremony needs 99 rolls however the slot gets back to a start. On each privacy
// gate and in the words' states the walk's screens do not name, the cover comes at 30 s and the wipe at 10
// minutes. Reading (a VoiceOver focus, Q80 (b)) is input. Each walk leaves the slot at home.

import XCTest

final class CeremonyIdleTests: XCTestCase {
    override func setUpWithError() throws {
        try KcrVectors.load()
        assertLiveSlot()
    }

    override func tearDown() {
        assertSlotEmptied()
    }

    /// The timers' step after ms more without input.
    private func idle(_ rig: Rig, _ ms: Int64) {
        rig.clock.now += ms
        rig.model.tick()
    }

    /// IdleTest.kt's theCoverTheWarningAndTheWipeOnEveryScreen.
    func testTheCoverTheWarningAndTheWipeOnEveryScreen() {
        for screen in Walk.screens {
            let name = screen.id
            let rig = Walk.to(screen)
            let held = rig.model.held
            if screen.isWorking {
                idle(rig, Timers.wipeMillis)
                XCTAssertEqual(rig.screen, screen, "\(name): the timers wait during a long call")
                XCTAssertNil(rig.model.state.overlay, name)
                assertSlotEmptied()
                continue
            }
            idle(rig, Timers.coverMillis - 1)
            XCTAssertNil(rig.model.state.overlay, "\(name): 29.999 s")
            idle(rig, 1)
            if Walk.protected.contains(screen) {
                XCTAssertEqual(rig.model.state.overlay, .cover, "\(name): 30 s on a Protected screen")
                rig.model.dismissOverlay()
                XCTAssertNil(rig.model.state.overlay, "\(name): the tap uncovered")
            } else {
                XCTAssertNil(rig.model.state.overlay, "\(name): 30 s on a Public screen")
                rig.model.input()
            }
            XCTAssertEqual(rig.screen, screen, name)
            XCTAssertEqual(rig.model.held, held, "\(name): the cover kept what is held")
            idle(rig, Timers.warnMillis - 1)
            XCTAssertNotEqual(rig.model.state.overlay, .warning, "\(name): 8 minutes 59.999 s warned")
            idle(rig, 1)
            if held {
                XCTAssertEqual(rig.model.state.overlay, .warning, "\(name): 9 minutes, something held")
                rig.model.dismissOverlay()
                XCTAssertNil(rig.model.state.overlay, "\(name): the tap took the warning away")
                XCTAssertEqual(rig.screen, screen, name)
                XCTAssertTrue(rig.model.held, "\(name): the tap kept everything")
            } else {
                XCTAssertNil(rig.model.state.overlay, "\(name): 9 minutes, nothing held")
            }
            idle(rig, Timers.wipeMillis)
            if held {
                rig.assertDiscarded(.idle, "\(name): 10 minutes")
                rig.assertNothingSecretShown(name)
                XCTAssertTrue(isDone(Core.shared.selfTest()), "\(name): the idle wipe left something in core")
            } else {
                XCTAssertEqual(rig.screen, screen, "\(name): 10 minutes, nothing held, nothing wiped")
                XCTAssertNil(rig.model.state.notice, name)
            }
            assertSlotEmptied()
        }
    }

    /// IdleTest.kt's theCoverAndTheWipeOnEachGateAndInTheWordsStates.
    func testTheCoverAndTheWipeOnEachGateAndInTheWordsStates() {
        let gates: [(String, () -> Rig)] = Walk.gated.sorted { $0.rawValue < $1.rawValue }.map { screen in
            ("\(screen.id) on its gate", { Walk.to(screen, gate: true) })
        }
        for (what, reach) in gates + Walk.states {
            let rig = reach()
            let before = rig.model.state
            idle(rig, Timers.coverMillis)
            XCTAssertEqual(rig.model.state.overlay, .cover, "\(what): 30 s")
            XCTAssertEqual(rig.model.state.gate, before.gate, what)
            idle(rig, Timers.wipeMillis - Timers.coverMillis)
            rig.assertDiscarded(.idle, "\(what): 10 minutes")
            rig.assertNothingSecretShown(what)
            XCTAssertTrue(isDone(Core.shared.selfTest()), "\(what): the idle wipe left something in core")
            assertSlotEmptied()
        }
    }

    /// IdleTest.kt's readingRestartsTheIdleTimeTakesNoCoverAwayAndEndsTheWarning.
    func testReadingRestartsTheIdleTimeTakesNoCoverAwayAndEndsTheWarning() {
        let rig = Walk.to(.words)
        idle(rig, Timers.coverMillis - 1)
        rig.model.reading()
        idle(rig, Timers.coverMillis - 1)
        XCTAssertNil(rig.model.state.overlay, "29.999 s after a reading")
        idle(rig, 1)
        XCTAssertEqual(rig.model.state.overlay, .cover, "30 s after a reading")
        rig.model.reading()
        XCTAssertEqual(rig.model.state.overlay, .cover, "a reading took the cover away")
        idle(rig, Timers.warnMillis - 1)
        XCTAssertEqual(rig.model.state.overlay, .cover, "8 minutes 59.999 s after a reading under the cover")
        idle(rig, 1)
        XCTAssertEqual(rig.model.state.overlay, .warning, "9 minutes after a reading under the cover")
        rig.model.reading()
        XCTAssertEqual(rig.model.state.overlay, .cover, "a reading under the warning on a Protected screen: the cover")
        XCTAssertEqual(rig.screen, .words, "a reading under the warning")
        XCTAssertTrue(rig.model.held, "a reading under the warning kept everything")
        idle(rig, Timers.warnMillis - 1)
        XCTAssertEqual(rig.model.state.overlay, .cover, "8 minutes 59.999 s after a reading under the warning")
        idle(rig, 1)
        XCTAssertEqual(rig.model.state.overlay, .warning, "9 minutes after a reading under the warning")
        idle(rig, Timers.wipeMillis - Timers.warnMillis - 1)
        XCTAssertEqual(rig.screen, .words, "9 minutes 59.999 s after a reading under the warning")
        idle(rig, 1)
        rig.assertDiscarded(.idle, "10 minutes after a reading under the warning")
        XCTAssertTrue(isDone(Core.shared.selfTest()), "the idle wipe left something in core")
        assertSlotEmptied()
        let dice = Walk.to(.dice)
        XCTAssertTrue(dice.model.held, "the dice hold a session")
        idle(dice, Timers.warnMillis)
        XCTAssertEqual(dice.model.state.overlay, .warning, "9 minutes on the dice")
        dice.model.reading()
        XCTAssertNil(dice.model.state.overlay, "a reading under the warning on a Public screen: the screen")
        XCTAssertEqual(dice.screen, .dice)
        XCTAssertTrue(dice.model.held, "a reading under the warning on the dice kept everything")
        idle(dice, Timers.warnMillis - 1)
        XCTAssertNil(dice.model.state.overlay, "8 minutes 59.999 s after a reading on the dice")
        idle(dice, 1)
        XCTAssertEqual(dice.model.state.overlay, .warning, "9 minutes after a reading on the dice")
    }

    /// IdleTest.kt's aLoadedSnapshotSurvivesTheIdleWipe (the test-registry build, whose key verifies
    /// the snapshot; the shipping build refuses it, NoRegistryKey, which the walk's step shows).
    func testALoadedSnapshotSurvivesTheIdleWipe() throws {
        #if KC_WITH_TEST_REGISTRY
        let rig = Walk.to(.snapshot)
        let loaded = try XCTUnwrap(rig.model.state.loaded)
        rig.model.snapshotDone()
        rig.begin(.diceOnly, .twelve)
        idle(rig, Timers.wipeMillis)
        rig.assertDiscarded(.idle, "10 minutes on the dice")
        XCTAssertEqual(rig.model.state.loaded, loaded, "the snapshot the idle wipe left")
        // And core still holds it: the next seed's Check now runs against it on its own. The snapshot
        // registers the seal of 50 rolls of the faces 1 to 6 in turn (dice-50-words12), Rig.roll's.
        rig.begin(.diceOnly, .twelve)
        rig.roll(50)
        rig.model.diceDone()
        rig.worker.run()
        rig.model.checkNow()
        XCTAssertEqual(rig.screen, .collision, "the next check ran against the snapshot core kept")
        XCTAssertNotNil(rig.model.state.registry, "the collision was found by the snapshot")
        #else
        let rig = Walk.to(.snapshot)
        XCTAssertEqual(rig.model.state.snapshotRefusal, .noRegistryKey, "the shipping build trusts no registry key")
        XCTAssertNil(rig.model.state.loaded)
        #endif
    }

    /// From a discard's start screen, offline (Go offline's Start where the phone went online): a new
    /// dice-only seed of 12 words; the dice's minimum.
    private func nextMinimum(_ rig: Rig, _ what: String) -> Int? {
        rig.offline.set(true)
        rig.model.appReturned()
        rig.model.dismissOverlay()
        if rig.screen == .goOffline { rig.model.startOffline() }
        XCTAssertEqual(rig.screen, .home, what)
        rig.begin(.diceOnly, .twelve)
        XCTAssertEqual(rig.screen, .dice, what)
        return rig.model.state.dice?.minimum
    }

    /// IdleTest.kt's the99RollMinimumAfterACollisionOutlivesEveryRestartPath.
    func testThe99RollMinimumAfterACollisionOutlivesEveryRestartPath() {
        let control = Walk.to(.home)
        control.begin(.diceOnly, .twelve)
        XCTAssertEqual(control.model.state.dice?.minimum, 50, "12 words with no collision before")
        assertSlotEmptied()

        let discards: [(String, Notice, (Rig) -> Void)] = [
            ("leaving the report", .left, { rig in
                rig.model.showReport()
                rig.model.passGate()
                rig.model.appLeft()
            }),
            ("going online", .offline, { rig in rig.offline.set(false) }),
            ("60 s away", .background, { rig in
                rig.model.appLeft()
                rig.clock.now += Timers.backgroundMillis
                rig.model.tick()
            }),
            ("the idle wipe", .idle, { [self] rig in idle(rig, Timers.wipeMillis) }),
        ]
        for (what, notice, discard) in discards {
            let rig = Walk.to(.collision)
            discard(rig)
            rig.assertDiscarded(notice, "\(what) after the collision")
            XCTAssertEqual(nextMinimum(rig, what), 99, "\(what) after the collision, then a new seed")
            assertSlotEmptied()
        }

        let restarted = Walk.to(.collisionReport)
        restarted.model.addFreshEntropy()
        restarted.worker.run()
        restarted.offline.set(false)
        XCTAssertEqual(nextMinimum(restarted, "the restart discarded"), 99, "the restarted ceremony discarded, then a new seed")
    }
}
