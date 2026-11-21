// Leaving the app on every screen of the walk (tasks/todo.md, M6 item D2), ported from :screens'
// LeavingTest.kt (Stage U's U2e; docs/mobile-apps.md, "Session lifetime"; Q57, Q75), over the real slot. On
// a Protected screen and during a long call, leaving discards at once, with the Left notice ("Working..."
// once its call's reply comes; the start-up self-test, which holds no session, back to First launch with
// nothing to say). On a Public screen the privacy cover goes up and the background time starts: 59 s away
// keeps everything, and the return keeps the cover until a tap, which only uncovers; 61 s away wipes what
// is held, with the Background notice, whether the timers ran while away or the app was suspended and the
// wipe comes at the return, before anything shows; a Public screen that holds nothing keeps its place. The
// words' states the walk's screens do not name are Protected, their privacy gates included (Q82). Every
// long call is discarded at once by a leave or by going online while it runs. On the iPhone, leaving is
// the scene going to the background (CaptureShield's scene phase). Each walk leaves the slot at home.

import XCTest

final class CeremonyLeavingTests: XCTestCase {
    override func setUpWithError() throws {
        try KcrVectors.load()
        assertLiveSlot()
    }

    override func tearDown() {
        assertSlotEmptied()
    }

    /// LeavingTest.kt's leavingAProtectedScreenOrALongCallDiscardsAtOnceAndAPublicOneIsCovered.
    func testLeavingAProtectedScreenOrALongCallDiscardsAtOnceAndAPublicOneIsCovered() {
        for screen in Walk.screens {
            let name = screen.id
            let rig = Walk.to(screen)
            let held = rig.model.held
            rig.model.appLeft()
            if screen == .selfTest {
                XCTAssertEqual(rig.screen, .selfTest, "\(name): until the self-test's reply")
                rig.worker.run()
                XCTAssertEqual(rig.screen, .firstLaunch, "\(name): the self-test left runs again from First launch")
                XCTAssertNil(rig.model.state.notice, "\(name): no session was held")
            } else if screen == .working {
                XCTAssertEqual(rig.screen, .working, "\(name): until the call's reply")
                rig.worker.run()
                rig.assertDiscarded(.left, name)
                XCTAssertTrue(isDone(Core.shared.selfTest()), "\(name): the call left something in core")
            } else if Walk.protected.contains(screen) {
                rig.assertDiscarded(.left, "\(name): leaving a Protected screen")
                rig.assertNothingSecretShown(name)
                XCTAssertTrue(isDone(Core.shared.selfTest()), "\(name): leaving left something in core")
            } else {
                let state = rig.model.state
                XCTAssertEqual(state.screen, screen, "\(name): leaving a Public screen")
                XCTAssertEqual(state.overlay, .cover, "\(name): the privacy cover")
                XCTAssertNil(state.notice, name)
                XCTAssertEqual(rig.model.held, held, "\(name): leaving a Public screen kept what is held")
            }
            assertSlotEmptied()
        }
    }

    /// LeavingTest.kt's leavingTheWordsStatesTheWalksScreensDoNotNameDiscardsAtOnce.
    func testLeavingTheWordsStatesTheWalksScreensDoNotNameDiscardsAtOnce() {
        for (what, reach) in Walk.states {
            let rig = reach()
            rig.model.appLeft()
            rig.assertDiscarded(.left, "\(what): leaving")
            rig.assertNothingSecretShown(what)
            XCTAssertTrue(isDone(Core.shared.selfTest()), "\(what): leaving left something in core")
            assertSlotEmptied()
        }
    }

    /// Each long call the model makes, started from where the model makes it and held on the worker
    /// (LeavingTest.kt's longCalls): its name, and a fresh Rig on its screen with the call waiting.
    private var longCalls: [(String, () -> Rig)] {
        [
            ("the start", { Walk.to(.working) }),
            ("the self-test", { Walk.to(.selfTest) }),
            ("the dice's Done", {
                let rig = Walk.to(.dice)
                rig.roll(99)
                rig.model.diceDone()
                return rig
            }),
            ("a scanned go-ahead QR's check", {
                let rig = Walk.to(.scan)
                rig.model.onGoAheadText(KcrVectors.proofUr("clear-empty-bucket"))
                return rig
            }),
            ("the backup's encryption", {
                let rig = Walk.to(.backupPassphrase)
                var words = rig.passphraseWords()
                rig.model.nextPage()
                words += rig.passphraseWords()
                rig.model.passphraseWritten()
                for _ in 0..<2 {
                    let state = rig.model.state
                    if let question = state.challenge?.questions[state.page] { rig.answer(words[question.position - 1]) }
                }
                return rig
            }),
            ("the saved backup's check", {
                let rig = Walk.to(.backupSave)
                rig.model.saveBackup(FakePickers())
                rig.model.backupPlaced(FakePlace())
                rig.model.appResumed()
                return rig
            }),
            ("a snapshot's read and load", {
                let rig = Walk.to(.home)
                let bytes = KcrVectors.snapshot(Walk.snapshotName)
                rig.model.loadSnapshot(FakePickers())
                rig.model.snapshotPicked(FakeFile(name: Walk.snapshotName + ".kcr", size: Int64(bytes.count), bytes: bytes))
                rig.model.appResumed()
                return rig
            }),
            ("a backup's read", {
                let rig = Walk.to(.home)
                let saved = SavedBackup.shared
                rig.model.checkBackup(FakePickers())
                rig.model.backupPicked(FakeFile(name: SavedBackup.name, size: Int64(saved.file.count), bytes: saved.file))
                rig.model.appResumed()
                return rig
            }),
            ("a backup's opening", {
                let rig = Walk.to(.backupCheckEntry)
                for word in SavedBackup.shared.passphrase {
                    rig.press(String(word.prefix(4)))
                    rig.model.entryTyped()
                }
                return rig
            }),
        ]
    }

    /// LeavingTest.kt's aLeaveOrGoingOnlineDuringEveryLongCallDiscardsIt.
    func testALeaveOrGoingOnlineDuringEveryLongCallDiscardsIt() {
        _ = SavedBackup.shared
        for (call, start) in longCalls {
            for online in [false, true] {
                let what = call + (online ? ", going online" : ", leaving")
                let rig = start()
                let busy = rig.screen
                XCTAssertTrue(busy.isWorking && rig.worker.waiting > 0, "\(what): the call waits behind its screen")
                if online {
                    rig.offline.set(false)
                } else {
                    rig.model.appLeft()
                }
                XCTAssertEqual(rig.screen, busy, "\(what): its screen until its reply")
                rig.worker.run()
                if busy == .selfTest {
                    XCTAssertEqual(rig.screen, online ? .goOffline : .firstLaunch, what)
                    XCTAssertNil(rig.model.state.notice, "\(what): no session was held")
                } else {
                    rig.assertDiscarded(online ? .offline : .left, what)
                    rig.assertNothingSecretShown(what)
                    XCTAssertNil(rig.model.state.loaded, "\(what): nothing loaded")
                }
                XCTAssertTrue(isDone(Core.shared.selfTest()), "\(what): the call left something in core")
                assertSlotEmptied()
            }
        }
    }

    /// LeavingTest.kt's sixtySecondsAwayFromAPublicScreenWipesWhatIsHeldAndFiftyNineKeepIt.
    func testSixtySecondsAwayFromAPublicScreenWipesWhatIsHeldAndFiftyNineKeepIt() {
        for screen in Walk.screens where !Walk.protected.contains(screen) && !screen.isWorking {
            let name = screen.id
            let kept = Walk.to(screen)
            let held = kept.model.held
            let page = kept.model.state.page
            kept.model.appLeft()
            kept.clock.now += Timers.backgroundMillis - 1_000
            kept.model.tick()
            kept.model.appReturned()
            XCTAssertEqual(kept.screen, screen, "\(name): 59 s away")
            XCTAssertEqual(kept.model.held, held, "\(name): 59 s away kept what is held")
            XCTAssertEqual(kept.model.state.overlay, .cover, "\(name): back within 60 s, the cover stays")
            kept.model.dismissOverlay()
            XCTAssertEqual(kept.screen, screen, "\(name): the tap only uncovers")
            XCTAssertNil(kept.model.state.overlay, "\(name): the tap uncovered")
            XCTAssertEqual(kept.model.state.page, page, name)
            assertSlotEmptied()

            for frozen in [false, true] {
                let what = name + (frozen ? ": 61 s away, suspended" : ": 61 s away")
                let away = Walk.to(screen)
                away.model.appLeft()
                away.clock.now += Timers.backgroundMillis + 1_000
                if !frozen { away.model.tick() }
                away.model.appReturned()
                if held {
                    away.assertDiscarded(.background, what)
                    away.assertNothingSecretShown(what)
                    XCTAssertTrue(isDone(Core.shared.selfTest()), "\(what): the wipe left something in core")
                } else {
                    XCTAssertEqual(away.screen, screen, "\(what): nothing held, nothing to wipe")
                    XCTAssertNil(away.model.state.notice, what)
                    XCTAssertFalse(away.model.held, what)
                }
                assertSlotEmptied()
            }
        }
    }
}
