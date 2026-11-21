// One walk to every screen but the stop screen (tasks/todo.md, M6 item D2), ported from :screens' Walk.kt
// (Stage U's U-3): a fresh Rig brought to the screen a test names, over the real slot, by the path the
// JVM walk takes (a Mixed seed of 24 words, so Device entropy, the commitment, the device swap and D are
// on it), each screen reached from the one before it on its branch and checked on arrival, its privacy
// gate with it. The branches are Walk.kt's: the check's screens from the check QR, the skipped check's
// result from Skip's confirm, the watch-only offer from the backup offer's Skip, the watch-only summary
// from the BIP39 question's No, D's offer from the registration's Skip, the checklist from D's Skip, and
// Check a backup, Load registry snapshot and About from Home. "Working..." is Length's start held on the
// worker; the start-up self-test's screen is First launch's Continue, held likewise. Check a backup opens
// SavedBackup.shared. Each picker's answer is followed by the app's resume, as on the device. In the
// shipping build (no registry key) Load registry snapshot's result is core's refusal, NoRegistryKey: the
// same screen.

import XCTest

enum Walk {
    /// Every screen the walk reaches: every screen but Stop, in the enum's order.
    static let screens: [Screen] = Screen.allCases.filter { $0 != .stop }

    /// The Protected screens, as docs/mobile-apps.md's "Session lifetime" lists them (the Pi's list):
    /// the every-screen tests take what they expect from this list, not from Screen's isProtected, which
    /// the walk's own test checks against it.
    static let protected: Set<Screen> = [
        .words, .wordsOverview, .readbackEntry, .readbackMismatch, .backupPassphrase, .backupConfirm, .bip39Entry,
        .backupCheckEntry, .revealD, .registerQr, .collisionReport, .watchAccountQr, .watchDescriptorQr,
    ]

    /// The screens the walk enters through a privacy gate: each Protected screen entered from a Public one.
    static let gated: Set<Screen> = [
        .collisionReport, .words, .backupPassphrase, .bip39Entry, .watchAccountQr, .registerQr, .revealD, .backupCheckEntry,
    ]

    /// How one screen is reached: from the screen before it on its branch (none for First launch), by go.
    private struct Step {
        let from: Screen?
        let go: (Rig) -> Void
    }

    /// kcr.json's snapshot Load registry snapshot's result shows.
    static let snapshotName = "with-dice-50"

    private static let steps: [Screen: Step] = [
        .firstLaunch: Step(from: nil) { _ in },
        .selfTest: Step(from: .firstLaunch) { $0.model.firstLaunchDone() },
        .goOffline: Step(from: .selfTest) { $0.worker.run() },
        .home: Step(from: .goOffline) { $0.model.startOffline() },
        .length: Step(from: .home) { $0.model.chooseMode(.mixed) },
        .working: Step(from: .length) { $0.model.chooseLength(.twentyFour) },
        .deviceEntropy: Step(from: .working) { $0.worker.run() },
        .commitment: Step(from: .deviceEntropy) { $0.model.deviceEntropyDone() },
        .dice: Step(from: .commitment) { $0.model.commitmentDone() },
        .checkPrompt: Step(from: .dice) { rig in
            rig.roll(99)
            rig.model.diceDone()
            rig.worker.run()
        },
        .skipConfirm: Step(from: .checkPrompt) { $0.model.skip() },
        .sealCard: Step(from: .checkPrompt) { $0.model.checkNow() },
        .checkQr: Step(from: .sealCard) { $0.model.showCheckQr() },
        .scan: Step(from: .checkQr) { $0.model.scanQr() },
        .codeEntry: Step(from: .checkQr) { $0.model.typeCode() },
        .matchFoundConfirm: Step(from: .checkQr) { $0.model.matchFound() },
        .cannotCheckConfirm: Step(from: .checkQr) { $0.model.cannotCheck() },
        .collision: Step(from: .matchFoundConfirm) { $0.model.matchFoundConfirmed() },
        .collisionReport: Step(from: .collision) { $0.model.showReport() },
        .checkResult: Step(from: .skipConfirm) { $0.model.skipConfirmed() },
        .words: Step(from: .checkResult) { $0.model.showWords() },
        .wordsOverview: Step(from: .words) { $0.model.toOverview() },
        .deviceSwap: Step(from: .wordsOverview) { rig in
            for _ in 0..<(insertsPerDevice / overviewWords) {
                rig.model.nextPage()
            }
        },
        .readbackEntry: Step(from: .deviceSwap) { rig in
            rig.model.swapDone()
            rig.model.passGate()
            rig.model.toInsertView()
            for _ in 0..<(insertsPerDevice - 1) {
                rig.model.nextPage()
            }
            rig.model.startReadback()
        },
        .readbackMismatch: Step(from: .readbackEntry) { rig in
            rig.press("zzzz")
            rig.model.readbackTyped()
        },
        .readbackDone: Step(from: .readbackEntry) { rig in
            for _ in 0..<(2 * insertsPerDevice) {
                rig.readBackShown()
                rig.model.readbackNext()
            }
        },
        .wallet: Step(from: .readbackDone) { $0.model.showSummary() },
        .backupOffer: Step(from: .wallet) { $0.model.summaryDone() },
        .backupPassphrase: Step(from: .backupOffer) { $0.model.makeBackup() },
        .backupConfirm: Step(from: .backupPassphrase) { rig in
            rig.model.nextPage()
            rig.model.passphraseWritten()
        },
        .backupSave: Step(from: .backupPassphrase) { rig in
            var words = rig.passphraseWords()
            rig.model.nextPage()
            words += rig.passphraseWords()
            rig.model.passphraseWritten()
            rig.confirm(words)
        },
        .backupVerified: Step(from: .backupSave) { rig in
            rig.model.saveBackup(FakePickers())
            rig.model.backupPlaced(FakePlace())
            rig.model.appResumed()
            rig.worker.run()
        },
        .watchOffer: Step(from: .backupOffer) { $0.model.skipBackup() },
        .bip39Ask: Step(from: .watchOffer) { $0.model.showWatchOnly() },
        .bip39Entry: Step(from: .bip39Ask) { $0.model.withBip39Passphrase() },
        .watchSummary: Step(from: .bip39Ask) { $0.model.noBip39Passphrase() },
        .watchAccountQr: Step(from: .watchSummary) { $0.model.watchSummaryDone() },
        .watchDescriptorQr: Step(from: .watchAccountQr) { $0.model.nextPage() },
        .registerOffer: Step(from: .watchDescriptorQr) { $0.model.watchDone() },
        .registerQr: Step(from: .registerOffer) { $0.model.showRegistration() },
        .revealDOffer: Step(from: .registerOffer) { $0.model.skipRegistration() },
        .revealD: Step(from: .revealDOffer) { $0.model.showDeviceLeg() },
        .checklist: Step(from: .revealDOffer) { $0.model.skipDeviceLeg() },
        .backupCheckEntry: Step(from: .home) { rig in
            let saved = SavedBackup.shared
            rig.model.checkBackup(FakePickers())
            rig.model.backupPicked(FakeFile(name: SavedBackup.name, size: Int64(saved.file.count), bytes: saved.file))
            rig.model.appResumed()
            rig.worker.run()
        },
        .backupCheckResult: Step(from: .backupCheckEntry) { rig in
            for word in SavedBackup.shared.passphrase {
                rig.press(String(word.prefix(4)))
                rig.model.entryTyped()
            }
            rig.worker.run()
        },
        .backupRecheck: Step(from: .backupCheckResult) { $0.model.showRecheck() },
        .snapshot: Step(from: .home) { rig in
            let bytes = KcrVectors.snapshot(snapshotName)
            rig.model.loadSnapshot(FakePickers())
            rig.model.snapshotPicked(FakeFile(name: snapshotName + ".kcr", size: Int64(bytes.count), bytes: bytes))
            rig.model.appResumed()
            rig.worker.run()
        },
        .about: Step(from: .home) { $0.model.about() },
    ]

    /// States of the words' screens the walk's screens do not name, each a fresh Rig in that state
    /// (Stage U's U2b2): the second privacy gate a 24-word seed's device swap leads to; Check a backup's
    /// words on their gate and past it; and an insert reviewed from a read-back mismatch. All Protected.
    static let states: [(String, () -> Rig)] = [
        ("the device swap's second gate", {
            let rig = to(.deviceSwap)
            rig.model.swapDone()
            XCTAssertTrue(rig.screen == .wordsOverview && rig.model.state.gate, "the second gate did not show")
            return rig
        }),
        ("Check a backup's words on their gate", { checkedWords(gate: true) }),
        ("Check a backup's words", { checkedWords(gate: false) }),
        ("an insert reviewed from a mismatch", {
            let rig = to(.readbackMismatch)
            rig.model.reviewInsert()
            XCTAssertTrue(rig.screen == .words && rig.model.state.reviewing, "the insert was not reviewed")
            return rig
        }),
    ]

    /// Check a backup's words, insert 1, on their privacy gate or past it.
    private static func checkedWords(gate: Bool) -> Rig {
        let rig = to(.backupCheckResult)
        rig.model.showBackupWords()
        let state = rig.model.state
        XCTAssertTrue(state.screen == .words && state.opened != nil && state.gate, "Check a backup's words did not show their gate")
        if !gate { rig.model.passGate() }
        return rig
    }

    /// A fresh Rig on screen (any but Stop), over core (Core itself, or a stand-in over it), its long calls
    /// run but "Working..."'s and the self-test's own: past the privacy gate, or on it when gate (a screen of gated). Every screen on the way is checked as
    /// it shows, its gate with it (shown on gated's alone), and passed through its gate.
    static func to(_ screen: Screen, gate: Bool = false, core: CeremonyCore = Core.shared, file: StaticString = #filePath, line: UInt = #line) -> Rig {
        XCTAssertNotEqual(screen, .stop, "the stop screen is the halt tests' alone", file: file, line: line)
        XCTAssertTrue(!gate || gated.contains(screen), "\(screen.id) is entered with no privacy gate", file: file, line: line)
        if path(screen).contains(.backupCheckEntry) { _ = SavedBackup.shared }
        let rig = reach(screen, core)
        let shown = rig.model.state.gate
        XCTAssertEqual(shown, gated.contains(screen), "\(screen.id): " + (shown ? "a privacy gate showed" : "its privacy gate did not show"), file: file, line: line)
        if !gate, shown { rig.model.passGate() }
        return rig
    }

    /// The screens from First launch to screen on its branch, screen last.
    static func path(_ screen: Screen) -> [Screen] {
        guard let before = steps[screen]?.from else { return [screen] }
        return path(before) + [screen]
    }

    /// A fresh Rig on screen, by its branch, each screen checked as it shows and passed through its gate.
    private static func reach(_ screen: Screen, _ core: CeremonyCore) -> Rig {
        guard let step = steps[screen] else {
            XCTFail("no step reaches \(screen.id)")
            return Rig(core: core)
        }
        let rig = step.from.map { to($0, core: core) } ?? Rig(core: core).startUp()
        step.go(rig)
        XCTAssertEqual(rig.screen, screen, "the walk to \(screen.id) reached \(rig.screen.id)")
        return rig
    }
}
