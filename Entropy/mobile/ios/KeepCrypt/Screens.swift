// The app's screens over its ceremony model (tasks/todo.md, M6 item D3; Android's Screens.kt): the screen is
// a switch over the model's state. Every touch first reaches the model (input, the idle timer; touched,
// which Device entropy mixes in), and then reaches the screen's controls only if the press guard admits it
// (PressGuard.swift: a new screen, gate or overlay takes no touch until 300 ms after it was shown, judged by
// the touch's own time; M5-79): TouchGuard below, a gesture recognizer on the window that cancels a refused
// touch before any control gets it. The cover and the warning lie over the screen and take the tap that
// removes them, and while either is up the screen under it is hidden from VoiceOver (Q80 (a)). Each state's
// pane title (paneTitle(of:), fixed text) is posted to VoiceOver as it opens (U3g). The scan screen's scanner
// and the document pickers are the platform's seams (GoAheadScanner.swift, DocumentPicker.swift: the
// open picker, shared by Check a backup and Load registry snapshot, and the backup's exporter). D7 draws the
// last of them: Check a backup's, About.

import SwiftUI
import UIKit
import UIKit.UIGestureRecognizerSubclass

struct Screens: View {
    @ObservedObject var model: CeremonyModel
    let pressGuard: PressGuard
    let scanner: QrScanner
    @ObservedObject var pickers: ScreenPickers
    /// The pickers the model's entry points open: pickers itself, or in the TestHooks build its hooked
    /// stand-in for Check a backup (TestHooks.swift).
    let documents: DocumentPickers

    var body: some View {
        let state = model.state
        let registry = model.testRegistry
        ZStack {
            VStack(spacing: 0) {
                if let notice = state.notice, !state.screen.isWorking, state.screen != .stop {
                    NoticeBar(text: noticeLine(notice))
                }
                screen(state, registry)
            }
            .accessibilityHidden(state.overlay != nil)
            if let overlay = state.overlay {
                OverlayScreen(overlay: overlay, testRegistry: registry) { model.dismissOverlay() }
            }
        }
        .environment(\.pressGate, PressGate { action in
            // M6-23: the action runs only if the touch that made it was admitted (PressGuard.swift's permits).
            MainActor.assumeIsolated {
                if pressGuard.permits(shownView(model.state), uptimeMillis()) {
                    action()
                } else {
                    #if KC_TEST_HOOKS
                    TestHooks.shared.notePressDropped()
                    #endif
                }
            }
        })
        .background(KitColors.background.ignoresSafeArea())
        .background(TouchGuard(model: model, pressGuard: pressGuard))
        .fileImporter(
            isPresented: $pickers.importerUp, allowedContentTypes: [.data], allowsMultipleSelection: false,
            onCompletion: { result in
                switch result {
                case .success(let urls):
                    picked(urls.first.map(PickedURLFile.init))
                case .failure:
                    picked(nil)
                }
            },
            onCancellation: { picked(nil) })
        .modifier(BackupExporter(pickers: pickers, placed: model.backupPlaced))
        .onChange(of: shownView(state), initial: true) { _, view in
            pressGuard.composed(view, uptimeMillis())
            UIAccessibility.post(notification: .screenChanged, argument: paneTitle(of: model.state))
        }
    }

    /// The open picker's answer, to the model's entry for what it was opened for.
    private func picked(_ file: PickedFile?) {
        switch pickers.opening {
        case .backup: model.backupPicked(file)
        case .snapshot: model.snapshotPicked(file)
        }
    }

    @ViewBuilder
    private func screen(_ state: UiState, _ registry: Bool) -> some View {
        switch state.screen {
        case .firstLaunch:
            FirstLaunchScreen(testRegistry: registry, onContinue: model.firstLaunchDone)
        case .selfTest:
            SelfTestScreen(testRegistry: registry)
        case .goOffline:
            GoOfflineScreen(state: state, testRegistry: registry, onStart: model.startOffline)
        case .home:
            HomeScreen(
                state: state, testRegistry: registry,
                onNewSeed: { model.chooseMode(.mixed) }, onDiceOnly: { model.chooseMode(.diceOnly) },
                onCheckBackup: { model.checkBackup(documents) }, onLoadSnapshot: { model.loadSnapshot(documents) },
                onAbout: model.about)
        case .length:
            LengthScreen(testRegistry: registry, onWords: model.chooseLength)
        case .deviceEntropy:
            DeviceEntropyScreen(testRegistry: registry, onContinue: model.deviceEntropyDone)
        case .commitment:
            CommitmentScreen(state: state, testRegistry: registry, onContinue: model.commitmentDone)
        case .dice:
            DiceScreen(
                state: state, pick: model.dicePick, testRegistry: registry,
                onKey: { model.padKey(screen: .dice, page: state.page, key: $0) },
                onConfirm: model.confirmRoll, onUndo: model.undoRoll, onDone: model.diceDone)
        case .checkPrompt:
            CheckPromptScreen(testRegistry: registry, onCheckNow: model.checkNow, onSkip: model.skip)
        case .skipConfirm:
            OneWayConfirm(
                id: Screen.skipConfirm.id, testRegistry: registry, question: Screen.skipConfirm.title,
                consequence: CheckTexts.skipConfirm, action: CheckTexts.skipAction, onAction: model.skipConfirmed,
                onBack: model.back)
        case .sealCard:
            SealCardScreen(state: state, testRegistry: registry, onShowCheckQr: model.showCheckQr)
        case .checkQr:
            CheckQrScreen(
                state: state, testRegistry: registry, onScan: model.scanQr, onTypeCode: model.typeCode,
                onMatchFound: model.matchFound, onCannotCheck: model.cannotCheck)
        case .scan:
            ScanScreen(
                state: state, scanner: scanner, testRegistry: registry, onText: model.onGoAheadText,
                onStopped: model.scanStopped, onTypeCode: model.typeCode, onBack: model.back)
        case .codeEntry:
            CodeEntryScreen(
                state: state, code: model.goAheadCode, testRegistry: registry,
                onKey: { model.padKey(screen: .codeEntry, page: state.page, key: $0) },
                onDelete: { model.padDelete(screen: .codeEntry, page: state.page) }, onDone: model.codeDone,
                onBack: model.back)
        case .matchFoundConfirm:
            OneWayConfirm(
                id: Screen.matchFoundConfirm.id, testRegistry: registry, question: Screen.matchFoundConfirm.title,
                consequence: CheckTexts.matchFoundConsequence, action: CheckTexts.destroy,
                onAction: model.matchFoundConfirmed, onBack: model.back)
        case .cannotCheckConfirm:
            OneWayConfirm(
                id: Screen.cannotCheckConfirm.id, testRegistry: registry, question: Screen.cannotCheckConfirm.title,
                consequence: CheckTexts.cannotCheckConsequence, action: CheckTexts.startAgain,
                onAction: model.cannotCheckConfirmed, onBack: model.back)
        case .collision:
            CollisionScreen(state: state, testRegistry: registry, onShowReport: model.showReport)
        case .collisionReport:
            CollisionReportScreen(
                state: state, testRegistry: registry, passGate: model.passGate, onAddFreshEntropy: model.addFreshEntropy)
        case .checkResult:
            CheckResultScreen(state: state, testRegistry: registry, onShowWords: model.showWords)
        case .words:
            WordsInsertScreen(
                state: state, testRegistry: registry, passGate: model.passGate, onPrevious: model.previousPage,
                onNext: model.nextPage, onOverview: model.toOverview, onReadback: model.startReadback,
                onBackToReadback: model.backToReadback, onBackupDone: model.backupWordsDone)
        case .wordsOverview:
            WordsOverviewScreen(
                state: state, testRegistry: registry, passGate: model.passGate, onPrevious: model.previousPage,
                onNext: model.nextPage, onInsertView: model.toInsertView)
        case .deviceSwap:
            DeviceSwapScreen(testRegistry: registry, onContinue: model.swapDone)
        case .readbackEntry:
            ReadbackEntryScreen(
                state: state, letters: model.readbackLetters, testRegistry: registry, passGate: model.passGate,
                onKey: { model.padKey(screen: .readbackEntry, page: state.page, key: $0) },
                onDelete: { model.padDelete(screen: .readbackEntry, page: state.page) }, onDone: model.readbackTyped,
                onNext: model.readbackNext)
        case .readbackMismatch:
            ReadbackMismatchScreen(
                state: state, testRegistry: registry, passGate: model.passGate, onAgain: model.readbackAgain,
                onShowInsert: model.reviewInsert)
        case .readbackDone:
            ReadbackDoneScreen(testRegistry: registry, onNext: model.showSummary)
        case .wallet:
            WalletSummaryScreen(state: state, testRegistry: registry, onNext: model.summaryDone)
        case .backupOffer:
            BackupOfferScreen(testRegistry: registry, onMake: model.makeBackup, onSkip: model.skipBackup)
        case .backupPassphrase:
            BackupPassphraseScreen(
                state: state, testRegistry: registry, passGate: model.passGate, onPrevious: model.previousPage,
                onNext: model.nextPage, onConfirm: model.passphraseWritten)
        case .backupConfirm:
            BackupConfirmScreen(
                state: state, letters: model.backupLetters, testRegistry: registry, passGate: model.passGate,
                onKey: { model.padKey(screen: .backupConfirm, page: state.page, key: $0) },
                onDelete: { model.padDelete(screen: .backupConfirm, page: state.page) }, onDone: model.confirmTyped)
        case .backupSave:
            BackupSaveScreen(
                state: state, testRegistry: registry, onSave: { model.saveBackup(documents) }, onSkip: model.skipBackup)
        case .backupVerified:
            BackupVerifiedScreen(testRegistry: registry, onNext: model.backupVerifiedDone)
        case .watchOffer:
            WatchOfferScreen(testRegistry: registry, onShow: model.showWatchOnly, onSkip: model.skipWatchOnly)
        case .bip39Ask:
            Bip39AskScreen(testRegistry: registry, onNone: model.noBip39Passphrase, onPassphrase: model.withBip39Passphrase)
        case .bip39Entry:
            Bip39EntryScreen(
                state: state, letters: model.bip39Letters, testRegistry: registry, passGate: model.passGate,
                onKey: { model.padKey(screen: .bip39Entry, page: state.page, key: $0) },
                onPreviousKeys: model.previousPage, onNextKeys: model.nextPage,
                onDelete: { model.padDelete(screen: .bip39Entry, page: state.page) }, onDone: model.bip39Typed,
                onBack: model.back)
        case .watchSummary:
            WatchSummaryScreen(state: state, testRegistry: registry, onNext: model.watchSummaryDone)
        case .watchAccountQr:
            WatchAccountQrScreen(state: state, testRegistry: registry, passGate: model.passGate, onNext: model.nextPage)
        case .watchDescriptorQr:
            WatchDescriptorQrScreen(
                state: state, testRegistry: registry, passGate: model.passGate, onPrevious: model.previousPage,
                onDone: model.watchDone)
        case .registerOffer:
            RegisterOfferScreen(testRegistry: registry, onShow: model.showRegistration, onSkip: model.skipRegistration)
        case .registerQr:
            RegisterQrScreen(state: state, testRegistry: registry, passGate: model.passGate, onNext: model.registrationDone)
        case .revealDOffer:
            RevealDOfferScreen(testRegistry: registry, onShow: model.showDeviceLeg, onSkip: model.skipDeviceLeg)
        case .revealD:
            RevealDScreen(state: state, testRegistry: registry, passGate: model.passGate, onNext: model.deviceLegDone)
        case .checklist:
            ChecklistScreen(state: state, testRegistry: registry, onFinish: model.finishCeremony)
        case .backupCheckEntry:
            BackupCheckEntryScreen(
                state: state, letters: model.backupLetters, testRegistry: registry, passGate: model.passGate,
                onKey: { model.padKey(screen: .backupCheckEntry, page: state.page, key: $0) },
                onDelete: { model.padDelete(screen: .backupCheckEntry, page: state.page) }, onDone: model.entryTyped,
                onBack: model.back)
        case .backupCheckResult:
            BackupCheckResultScreen(
                state: state, testRegistry: registry, onShowWords: model.showBackupWords, onRecheck: model.showRecheck,
                onDone: model.closeBackup)
        case .backupRecheck:
            BackupRecheckScreen(state: state, testRegistry: registry, onBack: model.back)
        case .about:
            AboutScreen(testRegistry: registry, onBack: model.back)
        case .snapshot:
            SnapshotScreen(state: state, testRegistry: registry, onDone: model.snapshotDone)
        case .working:
            WorkingScreen(testRegistry: registry)
        case .stop:
            StopScreen(state: state, testRegistry: registry)
        }
    }
}

/// The phone's uptime in milliseconds: the clock UIKit stamps every touch with (ProcessInfo's system
/// uptime), on which the press guard judges a touch against the time its view was shown.
func uptimeMillis() -> Int64 {
    Int64(ProcessInfo.processInfo.systemUptime * 1_000)
}

/// The Protected wrapper (Android's Protected): a Protected screen's content shows only past the privacy
/// gate, and never while a recording of the screen is reported (the capture cover, CaptureShield's, covers
/// the whole scene then too). Its 30 s cover is the timers', drawn over every screen by Screens.
struct Protected<Content: View>: View {
    let state: UiState
    let testRegistry: Bool
    let passGate: () -> Void
    let content: Content

    init(state: UiState, testRegistry: Bool, passGate: @escaping () -> Void, @ViewBuilder content: () -> Content) {
        self.state = state
        self.testRegistry = testRegistry
        self.passGate = passGate
        self.content = content()
    }

    var body: some View {
        if state.gate {
            PrivacyGate(
                testRegistry: testRegistry, pass: passGate, words: state.screen == .words || state.screen == .wordsOverview)
        } else if state.recording {
            KitScreen("redacted", testRegistry: testRegistry) {
                KitText(ShellTexts.redacted)
            }
        } else {
            content
        }
    }
}

/// The privacy gate before a Protected screen (docs/mobile-apps.md, "Session lifetime"; Android's
/// PrivacyGate): every Protected screen is entered through "I'm alone, show words", and the gate is part of
/// that screen (Q82). Every gate warns to use headphones if a screen reader speaks the next screen (Q83);
/// before the words it also gives the SeedBook's safety rules.
struct PrivacyGate: View {
    let testRegistry: Bool
    let pass: () -> Void
    var words = false

    var body: some View {
        KitScreen("privacy_gate", testRegistry: testRegistry) {
            KitText(GateTexts.line)
            if words {
                KitText(GateTexts.seedBookRules, style: .small, id: "seedbook_rules")
            }
            KitText(GateTexts.headphones, style: .small, id: "headphones_warning")
        } actions: {
            KitButton(GateTexts.action, id: "pass_gate", action: pass)
        }
    }
}

/// "Working...": a long call runs; no input goes anywhere (the model ignores every tap).
struct WorkingScreen: View {
    let testRegistry: Bool

    var body: some View {
        VStack(spacing: 0) {
            if testRegistry {
                TestRegistryStrip()
            }
            Spacer()
            Text(ShellTexts.working)
                .font(KitType.heading)
                .foregroundColor(KitColors.text)
                .spoken(.heading)
                .frame(maxWidth: .infinity)
            Spacer()
        }
        .background(KitColors.background)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier(Screen.working.id)
    }
}

/// The stop screen (docs/mobile-apps.md, "When something fails"): red, fixed text naming the failure
/// (stopLine, the halt's reason), nothing held, and one action, "Close app", which ends the process; the
/// next start runs the self-test again.
struct StopScreen: View {
    let state: UiState
    let testRegistry: Bool

    var body: some View {
        KitScreen(Screen.stop.id, testRegistry: testRegistry, background: KitColors.stop) {
            Title(ShellTexts.stopped)
            Gap(16)
            KitText(stopLine(state.halt), id: "halt_reason")
            KitText(ShellTexts.stopNote)
        } actions: {
            KitButton(ShellTexts.closeApp, id: "close_app") {
                Ceremony.halt(.closed)
            }
        }
    }
}

/// An overlay over the screen (Android's OverlayScreen): the privacy cover (it hides the screen, and the
/// tap on it only takes it away) or the warning a minute before the idle wipe (the tap on it keeps
/// everything). It fills the window and takes the tap that removes it, anywhere on it, with its text centred
/// under the TEST REGISTRY strip in that build.
struct OverlayScreen: View {
    let overlay: Overlay
    let testRegistry: Bool
    let dismiss: () -> Void
    /// The tap and VoiceOver's action run through the press gate (Kit.swift, M6-23).
    @Environment(\.pressGate) private var pressGate

    var body: some View {
        VStack(spacing: 0) {
            if testRegistry {
                TestRegistryStrip()
            }
            Spacer()
            switch overlay {
            case .cover:
                Text(ShellTexts.coverLine)
                    .font(.system(size: 20))
                    .foregroundColor(KitColors.text)
                    .multilineTextAlignment(.center)
                    .padding(24)
            case .warning:
                Text(ShellTexts.warningLine)
                    .font(.system(size: 20))
                    .foregroundColor(KitColors.warning)
                    .multilineTextAlignment(.center)
                    .padding(24)
            }
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(KitColors.background.ignoresSafeArea())
        .contentShape(Rectangle())
        .onTapGesture { pressGate(dismiss) }
        .accessibilityElement(children: .combine)
        .spoken(.overlay)
        .accessibilityAction { pressGate(dismiss) }
        .accessibilityIdentifier(overlay == .cover ? "cover" : "idle_warning")
    }
}

/// The press guard's and the model's view of every touch (Android's root pointer handler): a view behind
/// the screens that puts a TouchGuardRecognizer on its window once it joins one.
private struct TouchGuard: UIViewRepresentable {
    let model: CeremonyModel
    let pressGuard: PressGuard

    func makeUIView(context: Context) -> TouchGuardView {
        TouchGuardView(model: model, pressGuard: pressGuard)
    }

    func updateUIView(_ view: TouchGuardView, context: Context) {}
}

final class TouchGuardView: UIView {
    private let recognizer: TouchGuardRecognizer

    init(model: CeremonyModel, pressGuard: PressGuard) {
        recognizer = TouchGuardRecognizer(model: model, pressGuard: pressGuard)
        super.init(frame: .zero)
        isUserInteractionEnabled = false
        isAccessibilityElement = false
        recognizer.area = self
    }

    required init?(coder: NSCoder) {
        nil
    }

    override func didMoveToWindow() {
        super.didMoveToWindow()
        recognizer.view?.removeGestureRecognizer(recognizer)
        window?.addGestureRecognizer(recognizer)
    }
}

/// Sees every touch that goes down in the window, before any control: inside the screens' area (not the
/// TestHooks panel's), each down is the model's input and, on Device entropy, its touched, with the
/// touch's own uptime; a touch the press guard refuses is taken here (the recognizer recognizes, which
/// cancels it in the views under it and fails their gestures), and one it admits goes on untouched (the
/// recognizer fails at once).
final class TouchGuardRecognizer: UIGestureRecognizer {
    private let model: CeremonyModel
    private let pressGuard: PressGuard
    /// The screens' area: touches outside it (the TestHooks panel) are neither input nor guarded.
    weak var area: UIView?

    init(model: CeremonyModel, pressGuard: PressGuard) {
        self.model = model
        self.pressGuard = pressGuard
        super.init(target: nil, action: nil)
        cancelsTouchesInView = true
        delaysTouchesBegan = false
        delaysTouchesEnded = false
    }

    override func touchesBegan(_ touches: Set<UITouch>, with event: UIEvent) {
        guard let area else {
            state = .failed
            return
        }
        var refused = false
        var downs = 0
        for touch in touches where area.bounds.contains(touch.location(in: area)) {
            let millis = Int64(touch.timestamp * 1_000)
            model.input()
            model.touched(uptimeMillis: millis)
            if !pressGuard.admits(shownView(model.state), millis) { refused = true }
            downs += 1
        }
        // The verdict the press gate asks again when a press's action comes (M6-23): iOS 26 runs a Button's
        // action for a touch this recognizer cancelled.
        if downs > 0 {
            pressGuard.noteDown(shownView(model.state), admitted: !refused)
        }
        #if KC_TEST_HOOKS
        let inArea = touches.filter { area.bounds.contains($0.location(in: area)) }
        let held = refused
        let uptime = inArea.first.map { Int64($0.timestamp * 1_000) } ?? 0
        MainActor.assumeIsolated { TestHooks.shared.noteTouches(inArea.count, refused: held, uptime: uptime) }
        #endif
        state = refused ? .recognized : .failed
    }
}
