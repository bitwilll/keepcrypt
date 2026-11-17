// The app's screens over its ceremony model (tasks/todo.md, M6 item D3; Android's Screens.kt): the screen is
// a switch over the model's state. Every touch first reaches the model (input, the idle timer; touched,
// which Device entropy mixes in), and then reaches the screen's controls only if the press guard admits it
// (PressGuard.swift: a new screen, gate or overlay takes no touch until 300 ms after it was shown, judged by
// the touch's own time; M5-79): each view is reported to the guard as it is shown, and D3b's recognizer
// on the window judges each touch. The cover and the warning lie over the screen and take the tap that
// removes them, and while either is up the screen under it is hidden from VoiceOver (Q80 (a)). Each state's
// pane title (paneTitle(of:), fixed text) is posted to VoiceOver as it opens (U3g). Screens past the dice
// draw their title alone until D4-D7 draw them.

import SwiftUI
import UIKit

struct Screens: View {
    @ObservedObject var model: CeremonyModel
    let pressGuard: PressGuard

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
        .background(KitColors.background.ignoresSafeArea())
        .onChange(of: shownView(state), initial: true) { _, view in
            pressGuard.composed(view, uptimeMillis())
            UIAccessibility.post(notification: .screenChanged, argument: paneTitle(of: model.state))
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
                onNewSeed: { model.chooseMode(.mixed) }, onDiceOnly: { model.chooseMode(.diceOnly) })
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
        case .working:
            WorkingScreen(testRegistry: registry)
        case .stop:
            StopScreen(state: state, testRegistry: registry)
        default:
            KitScreen(state.screen.id, testRegistry: registry) {
                Heading(state.screen.title)
            }
        }
    }
}

/// The phone's uptime in milliseconds: the clock UIKit stamps every touch with (ProcessInfo's system
/// uptime), on which the press guard judges a touch against the time its view was shown.
func uptimeMillis() -> Int64 {
    Int64(ProcessInfo.processInfo.systemUptime * 1_000)
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
                .accessibilityAddTraits(.isHeader)
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
        .onTapGesture(perform: dismiss)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
        .accessibilityAction { dismiss() }
        .accessibilityIdentifier(overlay == .cover ? "cover" : "idle_warning")
    }
}
