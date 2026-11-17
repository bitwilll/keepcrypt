// The iPhone app (tasks/todo.md, M6 items C2, C3, C5 and D2; Q86): the CeremonyModel (Ceremony.swift) over
// its seams, inside the capture layers (CaptureShield.swift) and watched by the offline check
// (OfflineCheck.swift). Until D3 brings the ceremony's SwiftUI screens, the shell draws Stage C's: First
// launch's Continue, the start-up self-test (docs/mobile-apps.md, step 2), Go offline (step 3), Home and
// the stop screen, and any other screen by its title alone. The TestHooks build (C5, M6-5) draws the UI
// tests' hook panel over every screen.

import SwiftUI

@main
struct KeepCryptApp: App {
    @StateObject private var model: CeremonyModel
    private let offlineCheck: OfflineCheck

    init() {
        #if KC_WITH_TEST_REGISTRY
        let registry = true
        #else
        let registry = false
        #endif
        let model = CeremonyModel(
            core: Core.shared, worker: QueueWorker(), clock: SystemClock(), date: SystemDate(), motion: NoMotion(),
            testRegistry: registry)
        _model = StateObject(wrappedValue: model)
        offlineCheck = OfflineCheck { offline in
            model.pathReported(offline: offline)
        }
        offlineCheck.start()
        #if KC_TEST_HOOKS
        TestHooks.shared.offlineCheck = offlineCheck
        #endif
    }

    var body: some Scene {
        WindowGroup {
            CaptureShield(model: model) {
                StartView(model: model)
            }
        }
    }
}

/// The motion source until D3 brings Core Motion's (docs/mobile-apps.md, "Entropy sources on phones"):
/// no sample. Motion is an extra mixed in with no credit, so none changes no quota.
final class NoMotion: MotionSource {
    func start(_ report: @escaping (Secret) -> Void) {}

    func stop() {}
}

/// Stage C's screens, in fixed text only, over the model's state.
struct StartView: View {
    @ObservedObject var model: CeremonyModel

    var body: some View {
        VStack(spacing: 0) {
            #if KC_WITH_TEST_REGISTRY
            TestRegistryStrip()
            #endif
            Spacer()
            switch model.state.screen {
            case .firstLaunch:
                VStack(alignment: .leading, spacing: 16) {
                    Text("First launch")
                        .font(.title)
                        .accessibilityIdentifier("first_launch")
                    Button("Continue") {
                        model.firstLaunchDone()
                    }
                    .accessibilityIdentifier("continue")
                }
            case .selfTest:
                Text("Running the self-test")
                    .accessibilityIdentifier("self_test_running")
            case .stop:
                StopScreen(reason: model.state.halt)
            case .goOffline:
                GoOfflineScreen(model: model)
            case .home:
                Text("Home")
                    .font(.title)
                    .accessibilityIdentifier("home")
            default:
                Text(model.state.screen.title)
                    .font(.title)
            }
            if let notice = model.state.notice {
                Text(noticeLine(notice))
                    .padding(.top, 24)
                    .accessibilityIdentifier(noticeId(notice))
            }
            Spacer()
        }
        .padding()
        .textSelection(.disabled)
    }
}

/// The notice line's identifier, for the UI tests.
func noticeId(_ notice: Notice) -> String {
    switch notice {
    case .left: return "notice_left"
    case .offline: return "notice_offline"
    case .idle: return "notice_idle"
    case .background: return "notice_background"
    case .screenshot: return "notice_screenshot"
    }
}

/// Go offline (docs/mobile-apps.md, step 3): the network state, and Start only while no path is usable.
struct GoOfflineScreen: View {
    @ObservedObject var model: CeremonyModel

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Self-test passed")
                .accessibilityIdentifier("self_test_passed")
            Text("Go offline")
                .font(.title)
            Text(model.state.offline
                 ? "No usable network path: the phone is offline."
                 : "A network path is usable: turn on airplane mode and turn off Wi-Fi.")
                .accessibilityIdentifier("network_state")
            Button("Start") {
                model.startOffline()
            }
            .disabled(!model.state.offline)
            .accessibilityIdentifier("start")
        }
    }
}

/// The stop screen (docs/mobile-apps.md, "When something fails"): why the slot halted in one fixed
/// line, and one action, which closes the app.
struct StopScreen: View {
    let reason: HaltReason?

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("KeepCrypt stopped")
                .font(.title)
                .accessibilityIdentifier("stopped")
            Text(stopLine(reason))
                .accessibilityIdentifier("halt_reason")
            Text("Something failed, so everything the session held was wiped. Close the app; its next start runs the self-test again before any ceremony.")
            Button("Close app") {
                Ceremony.halt(.closed)
            }
            .accessibilityIdentifier("close_app")
        }
    }
}

#if KC_WITH_TEST_REGISTRY
/// The test-registry build's strip, on every screen: this app trusts the test registry's key and is
/// never released.
struct TestRegistryStrip: View {
    var body: some View {
        Text("TEST REGISTRY")
            .font(.caption.bold())
            .frame(maxWidth: .infinity)
            .padding(4)
            .background(Color.orange)
            .accessibilityIdentifier("test_registry_strip")
    }
}
#endif
