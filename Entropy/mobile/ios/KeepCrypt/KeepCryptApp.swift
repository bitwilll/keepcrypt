// The iPhone app (tasks/todo.md, M6 items C2, C3 and C5; Q86): in Stage C a shell of the start-up
// self-test (docs/mobile-apps.md, step 2), Go offline (step 3) and Home, inside the capture layers
// (CaptureShield.swift) and watched by the offline check (OfflineCheck.swift). The ceremony's screens
// come in Stage D. The TestHooks build (C5, M6-5) draws the UI tests' hook panel over every screen.

import SwiftUI

@main
struct KeepCryptApp: App {
    @StateObject private var model: CeremonyModel
    private let offlineCheck: OfflineCheck

    init() {
        let model = CeremonyModel()
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

/// Stage C's screens, in fixed text only.
struct StartView: View {
    @ObservedObject var model: CeremonyModel

    var body: some View {
        VStack(spacing: 0) {
            #if KC_WITH_TEST_REGISTRY
            TestRegistryStrip()
            #endif
            Spacer()
            switch model.screen {
            case .selfTest:
                Text("Running the self-test")
                    .accessibilityIdentifier("self_test_running")
            case .stopped(let reason):
                StopScreen(reason: reason)
            case .goOffline:
                GoOfflineScreen(model: model)
            case .home:
                Text("Home")
                    .font(.title)
                    .accessibilityIdentifier("home")
            }
            if let notice = model.notice {
                Text(noticeLine(notice))
                    .padding(.top, 24)
                    .accessibilityIdentifier(notice == .screenshot ? "notice_screenshot" : "notice_offline")
            }
            Spacer()
        }
        .padding()
        .textSelection(.disabled)
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
            Text(model.offline
                 ? "No usable network path: the phone is offline."
                 : "A network path is usable: turn on airplane mode and turn off Wi-Fi.")
                .accessibilityIdentifier("network_state")
            Button("Start") {
                model.startOffline()
            }
            .disabled(!model.offline)
            .accessibilityIdentifier("start")
        }
    }
}

/// The stop screen (docs/mobile-apps.md, "When something fails"): why the slot halted in one fixed
/// line, and one action, which closes the app.
struct StopScreen: View {
    let reason: HaltReason

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
