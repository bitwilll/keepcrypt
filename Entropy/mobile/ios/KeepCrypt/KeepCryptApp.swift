// The iPhone app (tasks/todo.md, M6 items C2, C3 and C5; Q86): in Stage C a shell of the start-up
// self-test (docs/mobile-apps.md, step 2) inside the capture layers (CaptureShield.swift). The
// ceremony's screens come in Stage D. The TestHooks build (C5, M6-5) draws the UI tests' hook panel
// over every screen.

import SwiftUI

@main
struct KeepCryptApp: App {
    @StateObject private var model = CeremonyModel()

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
            case .passed:
                Text("Self-test passed")
                    .font(.title2)
                    .accessibilityIdentifier("self_test_passed")
            }
            if let notice = model.notice {
                Text(noticeLine(notice))
                    .padding(.top, 24)
                    .accessibilityIdentifier("notice_screenshot")
            }
            Spacer()
        }
        .padding()
        .textSelection(.disabled)
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
