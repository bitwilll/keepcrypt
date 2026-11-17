// The iPhone app (tasks/todo.md, M6 items C2 and C3; Q86): in Stage C a shell that runs the start-up
// self-test (docs/mobile-apps.md, step 2) and shows its outcome, "Self-test passed" or the stop screen.
// The ceremony's screens come in Stage D, the capture layers and the offline check in C5; the TestHooks
// build (C5, M6-5) draws the UI tests' hook panel under every screen.

import SwiftUI

@main
struct KeepCryptApp: App {
    var body: some Scene {
        WindowGroup {
            #if KC_TEST_HOOKS
            StartView()
                .safeAreaInset(edge: .bottom) { TestHookPanel() }
            #else
            StartView()
            #endif
        }
    }
}

/// The start-up self-test and its outcome, in fixed text only.
struct StartView: View {
    @State private var screen: StartScreen?

    var body: some View {
        VStack(spacing: 0) {
            #if KC_WITH_TEST_REGISTRY
            TestRegistryStrip()
            #endif
            Spacer()
            switch screen {
            case nil:
                Text("Running the self-test")
                    .accessibilityIdentifier("self_test_running")
            case .passed:
                Text("Self-test passed")
                    .font(.title2)
                    .accessibilityIdentifier("self_test_passed")
            case .stopped(let reason):
                StopScreen(reason: reason)
            }
            Spacer()
        }
        .padding()
        .textSelection(.disabled)
        .task {
            screen = await StartScreen.afterSelfTest()
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
