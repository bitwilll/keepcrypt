// The UI tests' hooks into the app (tasks/todo.md, M6 item C5; lead decision M6-5). XCUITest drives the
// app as a process of its own, so a hook it needs must be compiled into the app: this whole file is
// compiled only under KC_TEST_HOOKS, which the app target's TestHooks configuration alone sets (the
// gate's SwTestHook rule), and that configuration is built only by the KeepCrypt-TestHooks scheme,
// for the UI tests, and never archived. The Shipping and WithTestRegistry apps hold none of it.
//
// Rule 10's pattern: the hooks carry a marker, KC_TEST_HOOKS_DO_NOT_SHIP, drawn as the hook panel's
// identifier, so it is in every binary that holds the hooks; the app scan (scripts/banned-api-check.sh
// --ios-app) refuses it in both shipped configurations, and the iPhone workflow requires it in the
// TestHooks app, so a build that set the condition another way is still caught.
//
// The hooks stand in for what a simulator cannot do on its own: a recording or mirroring of the
// screen (the capture state forced on), the app switcher (the scene forced inactive), a hardware
// screenshot (the system's notification posted, as iOS posts it). Each acts on the same inputs the real
// events reach.

#if KC_TEST_HOOKS
import SwiftUI
import UIKit

/// The hooks: what the UI tests set through the panel's buttons.
@MainActor
final class TestHooks: ObservableObject {
    /// The process's one set of hooks.
    static let shared = TestHooks()

    /// Rule 10's marker for the hooks; the panel's identifier, so no build with the hooks drops it.
    static let marker = "KC_TEST_HOOKS_DO_NOT_SHIP"

    /// The capture state forced on, as a recording, mirroring or sharing of the screen sets it.
    @Published var captured = false
    /// The scene forced inactive, as the app switcher leaves it.
    @Published var inactive = false
}

/// The hook panel, drawn over the bottom of the scene in the TestHooks build, covers included.
struct TestHookPanel: View {
    @ObservedObject private var hooks = TestHooks.shared

    var body: some View {
        VStack(spacing: 4) {
            Text("TEST HOOKS")
                .font(.caption.bold())
                .accessibilityIdentifier(TestHooks.marker)
            HStack {
                Button("Capture") { hooks.captured.toggle() }
                    .accessibilityIdentifier("hook_capture")
                Button("Inactive") { hooks.inactive.toggle() }
                    .accessibilityIdentifier("hook_inactive")
                Button("Screenshot") {
                    NotificationCenter.default.post(name: UIApplication.userDidTakeScreenshotNotification, object: UIApplication.shared)
                }
                .accessibilityIdentifier("hook_screenshot")
            }
        }
        .font(.caption)
        .frame(maxWidth: .infinity)
        .padding(4)
        .background(Color.yellow)
    }
}
#endif
