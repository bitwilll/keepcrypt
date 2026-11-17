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

#if KC_TEST_HOOKS
import SwiftUI

/// The hooks: what the UI tests set through the panel's buttons.
@MainActor
final class TestHooks: ObservableObject {
    /// The process's one set of hooks.
    static let shared = TestHooks()

    /// Rule 10's marker for the hooks; the panel's identifier, so no build with the hooks drops it.
    static let marker = "KC_TEST_HOOKS_DO_NOT_SHIP"
}

/// The hook panel, drawn at the bottom of every screen in the TestHooks build.
struct TestHookPanel: View {
    var body: some View {
        Text("TEST HOOKS")
            .font(.caption.bold())
            .frame(maxWidth: .infinity)
            .padding(4)
            .background(Color.yellow)
            .accessibilityIdentifier(TestHooks.marker)
    }
}
#endif
