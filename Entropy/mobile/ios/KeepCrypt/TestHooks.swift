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
// screenshot (the system's notification posted, as iOS posts it), the network coming and going
// (the offline check's state forced) and a QR code before the camera (D4: the scanner's found callback
// handed the UI test's text, the camera's own path into the model; the simulator has no camera). Each acts
// on the same inputs the real events reach.

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
    /// The app's offline check, whose state the path hooks force.
    var offlineCheck: OfflineCheck?
    /// The scan screen's scanner while it scans, whose found callback the Scan hook calls.
    var scanner: HookedScanner?

    /// The text the UI test's launch environment gives the Scan hook (KC_HOOK_SCAN_TEXT), if any.
    nonisolated static var scanText: String? {
        ProcessInfo.processInfo.environment["KC_HOOK_SCAN_TEXT"]
    }
}

/// The scanner in the TestHooks build: with a scan text in the launch environment it holds the scan
/// screen's callbacks instead of starting the camera, and the Scan hook hands that text to found, as a
/// QR code before the camera would; without one it is the app's own scanner.
final class HookedScanner: QrScanner {
    private let camera: QrScanner
    private var found: ((String) -> Void)?

    init(camera: QrScanner) {
        self.camera = camera
    }

    func start(found: @escaping (String) -> Void, stopped: @escaping (ScanStop) -> Void) {
        guard TestHooks.scanText != nil else {
            camera.start(found: found, stopped: stopped)
            return
        }
        self.found = found
    }

    func stop() {
        found = nil
        camera.stop()
    }

    /// The Scan hook: the launch environment's text to found, once, as a scanned QR code's.
    func scan() {
        guard let found, let text = TestHooks.scanText else { return }
        self.found = nil
        found(text)
    }
}

/// The hook panel, drawn under the scene in the TestHooks build (outside the press guard), covers included.
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
            HStack {
                Button("Path usable") { hooks.offlineCheck?.force(offline: false) }
                    .accessibilityIdentifier("hook_path_usable")
                Button("No path") { hooks.offlineCheck?.force(offline: true) }
                    .accessibilityIdentifier("hook_path_none")
                Button("Scan") { hooks.scanner?.scan() }
                    .accessibilityIdentifier("hook_scan")
            }
        }
        .font(.caption)
        .frame(maxWidth: .infinity)
        .padding(4)
        .background(Color.yellow)
    }
}
#endif
