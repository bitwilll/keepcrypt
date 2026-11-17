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
// (the offline check's state forced), a QR code before the camera (D4: the scanner's found callback
// handed the UI test's text, the camera's own path into the model; the simulator has no camera) and a file
// from the open picker (D7: Check a backup's picker answered with the UI test's file, through the model's
// backupPicked, the importer's own path in; the system's document browser is not the app's to drive). Each
// acts on the same inputs the real events reach.

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

    /// The model's entry for Check a backup's picked file, the importer's own (Screens.swift).
    var backupPicked: ((PickedFile?) -> Void)?
    /// Check a backup's picker is waiting for the Backup file hook.
    var backupWaiting = false

    /// The file the UI test's launch environment gives the Backup file hook: its name (KC_HOOK_BACKUP_NAME)
    /// and its bytes in hex (KC_HOOK_BACKUP_HEX), a public backup.json vector's; nil without both.
    nonisolated static var backupFile: (name: String, bytes: [UInt8])? {
        let environment = ProcessInfo.processInfo.environment
        guard let name = environment["KC_HOOK_BACKUP_NAME"], let hex = environment["KC_HOOK_BACKUP_HEX"] else { return nil }
        let digits = Array(hex.utf8)
        guard digits.count % 2 == 0 else { return nil }
        var bytes: [UInt8] = []
        for at in stride(from: 0, to: digits.count, by: 2) {
            guard let byte = UInt8(String(decoding: digits[at...at + 1], as: UTF8.self), radix: 16) else { return nil }
            bytes.append(byte)
        }
        return (name, bytes)
    }

    /// The Backup file hook: the launch environment's file to the model's backupPicked, once, as the open
    /// picker's answer would come, while Check a backup's picker waits.
    func pickBackup() {
        guard backupWaiting, let file = TestHooks.backupFile else { return }
        backupWaiting = false
        backupPicked?(HookedFile(name: file.name, bytes: file.bytes))
    }
}

/// The pickers in the TestHooks build: with a backup file in the launch environment, Check a backup's
/// picker waits for the Backup file hook instead of opening the system's; everything else, and every
/// picker without one, is the app's own.
final class HookedPickers: DocumentPickers {
    private let screen: ScreenPickers

    init(screen: ScreenPickers) {
        self.screen = screen
    }

    func create(name: String, bytes: Secret) {
        screen.create(name: name, bytes: bytes)
    }

    func openBackup() {
        guard TestHooks.backupFile != nil else {
            screen.openBackup()
            return
        }
        MainActor.assumeIsolated { TestHooks.shared.backupWaiting = true }
    }

    func openSnapshot() {
        screen.openSnapshot()
    }
}

/// The Backup file hook's file: its name, its size as its bytes' count, and its bytes, read as a picked
/// file's are (at most limit + 1, into a Secret).
final class HookedFile: PickedFile {
    let name: String?
    let size: Int64?
    private let bytes: [UInt8]

    init(name: String, bytes: [UInt8]) {
        self.name = name
        size = Int64(bytes.count)
        self.bytes = bytes
    }

    func read(limit: Int) -> Secret? {
        Secret(taking: Array(bytes.prefix(limit + 1)))
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
                Button("Backup file") { hooks.pickBackup() }
                    .accessibilityIdentifier("hook_backup_file")
            }
        }
        .font(.caption)
        .frame(maxWidth: .infinity)
        .padding(4)
        .background(Color.yellow)
    }
}
#endif
