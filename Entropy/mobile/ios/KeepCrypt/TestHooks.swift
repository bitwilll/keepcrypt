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
// backupPicked, the importer's own path in; the system's document browser is not the app's to drive), and
// from U1 the backup's save (the exporter answered with a place in memory alone, through backupPlaced: the
// TestHooks app writes no file, rule 8, and core verifies what was written), the saved backup offered to
// Check a backup (KC_HOOK_BACKUP_FROM_SAVE), a snapshot from Load registry snapshot's picker (through
// snapshotPicked) and a halt of the slot (the shell's own, so the next call shows the stop screen); and the
// counts of touches the screens' touch guard saw and its press guard refused, which the panel shows, so a UI
// test can tell a press the guard refused from one that never reached the app (U1d). Each
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
    /// The touches the screens' touch guard saw go down in the screens' area, and those its press guard
    /// refused (U1d: the UI tests' probe of a press that did nothing).
    @Published private(set) var touchesSeen = 0
    @Published private(set) var touchesRefused = 0

    /// Touches that went down, refused or admitted by the press guard (Screens.swift's TouchGuardRecognizer).
    func noteTouches(_ count: Int, refused: Bool) {
        touchesSeen += count
        if refused { touchesRefused += count }
    }
    /// The app's offline check, whose state the path hooks force.
    var offlineCheck: OfflineCheck?
    /// The scan screen's scanner while it scans, whose found callback the Scan hook calls.
    var scanner: HookedScanner?

    /// The text the UI test's launch environment gives the Scan hook (KC_HOOK_SCAN_TEXT), if any.
    nonisolated static var scanText: String? {
        ProcessInfo.processInfo.environment["KC_HOOK_SCAN_TEXT"]
    }

    /// The model's entries the picker hooks answer, the pickers' own (Screens.swift, DocumentPicker.swift):
    /// Check a backup's picked file, the backup's saved place and Load registry snapshot's picked file.
    var backupPicked: ((PickedFile?) -> Void)?
    var backupPlaced: ((DocumentPlace?) -> Void)?
    var snapshotPicked: ((PickedFile?) -> Void)?
    /// Each picker waiting for its hook instead of the system's.
    var backupWaiting = false
    var saveWaiting = false
    var snapshotWaiting = false
    /// The backup the Save hook was handed (core's name and the model's own Secret), while the save waits.
    private var saving: (name: String, bytes: Secret)?
    /// The backup the Save hook's place was written, in memory alone (rule 8: no file), under core's name;
    /// zeroed when Check a backup takes it, at a new save and at the process's end.
    private(set) var saved: (name: String, bytes: [UInt8])?

    /// The launch environment's hex value of key as bytes; nil without it or when it is not hex.
    nonisolated static func hexEnvironment(_ key: String) -> [UInt8]? {
        guard let hex = ProcessInfo.processInfo.environment[key] else { return nil }
        let digits = Array(hex.utf8)
        guard digits.count % 2 == 0 else { return nil }
        var bytes: [UInt8] = []
        for at in stride(from: 0, to: digits.count, by: 2) {
            guard let byte = UInt8(String(decoding: digits[at...at + 1], as: UTF8.self), radix: 16) else { return nil }
            bytes.append(byte)
        }
        return bytes
    }

    /// Whether Check a backup's picker waits for the Backup file hook: with the save's copy offered
    /// (KC_HOOK_BACKUP_FROM_SAVE), or a file in the launch environment (KC_HOOK_BACKUP_NAME and
    /// KC_HOOK_BACKUP_HEX, a public backup.json vector's).
    nonisolated static var backupHooked: Bool {
        let environment = ProcessInfo.processInfo.environment
        return environment["KC_HOOK_BACKUP_FROM_SAVE"] != nil
            || (environment["KC_HOOK_BACKUP_NAME"] != nil && environment["KC_HOOK_BACKUP_HEX"] != nil)
    }

    /// The Save hook's mode (KC_HOOK_SAVE): "ok", or U2's "fail-write", "fail-read" and "corrupt"; nil
    /// without it, and the system's exporter opens.
    nonisolated static var saveMode: String? {
        ProcessInfo.processInfo.environment["KC_HOOK_SAVE"]
    }

    /// Whether Load registry snapshot's picker waits for the Snapshot file hook (KC_HOOK_SNAPSHOT_NAME and
    /// KC_HOOK_SNAPSHOT_HEX, a kcr.json snapshot's).
    nonisolated static var snapshotHooked: Bool {
        let environment = ProcessInfo.processInfo.environment
        return environment["KC_HOOK_SNAPSHOT_NAME"] != nil && environment["KC_HOOK_SNAPSHOT_HEX"] != nil
    }

    /// The Backup file hook: the file to the model's backupPicked, once, as the open picker's answer would
    /// come, while Check a backup's picker waits: the save's copy (taken, and zeroed here once handed over)
    /// or the launch environment's.
    func pickBackup() {
        guard backupWaiting else { return }
        let environment = ProcessInfo.processInfo.environment
        var file: (name: String, bytes: [UInt8])?
        if environment["KC_HOOK_BACKUP_FROM_SAVE"] != nil {
            file = saved
            dropSaved()
        } else if let name = environment["KC_HOOK_BACKUP_NAME"], let bytes = TestHooks.hexEnvironment("KC_HOOK_BACKUP_HEX") {
            file = (name, bytes)
        }
        guard var picked = file else { return }
        backupWaiting = false
        backupPicked?(HookedFile(name: picked.name, bytes: picked.bytes))
        picked.bytes.resetBytes()
    }

    /// The backup's save, held for the Save hook (HookedPickers.create).
    func holdSave(name: String, bytes: Secret) {
        saving = (name, bytes)
        saveWaiting = true
    }

    /// The Save hook: a place for the bytes the model was saving, to its backupPlaced, as the exporter's
    /// answer would come: written to memory alone, then read back from there.
    func pickSave() {
        guard saveWaiting, let saving else { return }
        saveWaiting = false
        self.saving = nil
        dropSaved()
        backupPlaced?(HookedPlace(name: saving.name, exported: saving.bytes, mode: TestHooks.saveMode ?? "ok"))
    }

    /// The Save hook's place wrote these bytes.
    fileprivate func keepSaved(name: String, bytes: [UInt8]) {
        dropSaved()
        saved = (name, bytes)
    }

    private func dropSaved() {
        saved?.bytes.resetBytes()
        saved = nil
    }

    /// The Snapshot file hook: the launch environment's snapshot to the model's snapshotPicked, once, while
    /// Load registry snapshot's picker waits.
    func pickSnapshot() {
        let environment = ProcessInfo.processInfo.environment
        guard snapshotWaiting, let name = environment["KC_HOOK_SNAPSHOT_NAME"],
            let bytes = TestHooks.hexEnvironment("KC_HOOK_SNAPSHOT_HEX")
        else { return }
        snapshotWaiting = false
        snapshotPicked?(HookedFile(name: name, bytes: bytes))
    }

    /// The Halt hook: the slot halted as core halts it (the shell's own halt, reason internal), so the
    /// model's next call shows the stop screen, as any halt does.
    func haltSlot() {
        _ = Core.shared.shellHalt()
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

/// The pickers in the TestHooks build: with its hook's launch environment, Check a backup's, the backup's
/// save and Load registry snapshot's picker each wait for their hook instead of opening the system's;
/// without it each is the app's own.
final class HookedPickers: DocumentPickers {
    private let screen: ScreenPickers

    init(screen: ScreenPickers) {
        self.screen = screen
    }

    func create(name: String, bytes: Secret) {
        guard TestHooks.saveMode != nil else {
            screen.create(name: name, bytes: bytes)
            return
        }
        MainActor.assumeIsolated { TestHooks.shared.holdSave(name: name, bytes: bytes) }
    }

    func openBackup() {
        guard TestHooks.backupHooked else {
            screen.openBackup()
            return
        }
        MainActor.assumeIsolated { TestHooks.shared.backupWaiting = true }
    }

    func openSnapshot() {
        guard TestHooks.snapshotHooked else {
            screen.openSnapshot()
            return
        }
        MainActor.assumeIsolated { TestHooks.shared.snapshotWaiting = true }
    }
}

/// A hooked picker's file: its name, its size as its bytes' count, and its bytes, read as a picked file's
/// are (at most limit + 1, into a Secret).
final class HookedFile: PickedFile {
    let name: String?
    let size: Int64?
    private var bytes: [UInt8]

    init(name: String, bytes: [UInt8]) {
        self.name = name
        size = Int64(bytes.count)
        self.bytes = bytes
    }

    deinit {
        bytes.resetBytes()
    }

    func read(limit: Int) -> Secret? {
        Secret(taking: Array(bytes.prefix(limit + 1)))
    }
}

/// The Save hook's place, in memory alone (rule 8: the TestHooks app writes no file): its write says whether
/// it was handed the very Secret the exporter would have written (ExportedPlace's test) and keeps a copy of
/// its bytes (TestHooks' saved); its read-back gives a copy of at most limit + 1 of them, so core's verify
/// runs on what was written. Its mode gives U2's failures: a write that fails, a read-back that fails, or a
/// read-back with its middle byte changed (core's verify refuses it).
final class HookedPlace: DocumentPlace {
    private let name: String
    private let exported: Secret
    private let mode: String
    private var written: [UInt8]?

    init(name: String, exported: Secret, mode: String) {
        self.name = name
        self.exported = exported
        self.mode = mode
    }

    deinit {
        written?.resetBytes()
    }

    func write(_ bytes: Secret) -> Bool {
        guard bytes === exported, mode != "fail-write" else { return false }
        let copy = (0..<bytes.count).map { bytes[$0] }
        written = copy
        let name = self.name
        MainActor.assumeIsolated { TestHooks.shared.keepSaved(name: name, bytes: copy) }
        return true
    }

    func readBack(limit: Int) -> Secret? {
        guard var copy = written, mode != "fail-read" else { return nil }
        if mode == "corrupt", !copy.isEmpty { copy[copy.count / 2] ^= 0x01 }
        defer { copy.resetBytes() }
        return Secret(taking: Array(copy.prefix(limit + 1)))
    }
}

private extension Array where Element == UInt8 {
    /// Every byte zeroed in place.
    mutating func resetBytes() {
        for index in indices {
            self[index] = 0
        }
    }
}

/// The secret nodes' identifiers (lead decision M6-20): compiled into the TestHooks app alone, each listed in
/// mobile/ios/expected/secret-identifiers.txt, which --ios-app refuses in the shipped apps. Each is kc_secret_
/// and the node's name, 16 bytes or more, so Swift keeps it as bytes in the binary (a string of 15 or fewer is
/// built in the code itself, which no byte scan sees) and no other name holds it (core's Rust symbols spell
/// passphrase_text, say).
extension SecretNode {
    var testIdentifier: String {
        switch self {
        case .insertWord: return "kc_secret_insert_word"
        case .insertSeedbook: return "kc_secret_insert_seedbook"
        case .insertFace: return "kc_secret_insert_face"
        case .overviewLine: return "kc_secret_overview_line"
        case .typedLetters: return "kc_secret_typed_letters"
        case .verdictLine: return "kc_secret_verdict_line"
        case .passphraseText: return "kc_secret_passphrase_text"
        case .confirmChoice: return "kc_secret_confirm_choice"
        case .bip39Text: return "kc_secret_bip39_text"
        case .deviceLeg: return "kc_secret_device_leg_text"
        case .dicePick: return "kc_secret_dice_pick"
        }
    }
}

/// The hook panel, drawn under the scene in the TestHooks build (outside the press guard), covers included.
struct TestHookPanel: View {
    @ObservedObject private var hooks = TestHooks.shared
    /// The model, whose facts line the panel shows (U1f), and whether the scene is active.
    @ObservedObject var model: CeremonyModel
    let sceneActive: Bool

    var body: some View {
        VStack(spacing: 4) {
            HStack {
                Text("TEST HOOKS")
                    .font(.caption.bold())
                    .accessibilityIdentifier(TestHooks.marker)
                Text(String(hooks.touchesSeen))
                    .accessibilityIdentifier("hook_touches_seen")
                Text(String(hooks.touchesRefused))
                    .accessibilityIdentifier("hook_touches_refused")
            }
            // What the model holds, by fixed names and counts alone (U1f), for a UI test's probe.
            Text(model.hookFacts(sceneActive: sceneActive))
                .font(.system(size: 6))
                .lineLimit(1)
                .accessibilityIdentifier("hook_facts")
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
            HStack {
                Button("Backup file") { hooks.pickBackup() }
                    .accessibilityIdentifier("hook_backup_file")
                Button("Save") { hooks.pickSave() }
                    .accessibilityIdentifier("hook_save")
                Button("Snapshot file") { hooks.pickSnapshot() }
                    .accessibilityIdentifier("hook_snapshot_file")
                Button("Halt") { hooks.haltSlot() }
                    .accessibilityIdentifier("hook_halt")
            }
        }
        .font(.caption)
        .frame(maxWidth: .infinity)
        .padding(4)
        .background(Color.yellow)
    }
}
#endif
