// The capture layers, app-wide (docs/mobile-apps.md, "Screen capture protection: iPhone"; tasks/todo.md,
// M6 item C5). iOS cannot block a screenshot or a recording, so the whole scene is wrapped once, before
// any Protected screen exists, and every screen inherits the layers:
//
// - **Capture redaction.** While SwiftUI's isSceneCaptured or the window's own sceneCaptureState
//   (UIKit, read by a view in the window and re-read on every change of the trait) says the screen is
//   recorded, mirrored or shared, the cover replaces the scene's content: nothing of it is drawn, or
//   left for the accessibility tree, until the capture ends.
// - **The app-switcher cover.** While the scene is not active (the app switcher, Control Center, a
//   system sheet), the privacy cover replaces it too, so the snapshot iOS keeps shows the cover.
// - **The screenshot response.** UIApplication.userDidTakeScreenshotNotification comes after the
//   screenshot is saved; the model then discards whatever session exists and says why.
// - The fourth layer, Q88's secure layer, is SecureLayer.swift's, for the views of the words.
//
// The content's state lives in the model, never in the views the cover replaces.

import SwiftUI
import UIKit

/// The scene's root: content, or a cover over the whole scene.
struct CaptureShield<Content: View>: View {
    @ObservedObject var model: CeremonyModel
    let content: Content

    @Environment(\.isSceneCaptured) private var isSceneCaptured
    @Environment(\.scenePhase) private var scenePhase
    @State private var windowCaptured = false
    #if KC_TEST_HOOKS
    @ObservedObject private var hooks = TestHooks.shared
    #endif

    init(model: CeremonyModel, @ViewBuilder content: () -> Content) {
        self.model = model
        self.content = content()
    }

    var body: some View {
        ZStack {
            switch CaptureCover.of(captured: captured, active: active) {
            case .capture:
                CaptureCover(line: "Hidden while the screen is recorded, mirrored or shared.")
                    .accessibilityIdentifier("capture_cover")
            case .privacy:
                CaptureCover(line: "KeepCrypt")
                    .accessibilityIdentifier("privacy_cover")
            case nil:
                content
            }
        }
        .background(CaptureStateProbe(captured: $windowCaptured))
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.userDidTakeScreenshotNotification)) { _ in
            model.discardAfterScreenshot()
        }
        #if KC_TEST_HOOKS
        .overlay(alignment: .bottom) { TestHookPanel() }
        #endif
    }

    /// The screen is recorded, mirrored or shared, as either reading says.
    private var captured: Bool {
        #if KC_TEST_HOOKS
        if hooks.captured { return true }
        #endif
        return isSceneCaptured || windowCaptured
    }

    /// The scene is active (in the foreground, taking input).
    private var active: Bool {
        #if KC_TEST_HOOKS
        if hooks.inactive { return false }
        #endif
        return scenePhase == .active
    }
}

/// A cover over the whole scene: an opaque background and one fixed line.
struct CaptureCover: View {
    /// Which cover the scene needs, if any: capture first, as it may outlast the scene's phase.
    enum Kind: Equatable {
        case capture
        case privacy
    }

    let line: String

    static func of(captured: Bool, active: Bool) -> Kind? {
        if captured { return .capture }
        if !active { return .privacy }
        return nil
    }

    var body: some View {
        ZStack {
            Color(uiColor: .systemBackground)
                .ignoresSafeArea()
            Text(line)
                .font(.headline)
                .multilineTextAlignment(.center)
                .padding()
        }
    }
}

/// The window's sceneCaptureState (UIKit, iOS 17), beside SwiftUI's isSceneCaptured: a view in the
/// window reads its trait when it joins the window and on every change of it, and reports the active
/// state alone.
private struct CaptureStateProbe: UIViewRepresentable {
    @Binding var captured: Bool

    func makeUIView(context: Context) -> CaptureStateView {
        CaptureStateView()
    }

    func updateUIView(_ view: CaptureStateView, context: Context) {
        let binding = $captured
        view.changed = { binding.wrappedValue = $0 }
    }
}

final class CaptureStateView: UIView {
    /// Called with each new reading, on the main thread, after the view update that brought it.
    var changed: ((Bool) -> Void)?
    private var last: Bool?

    override init(frame: CGRect) {
        super.init(frame: frame)
        isUserInteractionEnabled = false
        isAccessibilityElement = false
        _ = registerForTraitChanges([UITraitSceneCaptureState.self]) { (view: CaptureStateView, _: UITraitCollection) in
            view.read()
        }
    }

    required init?(coder: NSCoder) {
        nil
    }

    override func didMoveToWindow() {
        super.didMoveToWindow()
        read()
    }

    private func read() {
        let now = window?.traitCollection.sceneCaptureState == .active
        guard now != last else { return }
        last = now
        DispatchQueue.main.async { [weak self] in
            self?.changed?(now)
        }
    }
}
