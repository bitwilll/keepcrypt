// The iPhone app (tasks/todo.md, M6 items C2, C3, C5, D2 and D3; Q86): the CeremonyModel (Ceremony.swift)
// over its seams, the screens over its state (Screens.swift), inside the capture layers (CaptureShield.swift)
// and watched by the offline check (OfflineCheck.swift). The TestHooks build (C5, M6-5) draws the UI tests'
// hook panel under every screen.

import SwiftUI

@main
struct KeepCryptApp: App {
    @StateObject private var model: CeremonyModel
    private let offlineCheck: OfflineCheck
    private let pressGuard = PressGuard()
    private let scanner: QrScanner
    @StateObject private var pickers = ScreenPickers()

    init() {
        #if KC_WITH_TEST_REGISTRY
        let registry = true
        #else
        let registry = false
        #endif
        let model = CeremonyModel(
            core: Core.shared, worker: QueueWorker(), clock: SystemClock(), date: SystemDate(),
            motion: CoreMotionSource(), testRegistry: registry)
        _model = StateObject(wrappedValue: model)
        offlineCheck = OfflineCheck { offline in
            model.pathReported(offline: offline)
        }
        offlineCheck.start()
        #if KC_TEST_HOOKS
        TestHooks.shared.offlineCheck = offlineCheck
        let hooked = HookedScanner(camera: GoAheadScanner())
        TestHooks.shared.scanner = hooked
        scanner = hooked
        #else
        scanner = GoAheadScanner()
        #endif
    }

    var body: some Scene {
        WindowGroup {
            CaptureShield(model: model) {
                Screens(model: model, pressGuard: pressGuard, scanner: scanner, pickers: pickers)
            }
        }
    }
}
