// The press guard (tasks/todo.md, M6 item D2; :screens' PressGuard.kt; Stage U's U2i; lead decisions M5-72
// (f) and M5-79): docs/pi-firmware.md, "Buttons", says a press made before the current screen was fully
// drawn does nothing, so presses cannot skip a screen, a privacy gate included, before it was seen. On a
// phone a quick double tap is that press: its second touch lands on whatever the first one's press put
// under the finger. So a view admits a touch only from guardMillis after it was first shown, and none
// while the view the model holds has not been shown yet. Times are the touch's own (the uptime clock a
// touch event carries), so a double tap's second touch is refused even when a slow frame delays its
// handling. The SwiftUI screens (D3 on) report each view as they show it and ask before every press.
//
// At the action (lead decision M6-23, a U4 defect U2 found): the touch guard (Screens.swift) refused a touch at
// its down by recognizing, which cancelled it in the views under it; on iOS 26 a SwiftUI Button still ran its
// action for that touch (run 44326338905: a double tap's second touch, refused on the passphrase's entry, ran
// its Back 248 ms later and took the app home past the gate). Since M6-27 the cancel is gone, and the gate alone
// decides: the touch guard only observes (the verdict of each down, noteDown), because taking part in the
// gestures' arbitration made an iOS 26 Button lose an admitted press now and again, its closure never run (U2j's
// probe, "the button never fired"). Every press's action runs through the press gate (Kit.swift's PressGate, which KitButton, the pads' keys and
// the overlay's tap all go through), which asks permits when the action comes. An action runs only if the
// latest touch down in the screens' area was admitted (a down whose touches were refused in part counts as
// refused) and the view shown admits a touch at that moment; otherwise it is dropped, silently. A refusal
// holds until the next down, or until another view is shown (the refused touch's buttons went with its view).
// An action no touch made (VoiceOver's, Switch Control's) meets the 300 ms rule alone. Android's PressGuard.kt
// decides at the down only: its root pointer handler consumes a refused pointer's every event, so no click
// follows it (Screens.kt); this check at the action is iOS's alone.

/// What a touch lands on: the screen, whether its privacy gate stands before it, and the overlay over
/// it. A new one is a new screen to the eye, so its controls start closed; a screen that only redraws
/// itself (a roll on the dice, a key on a pad, another page of the same screen) keeps its view and every
/// press.
struct ShownView: Equatable {
    let screen: Screen
    let gate: Bool
    let overlay: Overlay?
}

/// The view state shows.
func shownView(_ state: UiState) -> ShownView {
    ShownView(screen: state.screen, gate: state.gate, overlay: state.overlay)
}

/// Android's PressGuard, ported: main thread only.
final class PressGuard {
    /// How long a new view's controls ignore touches after it was shown (M5-72 (f)).
    static let guardMillis: Int64 = 300

    private var view: ShownView?
    private var composedAt: Int64 = 0
    /// The latest touch down in the screens' area: the view the model showed then, and whether it was admitted.
    private var lastDown: (view: ShownView, admitted: Bool)?

    /// view was shown at uptimeMillis; a view that stays keeps the time it was first shown. Another view
    /// than the one a refused down landed on ends that refusal: its buttons are gone.
    func composed(_ view: ShownView, _ uptimeMillis: Int64) {
        if view == self.view { return }
        self.view = view
        composedAt = uptimeMillis
        if let lastDown, !lastDown.admitted, lastDown.view != view {
            self.lastDown = nil
        }
    }

    /// Touches went down on view (the model's), all admitted, or one or more refused (M6-23).
    func noteDown(_ view: ShownView, admitted: Bool) {
        lastDown = (view, admitted)
    }

    /// Whether the latest touch down was refused (a test's probe: a fixed yes or no).
    var lastDownRefused: Bool {
        lastDown?.admitted == false
    }

    /// Whether a press's action, coming at uptimeMillis on view (the model's), runs (M6-23): the latest down
    /// admitted, or none since a refusal ended, and the view admitting a touch now.
    func permits(_ view: ShownView, _ uptimeMillis: Int64) -> Bool {
        !lastDownRefused && admits(view, uptimeMillis)
    }

    /// Whether a touch going down at uptimeMillis on view (the model's) reaches its controls.
    func admits(_ view: ShownView, _ uptimeMillis: Int64) -> Bool {
        view == self.view && uptimeMillis - composedAt >= PressGuard.guardMillis
    }

    /// What the guard holds against modelView at uptimeMillis, for a test's probe line: the view it holds
    /// (screen id, gate, overlay) and how long ago it was shown, and the model's view. Fixed names and
    /// times alone.
    func facts(_ modelView: ShownView, _ uptimeMillis: Int64) -> String {
        func named(_ view: ShownView?) -> String {
            guard let view else { return "none" }
            var text = view.screen.id
            if view.gate { text += " behind its gate" }
            if let overlay = view.overlay { text += overlay == .cover ? " under Cover" : " under Warning" }
            return text
        }
        let age = view == nil ? "" : ", composed " + String(uptimeMillis - composedAt) + " ms ago"
        return "the press guard holds " + named(view) + age + "; the model shows " + named(modelView)
    }
}
