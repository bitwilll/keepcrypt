// The press guard (tasks/todo.md, M6 item D2; :screens' PressGuard.kt; Stage U's U2i; lead decisions M5-72
// (f) and M5-79): docs/pi-firmware.md, "Buttons", says a press made before the current screen was fully
// drawn does nothing, so presses cannot skip a screen, a privacy gate included, before it was seen. On a
// phone a quick double tap is that press: its second touch lands on whatever the first one's press put
// under the finger. So a view admits a touch only from guardMillis after it was first shown, and none
// while the view the model holds has not been shown yet. Times are the touch's own (the uptime clock a
// touch event carries), so a double tap's second touch is refused even when a slow frame delays its
// handling. The SwiftUI screens (D3 on) report each view as they show it and ask before every press.

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

    /// view was shown at uptimeMillis; a view that stays keeps the time it was first shown.
    func composed(_ view: ShownView, _ uptimeMillis: Int64) {
        if view == self.view { return }
        self.view = view
        composedAt = uptimeMillis
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
