package com.keepcrypt.entropy.screens

/**
 * What a touch lands on: the screen, whether its privacy gate stands before it, and the overlay over it
 * (the cover or the idle warning). A new one is a new screen to the eye, so its controls start closed;
 * a screen that only redraws itself (a roll on the dice, a key on a pad, another page of the same
 * screen) keeps its view and every press.
 */
data class ShownView(val screen: Screen, val gate: Boolean, val overlay: Overlay?)

/** The view state shows. */
fun shownView(state: UiState): ShownView = ShownView(state.screen, state.gate, state.overlay)

/**
 * The press guard (tasks/todo.md, Stage U's U2i; lead decisions M5-72 (f) and M5-79): docs/pi-firmware.md,
 * "Buttons", says a press made before the current screen was fully drawn does nothing, so presses cannot
 * skip a screen, a privacy gate included, before it was seen. On the phone a quick double tap is that
 * press: its second touch lands on whatever the first one's press put under the finger (DoubleTapTest
 * found Skip, Match found and Cannot check each opening their confirm and the second touch pressing its
 * Back, Entropy Android 41247649576, API 36). So a view admits a touch only from GUARD_MILLIS after the
 * frame that composed it (Screens' SideEffect, in that frame, before it is laid out and drawn), and none
 * while the view the model holds is not yet composed. Times are the phone's uptime clock, which a touch's
 * own time is on (the touch's time is when the finger went down, however late it is handled), so a double
 * tap's second touch is refused even when a slow frame delays its handling. Run 41252883580 timed the
 * opening from the frame after the first (a LaunchedEffect's withFrameMillis), which CI's software-rendered
 * emulators deliver hundreds of milliseconds later, and refused the journeys' deliberate presses. Main
 * thread only (Screens' composition and pointer handler).
 */
class PressGuard {
    private var view: ShownView? = null
    private var composedAt = 0L

    /** view was composed at uptimeMillis; a view that stays keeps the time it was first composed. */
    fun composed(view: ShownView, uptimeMillis: Long) {
        if (view == this.view) return
        this.view = view
        composedAt = uptimeMillis
    }

    /** Whether a touch going down at uptimeMillis on view (the model's) reaches its controls. */
    fun admits(view: ShownView, uptimeMillis: Long): Boolean = view == this.view && uptimeMillis - composedAt >= GUARD_MILLIS

    /**
     * What the guard holds against modelView at uptimeMillis, for a test's probe line: the view it holds (screen
     * id, gate, overlay) and how long ago it was composed, and the model's view. Fixed names and times alone.
     */
    fun facts(modelView: ShownView, uptimeMillis: Long): String {
        fun named(view: ShownView?) = view?.let { screenId(it.screen) + (if (it.gate) " behind its gate" else "") + (it.overlay?.let { o -> " under " + o.name } ?: "") } ?: "none"
        val held = view
        val age = if (held == null) "" else ", composed " + (uptimeMillis - composedAt) + " ms ago"
        return "the press guard holds " + named(held) + age + "; the model shows " + named(modelView)
    }

    companion object {
        /** How long a new view's controls ignore touches after the frame that composed it (M5-72 (f)). */
        const val GUARD_MILLIS = 300L
    }
}
