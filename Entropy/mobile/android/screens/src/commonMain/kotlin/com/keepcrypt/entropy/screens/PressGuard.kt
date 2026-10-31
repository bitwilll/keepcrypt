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
 * Back, Entropy Android 41247649576, API 36). So a view admits a touch only from GUARD_MILLIS after its
 * first frame, and nothing before that frame. Times are the frame clock's and the touch's uptime, which
 * are one monotonic clock on the phone. Main thread only (Screens' composition and pointer handler).
 */
class PressGuard {
    private var view: ShownView? = null
    private var firstFrame: Long? = null

    /** view's first frame was produced at frameMillis; a report for a view that is no longer shown is ignored. */
    fun drawn(view: ShownView, frameMillis: Long) {
        if (view != this.view) return
        if (firstFrame == null) firstFrame = frameMillis
    }

    /** The shown view is now view: a new one starts closed, until its first frame and GUARD_MILLIS after it. */
    fun showing(view: ShownView) {
        if (view == this.view) return
        this.view = view
        firstFrame = null
    }

    /** Whether a touch going down at uptimeMillis on view reaches its controls. */
    fun admits(view: ShownView, uptimeMillis: Long): Boolean {
        val frame = firstFrame ?: return false
        return view == this.view && uptimeMillis - frame >= GUARD_MILLIS
    }

    companion object {
        /** How long a new view's controls ignore touches after its first frame (M5-72 (f)). */
        const val GUARD_MILLIS = 300L
    }
}
