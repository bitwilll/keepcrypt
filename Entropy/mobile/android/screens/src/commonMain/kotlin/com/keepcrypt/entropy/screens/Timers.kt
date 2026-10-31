package com.keepcrypt.entropy.screens

/** What the timers ask of the ceremony model (the Pi's IdleStep, pi/app/src/input.rs, and the phone's background wipe). */
enum class TimerStep {
    /** Cover the Protected screen; the next tap only uncovers it. */
    Cover,

    /** The idle wipe is a minute away; any tap keeps everything. */
    Warn,

    /** 10 minutes without input: the session is wiped. */
    IdleWipe,

    /** 60 s away from the app on a Public screen: the session is wiped. */
    BackgroundWipe,
}

/**
 * The phone's timers (tasks/todo.md, M5 group 14; Q57; docs/pi-firmware.md, "Protected screens and
 * idle"; docs/mobile-apps.md, "Session lifetime"), on the injected monotonic clock. They keep no thread
 * and schedule nothing: the model asks step on each tick and on every return to the app.
 *
 * - Cover: 30 s without input on a Protected screen.
 * - Warning: 9 minutes without input while a session is held.
 * - Idle wipe: 10 minutes without input while a session is held, and on a Protected screen with
 *   nothing held (as on the Pi, whose collision-report QR shows the kept seal code).
 * - Background wipe: 60 s after the app was left on a Public screen, while a session is held (leaving a
 *   Protected screen discards at once: the model's rule, not a timer's).
 * - The picker rule: a picker the app opened (an activity over its own) stops the app without leaving
 *   it. That time counts as foreground time under the idle rules, and the background time never
 *   starts. The exemption ends at the activity's next resume, so it never outlasts the picker: a
 *   pickerOpened that no stop followed makes no later stop look like one. A permission prompt only
 *   pauses the activity, so it needs no exemption and its time is foreground time anyway.
 *
 * A boundary belongs to the later step: 59.999 s away keeps the session, 60 s wipes it.
 */
class Timers(private val clock: MonotonicClock) {
    private var lastInput = clock.nowMillis()

    /** When the app was left, while it is away; null in the foreground, a picker the app opened included. */
    private var leftAt: Long? = null

    /** A picker the app opened is up (or about to be), until the activity's next resume. */
    private var picker = false

    /** A tap, or any input, in the foreground: the idle time starts again. */
    fun input() {
        lastInput = clock.nowMillis()
    }

    /** The app is about to open a picker, an activity over its own: the stop that follows is no leaving. */
    fun pickerOpened() {
        picker = true
    }

    /**
     * The app's activity stopped, not for a configuration change: true when that is leaving the app,
     * and the background time starts; false while a picker the app opened is up.
     */
    fun left(): Boolean {
        if (picker) return false
        leftAt = clock.nowMillis()
        return true
    }

    /** The app is back (its activity started): the background time ends, and so does a picker. */
    fun returned() {
        leftAt = null
        picker = false
    }

    /**
     * The app's activity resumed: a picker it opened is over, or never stopped the app (a prompt, or a
     * picker that did not open), so the next stop is leaving again.
     */
    fun resumed() {
        picker = false
    }

    /** The step due now on a screen that is Protected or not, while a session is held or not; null for none. */
    fun step(onProtected: Boolean, holdsSecrets: Boolean): TimerStep? {
        val now = clock.nowMillis()
        val idle = now - lastInput
        val left = leftAt
        return when {
            holdsSecrets && left != null && now - left >= BACKGROUND_MILLIS -> TimerStep.BackgroundWipe
            (holdsSecrets || onProtected) && idle >= WIPE_MILLIS -> TimerStep.IdleWipe
            holdsSecrets && idle >= WARN_MILLIS -> TimerStep.Warn
            onProtected && idle >= COVER_MILLIS -> TimerStep.Cover
            else -> null
        }
    }

    companion object {
        /** 30 s without input covers a Protected screen. */
        const val COVER_MILLIS = 30_000L

        /** 9 minutes without input warns. */
        const val WARN_MILLIS = 540_000L

        /** 10 minutes without input wipes. */
        const val WIPE_MILLIS = 600_000L

        /** 60 s away from a Public screen wipes. */
        const val BACKGROUND_MILLIS = 60_000L
    }
}
