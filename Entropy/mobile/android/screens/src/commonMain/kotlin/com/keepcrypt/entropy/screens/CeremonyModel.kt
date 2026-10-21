package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.KcHalt
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Refusal
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Words
import kotlin.concurrent.Volatile
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** What covers the screen without leaving it. */
enum class Overlay {
    /**
     * The privacy cover: 30 s without input on a Protected screen, or the app away from a Public one.
     * The next tap only uncovers it, and the session stays.
     */
    Cover,

    /** The warning a minute before the idle wipe; any tap keeps everything. */
    Warning,
}

/** Why the session was wiped, said on the start screen (the Pi says so too, docs/pi-firmware.md). */
enum class Notice {
    /** The app was left on a Protected screen or during a long call. */
    Left,

    /** Airplane mode went off or Wi-Fi came on. */
    Offline,

    /** 10 minutes without input. */
    Idle,

    /** 60 s away from the app. */
    Background,
}

/**
 * What the screens draw (tasks/todo.md, M5 group 14): the screen's id and page index, and flags about
 * it, never a secret. Screens that show one (commits 19-21) hold Secret references here, which the
 * model wipes when they leave.
 */
data class UiState(
    val screen: Screen,
    val page: Int = 0,
    /** The privacy gate stands before this Protected screen ("I'm alone, show words"). */
    val gate: Boolean = false,
    val overlay: Overlay? = null,
    /** A recording of the screen is reported (Android 15+): Protected screens show a placeholder. */
    val recording: Boolean = false,
    /** Airplane mode on and Wi-Fi off, as the offline monitor last reported. */
    val offline: Boolean = false,
    val notice: Notice? = null,
)

/**
 * The one owner of the slot's use (tasks/todo.md, M5 group 14; the re-plan's CeremonyModel, platform
 * free; docs/mobile-apps.md, "Session lifetime" and "When something fails (Android)"). The platform
 * makes it once, with its seams (lead decision M5-20): the main thread's scope, the worker for long
 * calls (Dispatchers.Default on the phone), the monotonic clock, the offline monitor and the build's
 * testRegistry flag; on Android :app's CeremonyHolder holds it and calls wipeAll at its end. Every
 * method runs on the main thread.
 *
 * - Every core call goes through call, the app's only catch of KcHalt: a halt ends on the stop screen,
 *   which no input leaves; only its "Close app" does, which ends the process.
 * - A long call runs on the worker behind "Working...", which takes no input (work).
 * - Leaving the app during a long call or on a Protected screen, and going online after the start-up
 *   (away from the app too: the offline monitor reports until the model's end), call core's discard
 *   at once, even during a long call; the call's discarded reply then returns the UI to its start
 *   screen. On a Public screen leaving puts the privacy cover up, and 60 s away wipes.
 * - The timers (Timers) cover, warn and wipe on each tick.
 * - Until the start-up self-test passes (core's known-answer tests, a long call, run again on the next
 *   return after a discard), nothing else is offered.
 */
class CeremonyModel(
    private val scope: CoroutineScope,
    private val worker: CoroutineDispatcher,
    clock: MonotonicClock,
    private val offlineMonitor: OfflineMonitor,
    val testRegistry: Boolean,
) {
    private val timers = Timers(clock)
    private val mutable = MutableStateFlow(UiState(Screen.Working))

    /** What the screens draw. */
    val state: StateFlow<UiState> get() = mutable

    /** The start-up self-test has passed. */
    private var started = false

    /** The app is in the foreground (between its return and its leaving; a picker it opened included). */
    private var foreground = false

    /** The slot holds a session: from a start until a discard, a wipe or a halt. */
    private var session = false

    /** The long call running, if any. */
    private var running: Pending? = null

    /** The screen the running long call was started from, which "Working..." stands in for. */
    private var from = Screen.Working

    /** A long call's flag, set on the main thread by a discard and read on the worker before core is called. */
    private class Pending {
        @Volatile
        var discarded = false

        /** The discard's reason, for the start screen. */
        var notice: Notice? = null
    }

    /**
     * The app's activity started. A configuration change, or a picker the app opened, never left the
     * app. Otherwise the background rule comes first (60 s away wipes before anything shows), then the
     * offline monitor reads the state again (a change it could not report away, with the process
     * frozen say, wipes here), and the start-up self-test runs if it has not passed.
     */
    fun appReturned() {
        if (stopped()) return
        if (foreground) {
            timers.returned()
            return
        }
        tick()
        timers.returned()
        foreground = true
        offlineMonitor.start(this::offlineChanged)
        if (!started && running == null) selfTest()
    }

    /**
     * The app's activity stopped, not for a configuration change (SecureActivity's report), and not for
     * a picker the app opened (the picker rule). During a long call and on a Protected screen the
     * session is discarded at once; on a Public screen the privacy cover goes up and the background time
     * starts.
     */
    fun appLeft() {
        if (stopped() || !foreground) return
        if (!timers.left()) return
        foreground = false
        val screen = mutable.value.screen
        if (screen == Screen.Working || isProtected(screen)) {
            discard(Notice.Left)
        } else {
            mutable.value = mutable.value.copy(overlay = Overlay.Cover)
        }
    }

    /**
     * The offline monitor's report (Q57), in the foreground or away. After the start-up, going online
     * while a session is held or a long call runs discards at once, and the start screen says why.
     */
    fun offlineChanged(offline: Boolean) {
        if (stopped()) return
        mutable.value = mutable.value.copy(offline = offline)
        if (offline || !started || (!session && running == null)) return
        discard(Notice.Offline)
    }

    /** A recording of the screen is reported or no longer reported (SecureActivity's, Android 15+). */
    fun recordingChanged(visible: Boolean) {
        mutable.value = mutable.value.copy(recording = visible)
    }

    /**
     * The app opens a picker next, an activity over its own: its stop is no leaving (the picker rule),
     * until the activity's next resume. A permission prompt only pauses the activity and needs none.
     */
    fun pickerOpened() {
        timers.pickerOpened()
    }

    /**
     * The app's activity resumed (SecureActivity's report): the picker rule's exemption ends, so a
     * pickerOpened that no stop followed never makes a later leaving look like a picker.
     */
    fun appResumed() {
        timers.resumed()
    }

    /**
     * A tap anywhere: the idle time starts again. Nothing during a long call or on the stop screen: a
     * press while the app is busy goes no further (docs/pi-firmware.md, "Buttons").
     */
    fun input() {
        if (busy()) return
        timers.input()
    }

    /** The tap that takes the cover or the warning away; it does nothing else. */
    fun dismissOverlay() {
        if (busy()) return
        timers.input()
        mutable.value = mutable.value.copy(overlay = null)
    }

    /** "I'm alone, show words": the Protected screen behind the privacy gate shows. */
    fun passGate() {
        if (busy()) return
        timers.input()
        mutable.value = mutable.value.copy(gate = false)
    }

    /** The timers' step now: the platform calls it each second (runTimers), and every return to the app does. */
    fun tick() {
        if (busy()) return
        val current = mutable.value
        when (timers.step(isProtected(current.screen), session)) {
            TimerStep.BackgroundWipe -> discard(Notice.Background)
            TimerStep.IdleWipe -> discard(Notice.Idle)
            TimerStep.Warn -> {
                if (current.overlay != Overlay.Warning) mutable.value = current.copy(overlay = Overlay.Warning)
            }
            TimerStep.Cover -> {
                if (current.overlay == null) mutable.value = current.copy(overlay = Overlay.Cover)
            }
            null -> {}
        }
    }

    /** The timers, each second, for as long as the platform's scope lives (:app's CeremonyHolder launches it there). */
    suspend fun runTimers() {
        while (true) {
            delay(TICK_MILLIS)
            tick()
        }
    }

    /**
     * The platform's end of the model (the ViewModel's onCleared): everything the slot holds goes, the
     * kept Wiped and a loaded snapshot too, a long call running drops its result, and the offline
     * monitor stops. A halted slot holds nothing already.
     */
    fun wipeAll() {
        running?.discarded = true
        session = false
        call { Core.wipeAll() }
        offlineMonitor.stop()
    }

    /**
     * New seed or Dice-only seed, and every restart, which core takes from the kept Wiped: core's start
     * and its known-answer suite, a long call. The slot then holds a session, under the timers.
     */
    fun start(words: Words, mode: Mode) {
        work({ Core.start(words, mode) }) { session = true }
    }

    /**
     * A long call: core runs on the worker behind "Working...", which takes no input, so the main thread
     * never waits on it. done gets the value on the main thread and may enter the next screen; if it
     * enters none, the screen the call was started from comes back. A refusal goes back to that screen
     * and to refused (by default a halt: a refusal from a call that refuses nothing is the shell's bug).
     * A discard while it runs has called core's discard at once, so the call returns discarded, or is
     * never made if it had not reached core yet; a call that reached core after the discard (a start or
     * the self-test, which core offers at home) has what it made discarded again. Either way the start
     * screen follows. A halt is the stop screen. One long call at a time: a second is the shell's bug,
     * and halts.
     */
    fun <T> work(core: () -> Reply<T>, refused: (Refusal) -> Unit = { halt() }, done: (T) -> Unit) {
        if (running != null || stopped()) {
            halt()
            return
        }
        val pending = Pending()
        running = pending
        from = mutable.value.screen
        show(Screen.Working)
        scope.launch {
            val reply = withContext(worker) {
                if (pending.discarded) Reply.Discarded else call(core)
            }
            if (running === pending) running = null
            if (stopped()) return@launch
            when {
                reply == null -> halted()
                pending.discarded -> {
                    if (reply !is Reply.Discarded && call { Core.discard() } == null) {
                        halted()
                    } else {
                        toStart(pending.notice)
                    }
                }
                else -> when (reply) {
                    is Reply.Done -> {
                        done(reply.value)
                        if (mutable.value.screen == Screen.Working) show(from)
                    }
                    is Reply.Refused -> {
                        show(from)
                        refused(reply.refusal)
                    }
                    Reply.Discarded -> toStart(null)
                }
            }
        }
    }

    /** The start-up self-test: core's known-answer suite, a long call; any reply but Done halts. */
    private fun selfTest() {
        work({ Core.selfTest() }) {
            started = true
            show(home())
        }
    }

    /**
     * Leaving the app, going online or a timer's wipe (Q57): core's discard, at once, even during a long
     * call. The stage and a checked backup go; the kept Wiped and a loaded snapshot stay. With a long
     * call running, "Working..." stays until its reply, then the start screen; otherwise the start
     * screen now, saying why.
     */
    private fun discard(notice: Notice) {
        val pending = running
        if (pending != null) {
            pending.discarded = true
            pending.notice = notice
        }
        session = false
        if (call { Core.discard() } == null) {
            halted()
            return
        }
        if (pending == null) toStart(notice)
    }

    /**
     * The start screen after a discard: until the start-up self-test has passed, "Working..." again and,
     * in the foreground, the self-test again; then the first screen (Go offline from commit 16), saying
     * why the session went.
     */
    private fun toStart(notice: Notice?) {
        if (!started) {
            show(Screen.Working)
            if (foreground) selfTest()
            return
        }
        show(home(), notice = notice)
    }

    /** The screen a ceremony starts from once the self-test has passed. */
    private fun home(): Screen = Screen.FirstLaunch

    /**
     * Shows screen (its page), through the privacy gate when it is Protected and the screen it leaves is
     * not ("Working..." stands for the screen its call came from). Away from the app the privacy cover
     * stays up.
     */
    private fun show(screen: Screen, page: Int = 0, notice: Notice? = null) {
        val current = mutable.value
        val leaving = if (current.screen == Screen.Working) from else current.screen
        mutable.value = UiState(
            screen = screen,
            page = page,
            gate = isProtected(screen) && !isProtected(leaving),
            overlay = if (foreground) null else Overlay.Cover,
            recording = current.recording,
            offline = current.offline,
            notice = notice,
        )
    }

    /** The shell's own bug, failed closed: the slot halts, and the stop screen follows. */
    private fun halt() {
        call<Unit> { Core.halt() }
        halted()
    }

    /**
     * After a halt the slot holds nothing and answers every call with the halt status: the stop screen,
     * which only ends the process. A long call still running has its reply ignored.
     */
    private fun halted() {
        running?.discarded = true
        session = false
        mutable.value = UiState(Screen.Stop, recording = mutable.value.recording)
    }

    private fun stopped(): Boolean = mutable.value.screen == Screen.Stop

    /** A long call runs, or the stop screen shows: input goes no further. */
    private fun busy(): Boolean = stopped() || mutable.value.screen == Screen.Working

    /**
     * Every core call the model makes, short or long, on whichever thread makes it: the app's only
     * catch of KcHalt (the gate allows no other). The halt status is null, for the caller to end on the
     * stop screen on the main thread.
     */
    private fun <T> call(core: () -> Reply<T>): Reply<T>? {
        try {
            return core()
        } catch (halt: KcHalt) {
            return null
        }
    }

    private companion object {
        /** How often the platform's runTimers asks the timers. */
        const val TICK_MILLIS = 1_000L
    }
}
