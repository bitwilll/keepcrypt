package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.DiceProgress
import com.keepcrypt.entropy.ffi.Extra
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

/** Core refuses a 257th roll by halting, so the dice screen's confirm is disabled at 256 (docs/pi-firmware.md, "Confirmations"). */
const val MAX_ROLLS = 256

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
 * What the screens draw (tasks/todo.md, M5 groups 14 and 15): the screen's id and page index, flags
 * about it, and the public values a screen shows (the dice counts, C), never a secret. Screens that
 * show one (commits 19-21) hold Secret references here, which the model wipes when they leave.
 */
data class UiState(
    val screen: Screen,
    val page: Int = 0,
    /** The privacy gate stands before this Protected screen ("I'm alone, show words"). */
    val gate: Boolean = false,
    val overlay: Overlay? = null,
    /** A recording of the screen is reported (Android 15+): Protected screens show a placeholder. */
    val recording: Boolean = false,
    /** Airplane mode on, as the offline monitor last reported. */
    val airplaneMode: Boolean = false,
    /** Wi-Fi off, as the offline monitor last reported. */
    val wifiOff: Boolean = false,
    val notice: Notice? = null,
    /** The dice screen's counts, core's: the rolls, the minimum and the bits, never a roll. */
    val dice: DiceProgress? = null,
    /** The ceremony is dice-only, which the dice screen says. */
    val diceOnly: Boolean = false,
    /** C on the commitment screen, as 16 groups of 4 hex digits (public). */
    val commitment: String? = null,
) {
    /** Offline (Q57): airplane mode on and Wi-Fi off. */
    val offline: Boolean get() = airplaneMode && wifiOff
}

/**
 * The one owner of the slot's use (tasks/todo.md, M5 groups 14 and 15; the re-plan's CeremonyModel,
 * platform free; docs/mobile-apps.md, "Session lifetime", "When something fails (Android)" and
 * "Screens and user flow"). The platform makes it once, with its seams (lead decision M5-20): the main
 * thread's scope, the worker for long calls (Dispatchers.Default on the phone), the monotonic clock,
 * the offline monitor, the motion source and the build's testRegistry flag; on Android :app's
 * CeremonyHolder holds it and calls wipeAll at its end. Every method runs on the main thread.
 *
 * - Every core call goes through call, the app's only catch of KcHalt: a halt ends on the stop screen,
 *   which no input leaves; only its "Close app" does, which ends the process.
 * - A long call runs on the worker behind "Working..." (the start-up self-test behind its own
 *   screen), which takes no input (work).
 * - Leaving the app during a long call or on a Protected screen, and going online after the start-up
 *   (away from the app too: the offline monitor reports until the model's end), call core's discard
 *   at once, even during a long call; the call's discarded reply then returns the UI to its start
 *   screen, Go offline. On a Public screen leaving puts the privacy cover up, and 60 s away wipes.
 * - The timers (Timers) cover, warn and wipe on each tick.
 * - Until the start-up self-test passes (core's known-answer tests, a long call, run again on the next
 *   return after a discard), nothing else is offered. Then, on every start: First launch, Go offline
 *   (its Start only offline), Home, Length, and the ceremony, which needs airplane mode on and Wi-Fi
 *   off on every screen from Home on (Q57): Device entropy and Commitment in Mixed mode only, then
 *   Dice. System Back goes back only where nothing is lost (back).
 */
class CeremonyModel(
    private val scope: CoroutineScope,
    private val worker: CoroutineDispatcher,
    private val clock: MonotonicClock,
    private val offlineMonitor: OfflineMonitor,
    private val motion: MotionSource,
    val testRegistry: Boolean,
) {
    private val timers = Timers(clock)
    private val mutable = MutableStateFlow(UiState(Screen.SelfTest))

    /** What the screens draw. */
    val state: StateFlow<UiState> get() = mutable

    /**
     * The dice pad's pick (rule 5: a PadEntry, never a String): the dice screen's pad writes the face
     * into it, confirmRoll pushes it to core, and it is wiped when the dice screen leaves.
     */
    val dicePick: PadEntry = dicePadEntry()

    /** The start-up self-test has passed. */
    private var started = false

    /** The app is in the foreground (between its return and its leaving; a picker it opened included). */
    private var foreground = false

    /** The slot holds a session: from a start until a discard, a wipe or a halt. */
    private var session = false

    /** The long call running, if any. */
    private var running: Pending? = null

    /** The state the running long call was started from (screen, page, public values); its screen stands in for it. */
    private var from = UiState(Screen.SelfTest)

    /** The ceremony's mode: Home's choice (New seed is Mixed), kept by start for its screens. */
    private var mode = Mode.Mixed

    /** A long call's flag, set on the main thread by a discard and read on the worker before and after core's call. */
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
        if (isWorking(screen) || isProtected(screen)) {
            discard(Notice.Left)
        } else {
            mutable.value = mutable.value.copy(overlay = Overlay.Cover)
        }
    }

    /**
     * The offline monitor's report (Q57), in the foreground or away. After the start-up, going online
     * while a session is held or a long call runs discards at once, and the start screen, Go offline,
     * says why; on a screen past Go offline with nothing held, Go offline comes back, with nothing to
     * say. Before the start-up self-test passes, and on First launch and Go offline, only the state
     * changes.
     */
    fun offlineChanged(airplaneMode: Boolean, wifiOff: Boolean) {
        if (stopped()) return
        val current = mutable.value.copy(airplaneMode = airplaneMode, wifiOff = wifiOff)
        mutable.value = current
        if (current.offline || !started) return
        if (session || running != null) {
            discard(Notice.Offline)
        } else if (needsOffline(current.screen)) {
            show(Screen.GoOffline)
        }
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

    /**
     * A touch anywhere, with the event's uptime in milliseconds (the screens' pointer handler): on
     * Device entropy that time, and the clock's nanoseconds as it arrives, go into the pool with no
     * credit (docs/mobile-apps.md, "Touch and button timing"); anywhere else, nothing.
     */
    fun touched(uptimeMillis: Long) {
        if (!collecting()) return
        val timing = ByteArray(16)
        putLong(timing, 0, uptimeMillis)
        putLong(timing, 8, clock.nowNanos())
        extra(Extra.InputTiming, timing)
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

    /**
     * The system Back (the platform's): back to the screen before only where nothing is lost, as the
     * Pi's KEY1 (Length to Home, Home to Go offline, Go offline to First launch); anywhere else it does
     * nothing, so it never ends a session, leaves a long call or leaves the app.
     */
    fun back() {
        val screen = mutable.value.screen
        val previous = backTo(screen) ?: return
        if (pressOn(screen)) show(previous)
    }

    /** First launch's Continue: Go offline. */
    fun firstLaunchDone() {
        if (pressOn(Screen.FirstLaunch)) show(Screen.GoOffline)
    }

    /** Go offline's Start: Home, only offline (online its button is disabled, and a press does nothing). */
    fun startOffline() {
        if (mutable.value.offline && pressOn(Screen.GoOffline)) show(Screen.Home)
    }

    /** Home's New seed (Mixed) or Dice-only seed: Length. */
    fun chooseMode(mode: Mode) {
        if (!pressOn(Screen.Home)) return
        this.mode = mode
        show(Screen.Length)
    }

    /** Length's 12 or 24 words: the ceremony starts, in Home's mode. */
    fun chooseLength(words: Words) {
        if (pressOn(Screen.Length)) start(words, mode)
    }

    /**
     * Device entropy's Continue: the commitment, which reads the phone's random source and fixes D
     * (no extra reaches the pool after it), then Commitment with C.
     */
    fun deviceEntropyDone() {
        if (!pressOn(Screen.DeviceEntropy) || !short { Core.commit() }) return
        val reply = done { Core.commitment() } ?: return
        val commitment = reply.value
        if (commitment == null) {
            halt()
            return
        }
        show(Screen.Commitment, commitment = hexGroups(commitment))
    }

    /** Commitment's Continue: the dice. */
    fun commitmentDone() {
        if (pressOn(Screen.Commitment) && short { Core.startDice() }) showDice()
    }

    /**
     * The dice screen's confirm: the face picked on the pad is pushed to core and the pick is wiped. It
     * does nothing with no face picked or at 256 rolls, where its button is disabled. The face is read
     * from the pick as a number, with no copy of the pick's bytes, so the pick's wipe leaves none (rule 5).
     */
    fun confirmRoll() {
        if (!pressOn(Screen.Dice)) return
        val dice = mutable.value.dice ?: return
        if (dicePick.length != 1 || dice.rolls >= MAX_ROLLS) return
        val face = dicePick.keyAt(0) - '0'
        dicePick.wipe()
        if (short { Core.pushRoll(face) }) showDice()
    }

    /** The dice screen's undo: the last roll goes (the pick stays); nothing with no roll. */
    fun undoRoll() {
        if (!pressOn(Screen.Dice)) return
        val dice = mutable.value.dice ?: return
        if (dice.rolls > 0 && short { Core.undoRoll() }) showDice()
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
     * kept Wiped and a loaded snapshot too, a long call running drops its result, the dice pad's pick
     * is wiped, and the motion source and the offline monitor stop. A halted slot holds nothing already.
     */
    fun wipeAll() {
        running?.discarded = true
        session = false
        call { Core.wipeAll() }
        dicePick.wipe()
        motion.stop()
        offlineMonitor.stop()
    }

    /**
     * New seed or Dice-only seed, from Length, and every restart, which core takes from the kept Wiped:
     * core's start and its known-answer suite, a long call. The slot then holds a session, under the
     * timers: Mixed mode goes on to Device entropy; dice-only mode commits and opens the dice at once,
     * skipping Device entropy and Commitment (it has no device leg and no C).
     */
    fun start(words: Words, mode: Mode) {
        this.mode = mode
        work({ Core.start(words, mode) }) {
            session = true
            when (mode) {
                Mode.Mixed -> show(Screen.DeviceEntropy)
                Mode.DiceOnly -> if (short { Core.commit() } && short { Core.startDice() }) showDice()
            }
        }
    }

    /**
     * A long call: core runs on the worker behind busy ("Working...", or the start-up self-test's
     * screen), which takes no input, so the main thread never waits on it. done gets the value on the
     * main thread and may enter the next screen; if it enters none, the screen the call was started
     * from comes back as it was. A refusal goes back to that screen and to refused (by default a halt:
     * a refusal from a call that refuses nothing is the shell's bug). A discard while it runs has called
     * core's discard at once, so the call returns discarded, or is never made if it had not reached core
     * yet; a call that reached core after the discard (a start or the self-test, which core offers at home)
     * has what it made discarded again on the worker (onWorker). Either way the start screen follows.
     * A halt is the stop screen. One long call at a time: a second is the shell's bug, and halts, as
     * does a busy screen that takes input.
     */
    fun <T> work(
        core: () -> Reply<T>,
        busy: Screen = Screen.Working,
        refused: (Refusal) -> Unit = { halt() },
        done: (T) -> Unit,
    ) {
        if (running != null || stopped() || !isWorking(busy)) {
            halt()
            return
        }
        val pending = Pending()
        running = pending
        from = mutable.value
        show(busy)
        scope.launch {
            val reply = withContext(worker) { onWorker(pending, core) }
            if (running === pending) running = null
            if (stopped()) return@launch
            when {
                reply == null -> halted()
                pending.discarded -> toStart(pending.notice)
                else -> when (reply) {
                    is Reply.Done -> {
                        done(reply.value)
                        if (mutable.value.screen == busy) showFrom()
                    }
                    is Reply.Refused -> {
                        showFrom()
                        refused(reply.refusal)
                    }
                    Reply.Discarded -> toStart(null)
                }
            }
        }
    }

    /**
     * A long call's part on the worker. A discard that came first means no call at all. A call that
     * reached core after a discard (or after wipeAll) has what it made discarded again here, on the
     * worker, before its reply goes back: a cancelled scope (the holder's end, which cancels it before
     * wipeAll) drops the reply on the main thread but cannot skip this. A discard that came after this
     * look found the call done in core, so its own core discard took what the call made. Null is the
     * halt status.
     */
    private fun <T> onWorker(pending: Pending, core: () -> Reply<T>): Reply<T>? {
        if (pending.discarded) return Reply.Discarded
        val reply = call(core) ?: return null
        if (reply is Reply.Discarded || !pending.discarded) return reply
        return if (call { Core.discard() } == null) null else Reply.Discarded
    }

    /** The start-up self-test: core's known-answer suite, a long call behind its own screen; any reply but Done halts. */
    private fun selfTest() {
        work({ Core.selfTest() }, busy = Screen.SelfTest) {
            started = true
            show(Screen.FirstLaunch)
        }
    }

    /**
     * Leaving the app, going online or a timer's wipe (Q57): core's discard, at once, even during a long
     * call. The stage and a checked backup go; the kept Wiped and a loaded snapshot stay. With a long
     * call running, its screen stays until its reply, then the start screen; otherwise the start
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
     * The start screen after a discard: until the start-up self-test has passed, its screen again and,
     * in the foreground, the self-test again; then Go offline, saying why the session went.
     */
    private fun toStart(notice: Notice?) {
        if (!started) {
            show(Screen.SelfTest)
            if (foreground) selfTest()
            return
        }
        show(Screen.GoOffline, notice = notice)
    }

    /** The state a long call came from, as it was (its page and public values), when the call entered no other screen. */
    private fun showFrom() {
        val previous = from
        show(previous.screen, previous.page, dice = previous.dice, commitment = previous.commitment)
    }

    /** The dice screen with core's counts now. */
    private fun showDice() {
        val progress = done { Core.diceProgress() } ?: return
        show(Screen.Dice, dice = progress.value)
    }

    /**
     * Shows screen (its page and public values), through the privacy gate when it is Protected and the
     * screen it leaves is not (a long call's screen stands for the screen its call came from). Away
     * from the app the privacy cover stays up.
     */
    private fun show(
        screen: Screen,
        page: Int = 0,
        notice: Notice? = null,
        dice: DiceProgress? = null,
        commitment: String? = null,
    ) {
        val current = mutable.value
        val leaving = if (isWorking(current.screen)) from.screen else current.screen
        enter(
            UiState(
                screen = screen,
                page = page,
                gate = isProtected(screen) && !isProtected(leaving),
                overlay = if (foreground) null else Overlay.Cover,
                recording = current.recording,
                airplaneMode = current.airplaneMode,
                wifiOff = current.wifiOff,
                notice = notice,
                dice = dice,
                diceOnly = mode == Mode.DiceOnly,
                commitment = commitment,
            ),
        )
    }

    /**
     * The next state, and the seams a screen holds while it shows: the motion source runs only on
     * Device entropy, and the dice pad's pick is wiped when the dice screen leaves.
     */
    private fun enter(next: UiState) {
        val before = mutable.value.screen
        mutable.value = next
        if (next.screen == before) return
        if (before == Screen.DeviceEntropy) motion.stop()
        if (before == Screen.Dice) dicePick.wipe()
        if (next.screen == Screen.DeviceEntropy) motion.start(this::motionSample)
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
        enter(UiState(Screen.Stop, recording = mutable.value.recording))
    }

    private fun stopped(): Boolean = mutable.value.screen == Screen.Stop

    /** A long call runs, or the stop screen shows: input goes no further. */
    private fun busy(): Boolean = stopped() || isWorking(mutable.value.screen)

    /**
     * A press on screen's control reaches the model only while that screen shows, uncovered and past
     * any privacy gate, with no long call running (a press left over from a screen that has gone does
     * nothing); it is input for the idle timer.
     */
    private fun pressOn(screen: Screen): Boolean {
        val current = mutable.value
        if (busy() || current.screen != screen || current.overlay != null || current.gate) return false
        timers.input()
        return true
    }

    /** Where Back goes from screen: only where nothing is lost, before any session; null elsewhere. */
    private fun backTo(screen: Screen): Screen? = when (screen) {
        Screen.GoOffline -> Screen.FirstLaunch
        Screen.Home -> Screen.GoOffline
        Screen.Length -> Screen.Home
        Screen.SelfTest, Screen.FirstLaunch, Screen.DeviceEntropy, Screen.Commitment, Screen.Dice, Screen.Working,
        Screen.Stop -> null
    }

    /** Whether screen needs airplane mode on and Wi-Fi off (Q57): every screen from Home on. */
    private fun needsOffline(screen: Screen): Boolean = when (screen) {
        Screen.SelfTest, Screen.FirstLaunch, Screen.GoOffline, Screen.Working, Screen.Stop -> false
        Screen.Home, Screen.Length, Screen.DeviceEntropy, Screen.Commitment, Screen.Dice -> true
    }

    /** The slot is collecting and Device entropy shows: extras go into the pool (until the commitment). */
    private fun collecting(): Boolean = session && running == null && mutable.value.screen == Screen.DeviceEntropy

    /** A motion sample from the motion source: into the pool while collecting; zeroed either way. */
    private fun motionSample(sample: ByteArray) {
        if (collecting()) extra(Extra.Motion, sample) else sample.fill(0)
    }

    /** An uncredited extra into the pool; its bytes are zeroed once core has them (rule 5), and never logged. */
    private fun extra(source: Extra, bytes: ByteArray) {
        val reply = call { Core.addExtra(source, bytes) }
        bytes.fill(0)
        settle(reply)
    }

    /** A short call on the main thread that must be done: true when it was; anything else halts (false). */
    private fun short(core: () -> Reply<Unit>): Boolean = settle(call(core))

    /** A short call's Done reply; null once anything else has halted. */
    private fun <T> done(core: () -> Reply<T>): Reply.Done<T>? {
        val reply = call(core)
        if (reply is Reply.Done) return reply
        settle(reply)
        return null
    }

    /**
     * What a short call's reply leads to: true for Done. The halt status (null) ends on the stop screen,
     * and a refusal or a discard, which no short call the screens make can give, is the shell's bug and
     * halts; false for both.
     */
    private fun settle(reply: Reply<*>?): Boolean {
        when (reply) {
            is Reply.Done -> return true
            null -> halted()
            else -> halt()
        }
        return false
    }

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

/** value's eight bytes, big-endian, into bytes from at. */
private fun putLong(bytes: ByteArray, at: Int, value: Long) {
    for (index in 0 until 8) bytes[at + index] = (value ushr (56 - 8 * index)).toByte()
}
