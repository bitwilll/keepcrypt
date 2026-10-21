package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.DiceProgress
import com.keepcrypt.entropy.ffi.Extra
import com.keepcrypt.entropy.ffi.KcHalt
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.QrMatrix
import com.keepcrypt.entropy.ffi.Refusal
import com.keepcrypt.entropy.ffi.RefusalGroup
import com.keepcrypt.entropy.ffi.RegistryHeader
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Revealed
import com.keepcrypt.entropy.ffi.SealCard
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
 * What the screens draw (tasks/todo.md, M5 groups 14, 15 and 16; lead decision M5-49): the screen's
 * id and page index, flags about it, and the public values a screen shows (the dice counts, C, the
 * seal card, the check QR, a snapshot's or proof's header, why a scan stopped), never a secret but
 * through a Secret reference: the QR codes are QrMatrix, whose bits a Secret holds, and the model
 * wipes each one when no screen holds it any more (the collision report's carries the destroyed
 * seed's seal code). The words and the rest (commits 19-21) hold theirs the same way.
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
    /**
     * The seal card (public), from Check now on and never on the prompt (lead decision M5-55): on the
     * seal card and the check's screens after it, drawn on the collision result (the destroyed seed's),
     * and its Seal ID named by the check result's text.
     */
    val seal: SealCard? = null,
    /**
     * The seal card's check QR (T and the check's nonce, public), from Check now until the check ends:
     * the code entry and the confirm screens keep it too, so their Back finds the same check and nonce.
     */
    val checkRequest: QrMatrix? = null,
    /** The collision-report QR (Protected: the destroyed seed's seal code), wiped when its screen leaves. */
    val report: QrMatrix? = null,
    /**
     * The header the check ran against: the loaded snapshot's (its number, date, count of seals and
     * freshness), or a scanned go-ahead QR's proof's (proof).
     */
    val registry: RegistryHeader? = null,
    /**
     * The registry header is a scanned go-ahead QR's proof, not a loaded snapshot's (lead decision
     * M5-55): its count is the entries in this seal's bucket, which the result says, never a snapshot's
     * total of seals.
     */
    val proof: Boolean = false,
    /** The words came by Skip, with no check: the result says the seal can be checked later. */
    val skipped: Boolean = false,
    /** The typed go-ahead code was refused: the code entry says so, and the check, its nonce and actions stay. */
    val codeRefused: Boolean = false,
    /** The scan screen's scanner stopped without a code (the camera refused, missing or failed): it says why and scans no more. */
    val scanStop: ScanStop? = null,
    /**
     * Core refused the scanned QR's text (no registry key in this build, no go-ahead QR, another seal's
     * bucket): the scan screen says so and scans no more, and the check, its nonce and actions stay.
     */
    val scanRefusal: Refusal? = null,
) {
    /** Offline (Q57): airplane mode on and Wi-Fi off. */
    val offline: Boolean get() = airplaneMode && wifiOff
}

/**
 * The one owner of the slot's use (tasks/todo.md, M5 groups 14-16; the re-plan's CeremonyModel,
 * platform free; docs/mobile-apps.md, "Session lifetime", "When something fails (Android)" and
 * "Screens and user flow"). The platform makes it once, with its seams (lead decision M5-20): the main
 * thread's scope, the worker for long calls (Dispatchers.Default on the phone), the monotonic clock,
 * the UTC date, the offline monitor, the motion source and the build's testRegistry flag; on Android
 * :app's CeremonyHolder holds it and calls wipeAll at its end. Every method runs on the main thread.
 *
 * - Every core call goes through call, the app's only catch of KcHalt: a halt ends on the stop screen,
 *   which no input leaves; only its "Close app" does, which ends the process.
 * - A long call runs on the worker behind "Working..." (the start-up self-test behind its own
 *   screen), which takes no input (work).
 * - Leaving the app during a long call or on a Protected screen, and going online after the start-up
 *   (away from the app too: the offline monitor reports until the model's end), call core's discard
 *   at once, even during a long call; the call's discarded reply then returns the UI to its start
 *   screen (toStart). That start screen is certain for the long calls core offers at home, start and
 *   the self-test; finish, revealProof (the scanned go-ahead QR's check, commit 18) and encryptBackup
 *   (the backup's, commit 20), which it does not offer there, halt the slot instead when a discard
 *   reaches core between the worker's look at the discard flag and the call (fail closed: the stop
 *   screen; lead decision M5-54's residual, work). On a Public screen leaving puts the privacy cover
 *   up, and 60 s away wipes.
 * - The timers (Timers) cover, warn and wipe on each tick.
 * - On every start First launch shows first, before any core call (lead decision M5-50); its Continue
 *   runs the start-up self-test (core's known-answer tests, a long call behind its own screen; any
 *   reply but Done halts), then Go offline (its Start only offline), Home, Length, and the ceremony,
 *   which needs airplane mode on and Wi-Fi off on every screen from Home on (Q57): Device entropy and
 *   Commitment in Mixed mode only, then Dice. A discard that hits the self-test returns to First
 *   launch, whose Continue runs it again; once it has passed, a discard's start screen is Go offline.
 *   System Back goes back only where nothing is lost (back).
 * - The dice's Done makes the seed, and the collision check follows (group 16; docs/mobile-apps.md,
 *   step 9; docs/seal-watchonly-braille.md, "Checking the seal"): the prompt, which shows no seal
 *   (the Seal ID shows from Check now on, lead decision M5-55) and whose Skip is confirmed on its own
 *   screen; Check now, which with a loaded snapshot runs the check against it at once (a short call
 *   on the main thread, lead decision M5-54), and otherwise shows the seal card with its check QR and
 *   the checker's answers, the scanned go-ahead QR (the scan screen, commit 18: its text is checked on
 *   the worker behind "Working..."), the typed go-ahead code, Match found and Cannot check (each one-way
 *   choice confirmed on its own screen). A wrong code, or a scanned QR core does not accept, is
 *   refused and the check stays, with its nonce. The check result names the Seal ID, and the
 *   collision result draws the destroyed seed's seal; after a scanned QR both say how many entries
 *   the seal's bucket holds, never a snapshot's total (lead decision M5-55). Match found wipes the seed
 *   unseen, then the collision-report QR (Protected) and "Add fresh entropy"; Cannot check wipes it and
 *   starts again. Both restarts are core's start from the kept Wiped, with the destroyed session's
 *   length and mode, so core sets the minimum (99 rolls after a collision).
 */
class CeremonyModel(
    private val scope: CoroutineScope,
    private val worker: CoroutineDispatcher,
    private val clock: MonotonicClock,
    private val date: UtcDate,
    private val offlineMonitor: OfflineMonitor,
    private val motion: MotionSource,
    val testRegistry: Boolean,
) {
    private val timers = Timers(clock)
    private val mutable = MutableStateFlow(UiState(Screen.FirstLaunch))

    /** What the screens draw. */
    val state: StateFlow<UiState> get() = mutable

    /**
     * The dice pad's pick (rule 5: a PadEntry, never a String): the dice screen's pad writes the face
     * into it, confirmRoll pushes it to core, and it is wiped when the dice screen leaves.
     */
    val dicePick: PadEntry = dicePadEntry()

    /**
     * The go-ahead code as the code entry's Crockford pad types it (a Public screen: the code is no
     * secret, but a pad writes into a PadEntry): codeDone hands it to core, and it is wiped when the
     * code entry leaves.
     */
    val goAheadCode: PadEntry = crockfordPadEntry()

    /** The start-up self-test (First launch's Continue) has passed. */
    private var started = false

    /** The app is in the foreground (between its return and its leaving; a picker it opened included). */
    private var foreground = false

    /**
     * The slot holds a session, or waits at its restart after a check that ended without the words
     * (Match found, Cannot check or a collision, with the kept Wiped and, after a collision, its report):
     * from a start until a discard, a wipe or a halt. The timers and going online treat both alike, and
     * a discard takes the slot home either way, keeping the Wiped (the 99-roll minimum stays).
     */
    private var session = false

    /** The long call running, if any. */
    private var running: Pending? = null

    /** The state the running long call was started from (screen, page, public values); its screen stands in for it. */
    private var from = UiState(Screen.FirstLaunch)

    /** The ceremony's mode: Home's choice (New seed is Mixed), kept by start for its screens and the restarts. */
    private var mode = Mode.Mixed

    /** The ceremony's length: Length's choice, kept by start for the restarts ("Add fresh entropy", "Start again"). */
    private var words = Words.Twelve

    /**
     * The loaded registry snapshot's header (snapshotLoaded): while the slot holds that snapshot, Check
     * now runs the check against it on its own. It outlives sessions and discards, as the slot's does,
     * and goes with wipeAll.
     */
    private var snapshot: RegistryHeader? = null

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
     * frozen say, wipes here). It never runs the start-up self-test: First launch's Continue does
     * (firstLaunchDone).
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

    /** The privacy gate's "I'm alone, show words": the Protected screen behind it shows. */
    fun passGate() {
        if (busy()) return
        timers.input()
        mutable.value = mutable.value.copy(gate = false)
    }

    /**
     * The system Back (the platform's), and the Back button of the scan screen, the code entry and each
     * one-way choice's confirm screen: back to the screen before only where nothing is lost, as the Pi's
     * KEY1 and KEY2 (Length to Home, Home to Go offline, Go offline to First launch; Skip's confirm to
     * the check prompt; the scan screen, Match found's and Cannot check's confirms and the code entry to
     * the seal card, with the same check and nonce and no core call, the typed code wiped); anywhere
     * else it does nothing, so it never ends a session, leaves a check or a long call, or leaves the app.
     */
    fun back() {
        val current = mutable.value
        val previous = backTo(current.screen) ?: return
        if (pressOn(current.screen)) show(previous, seal = current.seal, checkRequest = current.checkRequest)
    }

    /**
     * First launch's Continue: the start-up self-test behind its own screen, then Go offline (MA:170-172).
     * Once it has passed (First launch again by Back from Go offline), Go offline at once.
     */
    fun firstLaunchDone() {
        if (!pressOn(Screen.FirstLaunch)) return
        if (started) show(Screen.GoOffline) else selfTest()
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

    /**
     * The dice screen's Done, once the minimum is met (below it its button is disabled, and a press
     * does nothing; core would halt): core makes the seed (finish, a long call behind "Working..."),
     * then the check prompt, which shows no seal (lead decisions M5-48 and M5-55).
     */
    fun diceDone() {
        if (!pressOn(Screen.Dice)) return
        val dice = mutable.value.dice ?: return
        if (dice.rolls < dice.minimum) return
        work({ Core.finish() }) { show(Screen.CheckPrompt) }
    }

    /**
     * Load registry snapshot's result: the slot holds the snapshot core verified (Core.loadSnapshot),
     * whose header this is, so Check now runs the check against it on its own (docs/mobile-apps.md,
     * step 9). Commit 21's Load registry snapshot screen calls it after its load (lead decision M5-48);
     * until then only the tests do, after their own Core.loadSnapshot in the test-registry APK.
     */
    fun snapshotLoaded(header: RegistryHeader) {
        if (!stopped()) snapshot = header
    }

    /**
     * The prompt's "Check now (recommended)": the check starts (core draws its nonce), and from here
     * only a verified go-ahead reaches the words; the seal, which the prompt never shows, shows from
     * here on (lead decision M5-55). With a loaded snapshot the check runs against it at once, on
     * today's UTC date (the result warns of a Stale or Future snapshot), as a short call on the main
     * thread, since the FFI runs it under its lock as one (it only looks the seal up in the loaded
     * snapshot): no busy screen comes before its result, and no discard can land between a look at a
     * discard flag and the call (lead decision M5-54). Otherwise the seal card shows, with the check QR.
     */
    fun checkNow() {
        if (!pressOn(Screen.CheckPrompt) || !short { Core.startCheck() }) return
        val seal = done { Core.seal() } ?: return
        if (snapshot != null) {
            val revealed = done { Core.revealSnapshot(date.today()) } ?: return
            ended(revealed.value, seal.value)
            return
        }
        val request = done { Core.checkRequest() } ?: return
        show(Screen.SealCard, seal = seal.value, checkRequest = request.value)
    }

    /** The prompt's Skip: its confirm screen, since Skip is offered only before a check starts (rule 6). */
    fun skip() {
        if (pressOn(Screen.CheckPrompt)) show(Screen.SkipConfirm)
    }

    /**
     * Skip's confirm: the words with no check, and a result that says the seal can be checked later
     * (it names no seal: the Seal ID shows from Check now on, lead decision M5-55).
     */
    fun skipConfirmed() {
        if (pressOn(Screen.SkipConfirm) && short { Core.skipCheck() }) show(Screen.CheckResult, skipped = true)
    }

    /**
     * The seal card's "Scan go-ahead QR": the scan screen, with the same check and nonce. Its scanner
     * (the platform's) asks for the camera as the screen opens and hands its first text to
     * onGoAheadText; a stop without a code comes to scanStopped.
     */
    fun scanQr() {
        if (pressOn(Screen.SealCard)) showInCheck(Screen.Scan)
    }

    /** The seal card's or the scan screen's "Type go-ahead code": the code entry, its pad empty. */
    fun typeCode() {
        if (pressOn(Screen.SealCard) || pressOn(Screen.Scan)) showInCheck(Screen.CodeEntry)
    }

    /**
     * The scan screen's text: the first QR code its scanner read (the emulator tests, whose emulators
     * have no camera, hand the drill's texts in here, as the scanner would; a text over 4,296
     * characters never comes, the scanner drops it, swb:144). Core checks it as this check's go-ahead
     * QR on today's UTC date, a long call behind "Working..." (the proof's known-answer tests, its
     * signature and Merkle path), then judges it: the words are available, or the seed is wiped unseen
     * on a collision, and the result shows the proof's snapshot date, the entries in this seal's bucket
     * and any freshness warning (lead decision M5-55). A text core refuses (no registry key in this
     * build, no go-ahead QR, another seal's bucket) returns to the scan screen, which says so and scans
     * no more; the check, its nonce, "Type go-ahead code" and Back stay.
     */
    fun onGoAheadText(text: String) {
        if (!pressOn(Screen.Scan)) return
        val seal = mutable.value.seal
        work({ Core.revealProof(date.today(), text) }, refused = { showInCheck(Screen.Scan, scanRefusal = it) }) {
            ended(it, seal, proof = true)
        }
    }

    /**
     * The scan screen's scanner stopped without a code (the camera refused, missing or failed): the
     * screen says why and scans no more; anywhere else, or after a stop already said, nothing.
     */
    fun scanStopped(why: ScanStop) {
        val current = mutable.value
        if (busy() || current.screen != Screen.Scan || current.scanStop != null) return
        mutable.value = current.copy(scanStop = why)
    }

    /** The seal card's "Match found": its confirm screen. */
    fun matchFound() {
        if (pressOn(Screen.SealCard)) showInCheck(Screen.MatchFoundConfirm)
    }

    /** The seal card's "Cannot check": its confirm screen. */
    fun cannotCheck() {
        if (pressOn(Screen.SealCard)) showInCheck(Screen.CannotCheckConfirm)
    }

    /**
     * The code entry's Done, with all 8 symbols typed: core verifies the code against this check's T
     * and nonce. A verified one reveals the words; one that does not verify is refused, and the code
     * entry says so with the check, its nonce and the seal card's actions kept (its Back), the typed
     * code wiped. The code is handed over as a Secret and wiped once core has it.
     */
    fun codeDone() {
        if (!pressOn(Screen.CodeEntry) || !goAheadCode.isFull) return
        val seal = mutable.value.seal
        val code = goAheadCode.take()
        val reply = call { Core.revealCode(code) }
        code.wipe()
        when {
            reply is Reply.Done -> ended(reply.value, seal)
            reply is Reply.Refused && reply.refusal.group == RefusalGroup.Code -> showInCheck(Screen.CodeEntry, codeRefused = true)
            else -> settle(reply)
        }
    }

    /**
     * Match found's confirm, "Destroy this seed": the seed is wiped unseen, then the collision result,
     * which draws its seal (the confirm screen's, kept from the seal card).
     */
    fun matchFoundConfirmed() {
        val seal = mutable.value.seal
        if (pressOn(Screen.MatchFoundConfirm) && short { Core.matchFound() }) show(Screen.Collision, seal = seal)
    }

    /**
     * Cannot check's confirm, "Start again": the seed is wiped unseen and a new ceremony starts from the
     * kept Wiped (the normal minimum, or 99 rolls when this session was itself the restart after a
     * collision).
     */
    fun cannotCheckConfirmed() {
        if (pressOn(Screen.CannotCheckConfirm) && short { Core.cannotCheck() }) start(words, mode)
    }

    /** The collision result's "Show the collision report": its QR, a Protected screen behind the privacy gate. */
    fun showReport() {
        if (!pressOn(Screen.Collision)) return
        val report = done { Core.collisionReport() } ?: return
        show(Screen.CollisionReport, report = report.value)
    }

    /** "Add fresh entropy", past the report's gate: a new ceremony from the kept Wiped, at least 99 rolls. */
    fun addFreshEntropy() {
        if (pressOn(Screen.CollisionReport)) start(words, mode)
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
     * kept Wiped and a loaded snapshot too, a long call running drops its result, the pads' entries and
     * the QR codes on show are wiped, and the motion source and the offline monitor stop. A halted slot
     * holds nothing already.
     */
    fun wipeAll() {
        running?.discarded = true
        session = false
        snapshot = null
        call { Core.wipeAll() }
        dicePick.wipe()
        goAheadCode.wipe()
        val current = mutable.value
        current.checkRequest?.wipe()
        current.report?.wipe()
        motion.stop()
        offlineMonitor.stop()
    }

    /**
     * New seed or Dice-only seed, from Length, and every restart ("Add fresh entropy", "Start again",
     * with the destroyed session's length and mode), which core takes from the kept Wiped: core's start
     * and its known-answer suite, a long call. The slot then holds a session, under the timers: Mixed
     * mode goes on to Device entropy; dice-only mode commits and opens the dice at once, skipping
     * Device entropy and Commitment (it has no device leg and no C).
     */
    fun start(words: Words, mode: Mode) {
        this.words = words
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
     * core's discard at once, so the call returns discarded, or is never made when the worker sees the
     * discard first; either way the start screen follows. A discard that lands between the worker's
     * look at the flag and the call reaches core before the call does (onWorker), and what follows
     * depends on the call (lead decision M5-54): a start or the self-test, which core offers at home,
     * runs, what it made is discarded again on the worker, and the start screen follows; finish,
     * revealProof (the scanned go-ahead QR's check) and encryptBackup (the backup's, commit 20), which
     * core does not offer at home, halt the slot (fail closed: the stop screen instead of the start
     * screen, in a window of microseconds; M5-54's residual). A halt is the stop screen. One long call
     * at a time: a second is the shell's bug, and halts, as does a busy screen that takes input. The
     * busy screen keeps the QR codes of the screen it stands for (drawing none), so that screen comes
     * back with them whole; the next other screen wipes them.
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
        show(busy, checkRequest = from.checkRequest, report = from.report)
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
     * A long call's part on the worker, which looks at the discard flag before the call and again after
     * it. A discard (or wipeAll) before the first look means no call at all. One between the first look
     * and the call reaches core first (lead decision M5-54): a start or the self-test, which core offers
     * at home, then runs, and the second look finds the flag, so what it made is discarded again here,
     * on the worker, before its reply goes back (a cancelled scope, the holder's end, which cancels it
     * before wipeAll, drops the reply on the main thread but cannot skip this); finish, revealProof and
     * encryptBackup, which core does not offer at home, halt the slot there, and their reply is the halt
     * status (M5-54's residual: the stop screen, fail closed). A discard during the call makes core
     * return discarded, and one after the second look found the call done in core, so its own core
     * discard took what the call made. Null is the halt status.
     */
    private fun <T> onWorker(pending: Pending, core: () -> Reply<T>): Reply<T>? {
        if (pending.discarded) return Reply.Discarded
        val reply = call(core) ?: return null
        if (reply is Reply.Discarded || !pending.discarded) return reply
        return if (call { Core.discard() } == null) null else Reply.Discarded
    }

    /**
     * The start-up self-test, from First launch's Continue: core's known-answer suite, a long call behind
     * its own screen, then Go offline; any reply but Done halts.
     */
    private fun selfTest() {
        work({ Core.selfTest() }, busy = Screen.SelfTest) {
            started = true
            show(Screen.GoOffline)
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
     * The start screen after a discard: until the start-up self-test has passed (a discard that hit it),
     * First launch, whose Continue runs it again, with nothing to say (no session was held); then Go
     * offline, saying why the session went.
     */
    private fun toStart(notice: Notice?) {
        if (!started) {
            show(Screen.FirstLaunch)
            return
        }
        show(Screen.GoOffline, notice = notice)
    }

    /** The state a long call came from, as it was (its page and public values), when the call entered no other screen. */
    private fun showFrom() {
        val previous = from
        show(
            previous.screen,
            previous.page,
            dice = previous.dice,
            commitment = previous.commitment,
            seal = previous.seal,
            checkRequest = previous.checkRequest,
            report = previous.report,
            registry = previous.registry,
            proof = previous.proof,
            skipped = previous.skipped,
            codeRefused = previous.codeRefused,
            scanStop = previous.scanStop,
            scanRefusal = previous.scanRefusal,
        )
    }

    /** The dice screen with core's counts now. */
    private fun showDice() {
        val progress = done { Core.diceProgress() } ?: return
        show(Screen.Dice, dice = progress.value)
    }

    /** One of the check's screens after the seal card, with the seal card and its check QR (the same check and nonce). */
    private fun showInCheck(screen: Screen, codeRefused: Boolean = false, scanRefusal: Refusal? = null) {
        val current = mutable.value
        show(
            screen,
            seal = current.seal,
            checkRequest = current.checkRequest,
            codeRefused = codeRefused,
            scanRefusal = scanRefusal,
        )
    }

    /**
     * Where a go-ahead led (docs/seal-watchonly-braille.md, "Results"): the words are available, and
     * the result names the Seal ID and says against what (a loaded snapshot's header, a scanned go-ahead
     * QR's proof's, or the checker's typed code); or the seed was wiped unseen, and the collision result
     * follows, drawing the destroyed seed's seal (lead decision M5-55). proof says the header is a
     * proof's. The slot is Ready or at its restart, both held under the timers.
     */
    private fun ended(revealed: Revealed, seal: SealCard?, proof: Boolean = false) {
        when (revealed) {
            is Revealed.Clear -> show(Screen.CheckResult, seal = seal, registry = revealed.registry, proof = proof)
            is Revealed.Collision -> show(Screen.Collision, seal = seal, registry = revealed.registry, proof = proof)
        }
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
        seal: SealCard? = null,
        checkRequest: QrMatrix? = null,
        report: QrMatrix? = null,
        registry: RegistryHeader? = null,
        proof: Boolean = false,
        skipped: Boolean = false,
        codeRefused: Boolean = false,
        scanStop: ScanStop? = null,
        scanRefusal: Refusal? = null,
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
                seal = seal,
                checkRequest = checkRequest,
                report = report,
                registry = registry,
                proof = proof,
                skipped = skipped,
                codeRefused = codeRefused,
                scanStop = scanStop,
                scanRefusal = scanRefusal,
            ),
        )
    }

    /**
     * The next state, and what a screen holds while it shows: the motion source runs only on Device
     * entropy; the dice pad's pick is wiped when the dice screen leaves, and the typed go-ahead code
     * when the code entry does; a QR code the state held and the next one does not is wiped (rule 5:
     * the collision report's carries a seal code).
     */
    private fun enter(next: UiState) {
        val previous = mutable.value
        val before = previous.screen
        mutable.value = next
        wipeLeaving(previous.checkRequest, next)
        wipeLeaving(previous.report, next)
        if (next.screen == before) return
        if (before == Screen.DeviceEntropy) motion.stop()
        if (before == Screen.Dice) dicePick.wipe()
        if (before == Screen.CodeEntry) goAheadCode.wipe()
        if (next.screen == Screen.DeviceEntropy) motion.start(this::motionSample)
    }

    /** Wipes matrix unless next holds it. */
    private fun wipeLeaving(matrix: QrMatrix?, next: UiState) {
        if (matrix != null && matrix !== next.checkRequest && matrix !== next.report) matrix.wipe()
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

    /**
     * Where Back goes from screen: only where nothing is lost, before any session, and in the check
     * from a confirm screen or the code entry to the screen that offered it; null elsewhere.
     */
    private fun backTo(screen: Screen): Screen? = when (screen) {
        Screen.GoOffline -> Screen.FirstLaunch
        Screen.Home -> Screen.GoOffline
        Screen.Length -> Screen.Home
        Screen.SkipConfirm -> Screen.CheckPrompt
        Screen.Scan, Screen.CodeEntry, Screen.MatchFoundConfirm, Screen.CannotCheckConfirm -> Screen.SealCard
        Screen.SelfTest, Screen.FirstLaunch, Screen.DeviceEntropy, Screen.Commitment, Screen.Dice, Screen.CheckPrompt,
        Screen.SealCard, Screen.Collision, Screen.CollisionReport, Screen.CheckResult, Screen.Working, Screen.Stop -> null
    }

    /** Whether screen needs airplane mode on and Wi-Fi off (Q57): every screen from Home on. */
    private fun needsOffline(screen: Screen): Boolean = when (screen) {
        Screen.SelfTest, Screen.FirstLaunch, Screen.GoOffline, Screen.Working, Screen.Stop -> false
        Screen.Home, Screen.Length, Screen.DeviceEntropy, Screen.Commitment, Screen.Dice, Screen.CheckPrompt,
        Screen.SkipConfirm, Screen.SealCard, Screen.Scan, Screen.CodeEntry, Screen.MatchFoundConfirm,
        Screen.CannotCheckConfirm, Screen.Collision, Screen.CollisionReport, Screen.CheckResult -> true
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
