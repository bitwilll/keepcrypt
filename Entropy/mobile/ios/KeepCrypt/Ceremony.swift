// The Swift CeremonyModel's file (tasks/todo.md, M6 items A2, C3, C5 and D2; lead decision M6-6; Q86): the
// one way the app ends itself, Ceremony.halt; the start-up self-test's outcome; and the CeremonyModel, the
// Swift port of :screens' CeremonyModel.kt, which owns the slot's use for every screen of Screen.swift's
// list (the shared table, mobile/screens.json). The port keeps the Kotlin model's states, screens, gate,
// long calls, Back, pads, refusals and halts, method for method and in Kotlin's own words where they
// apply, so KeepCryptTests' walk can hold it to the JVM walk's expectations (Walk.kt). Where the iPhone
// differs, the platform does, never the flow: the offline check is one reading (no usable path, C5)
// where Android reads airplane mode and Wi-Fi; a screenshot discards the session on every screen (C5,
// the iPhone's own rule); and the halt status is a Reply case (Wire.swift), not a thrown KcHalt, since a
// Swift handler must end in Ceremony.halt, which ends the process. The model is UI-free: the SwiftUI
// screens (D3 on) draw its state and hand it their presses.

import Combine
import Foundation

/// The app's end (rule 3, fail closed; docs/mobile-apps.md, "When something fails"): every error the
/// app cannot answer with a screen ends here, and so does the stop screen's one action. The gate
/// allows no other type of this name and no other halt, and every error handler under mobile/ios
/// ends in this call or a rethrow.
enum Ceremony {
    /// Why the app ends: fixed cases, never a message (rule 5).
    enum End {
        /// The stop screen's "Close app".
        case closed
        /// The bridge or the app broke its own contract: a value the app cannot have made, a wipe
        /// that did not happen.
        case bridge
        /// The camera could not be opened for the scan after access was granted (GoAheadScanner): its
        /// error has no answer but the app's end (rule 3).
        case camera
    }

    /// Halts the slot, which drops everything it held, wipes Core's reply buffer and ends the process
    /// at once: no dialog and no message (a message could hold a secret). The next start runs the
    /// self-test again before anything else.
    static func halt(_ end: End) -> Never {
        let wiped = Core.shared.endForExit()
        exit(end == .closed && wiped ? 0 : 1)
    }
}

/// What a start-up self-test's reply means (docs/mobile-apps.md, step 2: a failure blocks every
/// ceremony): passed, or the stop screen with the slot's reason. Only an OK reply passes; a refusal or
/// a discard, which the self-test never gives, stops the app as internal (fail closed).
enum StartScreen: Equatable {
    case passed
    case stopped(HaltReason)

    init(selfTest: Reply<Void>) {
        switch selfTest {
        case .done:
            self = .passed
        case .halted(let reason):
            self = .stopped(reason)
        case .refused, .discarded:
            self = .stopped(.internal)
        }
    }
}

/// The stop screen's line for why the slot halted (Android's stopLine, pi-firmware.md's "Finish and
/// halts"): one fixed line per reason, built from no data.
func stopLine(_ reason: HaltReason?) -> String {
    switch reason {
    case .knownAnswerTest: return "A known-answer test failed."
    case .entropySource: return "The entropy source failed."
    case .healthTest: return "An entropy health test failed."
    case .exportSelfCheck: return "The watch-only export failed its self-check."
    case .panic: return "The app's core stopped unexpectedly."
    case .internal, nil: return "An internal check failed."
    }
}

/// Core refuses a 257th roll by halting, so the dice screen's confirm is disabled at 256
/// (docs/pi-firmware.md, "Confirmations").
let maxRolls = 256

/// The backup passphrase's words: two pages of four (pi-firmware.md, USB step 1).
let passphraseWords = 8

/// The insert view shows one insert a page, the overview four (the Pi's).
let overviewWords = 4

/// The inserts of one device: a 24-word seed's words 13-24 go on device 2 of 2 (swb, "24-word seeds").
let insertsPerDevice = 12

/// The read-back's Done takes three letters (the fourth face blank) or four (the letter pad's capacity).
let readbackMinLetters = 3

/// What covers the screen without leaving it.
enum Overlay: Equatable {
    /// The privacy cover: 30 s without input on a Protected screen, or the app away from a Public one.
    /// The next tap only uncovers it, and the session stays.
    case cover
    /// The warning a minute before the idle wipe; any tap keeps everything.
    case warning
}

/// Why the session was wiped, said on the start screen (the Pi says so too, docs/pi-firmware.md).
enum Notice: Equatable {
    /// The app was left on a Protected screen or during a long call.
    case left
    /// The phone went online: a network path became usable.
    case offline
    /// 10 minutes without input.
    case idle
    /// 60 s away from the app.
    case background
    /// A screenshot was taken (docs/mobile-apps.md, "Screen capture protection: iPhone"): the iPhone's own.
    case screenshot
}

/// The notice's line: fixed text, built from no data (Android's NoticeLine, and C5's screenshot line).
func noticeLine(_ notice: Notice) -> String {
    switch notice {
    case .left:
        return "The session was wiped: the app was left during it."
    case .offline:
        return "The session was wiped: the phone went online."
    case .idle:
        return "The session was wiped after 10 minutes without input."
    case .background:
        return "The session was wiped after 60 seconds away from the app."
    case .screenshot:
        return "The session was wiped: a screenshot was taken. A screenshot can keep what the screen showed, so nothing it may have held is used again."
    }
}

/// Why a save failed: the step the model names (the session stays).
enum SaveStep: Equatable {
    case write, readBack, verify
}

/// A failed save: its step, and for verify core's refusal of the file read back.
struct SaveFailure: Equatable {
    let step: SaveStep
    var refusal: Refusal?
}

/// Why Check a backup or Load registry snapshot opened no file: its name (not .age, or not .kcr), its
/// size (unknown, or past core's limit for a backup or a snapshot), or a read that failed.
enum FileRefusal: Equatable {
    case notAge, notKcr, noSize, tooLarge, snapshotTooLarge, unreadable
}

/// Whether refusal is one the backup's calls give (core's text exists for it): any other is the shell's bug.
func isBackupRefusal(_ refusal: Refusal) -> Bool {
    refusal == .wrongPassphrase || refusal == .readbackMismatch || refusal.group == .backup
}

/// Whether refusal is one a snapshot's load gives (its text exists): any other is the shell's bug.
func isSnapshotRefusal(_ refusal: Refusal) -> Bool {
    refusal == .noRegistryKey || refusal.group == .snapshot
}

/// C (or D) as its screen shows it (the Pi's ui/hex.rs): 32 bytes as 16 groups of 4 lower-case hex
/// digits, a space between the groups of a row and a line feed between the four rows; any other length
/// is the app's own bug, which ends it. C is public; D's screen lays it out the same way from its Secret,
/// a String only for the text on screen.
func hexGroups(_ bytes: Secret) -> String {
    guard bytes.count == 32 else { Ceremony.halt(.bridge) }
    let digits = Array("0123456789abcdef")
    var out = ""
    for index in 0..<bytes.count {
        if index > 0, index % 8 == 0 {
            out.append("\n")
        } else if index > 0, index % 2 == 0 {
            out.append(" ")
        }
        let byte = Int(bytes[index])
        out.append(digits[byte >> 4])
        out.append(digits[byte & 0x0F])
    }
    return out
}

extension OpenedBackup {
    /// Wipes its re-check QR, once the slot no longer holds the backup.
    func wipe() {
        recheck.wipe()
    }
}

/// What the screens draw (Android's UiState; lead decision M5-49): the screen and its page, flags about
/// it, and the public values a screen shows, never a secret but through a Secret reference: the QR
/// codes are QrMatrix, the words WordPage and a read-back's verdicts Mismatch, each holding its bytes in
/// a Secret, and the model wipes each one when no screen holds it any more.
struct UiState {
    var screen: Screen
    /// The screen's page index: the words' or the overview's page, a read-back's insert, the backup
    /// passphrase's page or its confirm's question, Check a backup's word, the BIP39 entry's page of keys.
    var page = 0
    /// The privacy gate stands before this Protected screen ("I'm alone, show words").
    var gate = false
    var overlay: Overlay?
    /// A recording or mirroring of the screen is reported: Protected screens show a placeholder.
    var recording = false
    /// No network path is usable, as the offline check last reported it (Android's airplane mode on and
    /// Wi-Fi off); until its first report the phone counts as online (fail closed, C5).
    var offline = false
    var notice: Notice?
    /// The dice screen's counts, core's: the rolls, the minimum and the bits, never a roll.
    var dice: DiceProgress?
    /// The ceremony is dice-only, which the dice screen says.
    var diceOnly = false
    /// C on the commitment screen, as 16 groups of 4 hex digits (public).
    var commitment: String?
    /// The seal card (public), from Check now on and never on the prompt (lead decision M5-55).
    var seal: SealCard?
    /// The seal card's check QR (T and the check's nonce, public), from Check now until the check ends.
    var checkRequest: QrMatrix?
    /// The collision-report QR (Protected: the destroyed seed's seal code), wiped when its screen leaves.
    var report: QrMatrix?
    /// The header the check ran against: the loaded snapshot's, or a scanned go-ahead QR's proof's.
    var registry: RegistryHeader?
    /// The registry header is a scanned go-ahead QR's proof, not a loaded snapshot's (lead decision M5-55).
    var proof = false
    /// The words came by Skip, with no check: the result says the seal can be checked later.
    var skipped = false
    /// The typed go-ahead code was refused: the code entry says so, and the check, its nonce and actions stay.
    var codeRefused = false
    /// The scan screen's scanner stopped without a code: it says why and scans no more.
    var scanStop: ScanStop?
    /// Core refused the scanned QR's text: the scan screen says so and scans no more; the check stays.
    var scanRefusal: Refusal?
    /// The insert on show: the words page's, page + 1, and the read-back's.
    var insert: WordPage?
    /// The overview's four inserts, page's (words 4 x page + 1 to 4 x page + 4).
    var overview: [WordPage]?
    /// The words page shows a read-back mismatch's insert: its one way on is back to that insert's read-back.
    var reviewing = false
    /// The device swap's way on: the words page or the overview at page, the first of device 2 of 2.
    var swapTo: Screen?
    /// The read-back entry's insert matched: the screen shows the whole word, and Next.
    var matched = false
    /// With matched: every insert has now matched, so Next leads to the read-back's end.
    var complete = false
    /// The read-back mismatch's verdicts, face by face (held in a Secret), wiped when its screen leaves.
    var mismatch: Mismatch?
    /// The wallet summary (public, as the Pi's, Q29): the fingerprint and the first receive address.
    var summary: Summary?
    /// The seed has 24 words, on two devices, which the checklist says.
    var twoDevices = false
    /// The backup passphrase's page on show (core's four words, held in a Secret), wiped when its screen leaves.
    var passphrase: Secret?
    /// The confirm found a wrong word: the passphrase shows again from its first page, saying so.
    var wrongConfirm = false
    /// The confirm's two questions of four choices (each choice a Secret), wiped when the confirm leaves.
    var challenge: Challenge?
    /// The encrypted backup's suggested name on the save screen (public).
    var backupName: String?
    /// Why the last save failed, naming its step: the save screen says so, and the session stays.
    var saveFailure: SaveFailure?
    /// Why Check a backup or Load registry snapshot opened no file: Home says so.
    var fileRefusal: FileRefusal?
    /// Core refused the passphrase typed, or the file, on Check a backup's entry.
    var entryRefusal: Refusal?
    /// Check a backup's opened backup (public: its fingerprint, seal card and re-check QR).
    var opened: OpenedBackup?
    /// The watch-only export (its summary, public, and its account and descriptor QRs, the xpub).
    var watch: WatchOnly?
    /// The registration QR (Protected: this seed's seal code), wiped when its screen leaves.
    var registration: QrMatrix?
    /// D on its screen (Protected: D and the rolls recreate the seed), in a Secret, wiped when it leaves.
    var deviceLeg: Secret?
    /// The loaded registry snapshot's header (public), the model's own, on every screen.
    var loaded: RegistryHeader?
    /// Core refused the snapshot picked: the result says so.
    var snapshotRefusal: Refusal?
    /// Why the slot halted (the first halt's), on the stop screen alone.
    var halt: HaltReason?
}

/// What a report of the offline check does (Android's offlineChanged, as a pure function).
enum PathStep: Equatable {
    /// Only the state changes.
    case nothing
    /// The session is discarded at once and the start screen says why.
    case discard
    /// Go offline comes back, with nothing to say.
    case goOffline
}

/// The halt reason the model met first (Android's haltReason): set by whichever thread meets the halt,
/// read on the main thread for the stop screen; it never changes once set.
private final class HaltLatch {
    private let lock = NSLock()
    private var first: HaltReason?

    var reason: HaltReason? {
        lock.lock()
        defer { lock.unlock() }
        return first
    }

    func record(_ reason: HaltReason) {
        lock.lock()
        defer { lock.unlock() }
        if first == nil { first = reason }
    }
}

/// A long call's flag, set on the main thread by a discard and read on the worker before and after
/// core's call; and the discard's reason, for the start screen (main thread only).
private final class Pending {
    private let lock = NSLock()
    private var flag = false
    var notice: Notice?

    var discarded: Bool {
        get {
            lock.lock()
            defer { lock.unlock() }
            return flag
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            flag = newValue
        }
    }
}

/// A long call's reply, handed from the worker to the main thread.
private final class Handed<T> {
    var reply: Reply<T>?
}

/// The one owner of the slot's use (Android's CeremonyModel, ported; docs/mobile-apps.md, "Session
/// lifetime", "When something fails" and "Screens and user flow"). The app makes it once with its seams
/// (Seams.swift): Core, the worker for long calls, the monotonic clock, the UTC date, the motion source
/// and the build's testRegistry flag. Every method runs on the main thread, as Android's.
///
/// - Every core call goes through call, which keeps the first halt's reason: a halt ends on the stop
///   screen, which names it and which no input leaves; only its "Close app" does (Ceremony.halt).
/// - A long call runs on the worker behind "Working..." (the start-up self-test behind its own screen),
///   which takes no input (work); so does a picked file's read.
/// - Leaving the app during a long call or on a Protected screen, and going online after the start-up
///   while a session or Check a backup's file is held or a long call runs, call core's discard at once,
///   even during a long call; the call's discarded reply then returns the UI to its start screen
///   (toStart). A screenshot discards the same way, on every screen (C5). On a Public screen leaving puts
///   the privacy cover up, and 60 s away wipes. On the iPhone leaving is the scene going to the
///   background, and coming back its next active phase (CaptureShield's scene phase).
/// - The timers (Timers) cover, warn and wipe on each tick, which the app makes every second.
/// - On every start First launch shows first, before any core call (lead decision M5-50); its Continue
///   runs the start-up self-test, then Go offline (its Start only offline), Home, Length, and the
///   ceremony, which needs the phone offline on every screen from Home on: Device entropy and Commitment
///   in Mixed mode only, then Dice, the collision check, the words, the read-back, the summary, the
///   exports and the checklist; Home's Check a backup, Load registry snapshot and About.
/// - Back goes back only where nothing is lost (back).
final class CeremonyModel: ObservableObject {
    /// What the screens draw.
    @Published private(set) var state = UiState(screen: .firstLaunch)

    /// Whether what the timers' warning and wipe apply to is held (holds): a session, a restart or a
    /// checked backup, or Check a backup's file and entries from the read's acceptance. While it is, the
    /// phone keeps its screen on (lead decision M5-72 (b)).
    @Published private(set) var held = false

    let testRegistry: Bool

    /// The dice pad's pick (rule 5: a PadEntry, never a String), wiped when the dice screen leaves.
    let dicePick = dicePadEntry()
    /// The go-ahead code as the code entry's Crockford pad types it, wiped when the code entry leaves.
    let goAheadCode = crockfordPadEntry()
    /// The read-back's letters as the entry's letter pad types them, wiped when the entry leaves.
    let readbackLetters = letterPadEntry()
    /// The backup's letters on its Protected screens: the confirm's answer and Check a backup's entry.
    let backupLetters = letterPadEntry()
    /// The BIP39 passphrase as its entry's ASCII pad types it, wiped when the entry leaves.
    let bip39Letters = asciiPadEntry()

    private let core: CeremonyCore
    private let worker: Worker
    private let clock: MonotonicClock
    private let date: UtcDate
    private let motion: MotionSource
    private let latch = HaltLatch()
    private let timers: Timers

    /// The encrypted backup core made in memory (ciphertext, never in the state), from its encryption
    /// until the save screen and its calls are over.
    private var backupFile: BackupFile?
    /// The confirm's first answer, a choice's index (0-3), until the second is typed; -1 for none.
    private var firstPick = -1
    /// The file Check a backup read, while its passphrase's entry and its call last. held follows it.
    private var checkFile: Secret? {
        didSet { held = holds() }
    }
    /// The file Load registry snapshot read, while core's load of it lasts.
    private var snapshotFile: Secret?
    /// Check a backup's entries typed so far, each a word's first four letters (or three) in a Secret.
    private var entries: [Secret] = []
    /// Check a backup's opened backup, while the slot holds it.
    private var checked: OpenedBackup?
    /// The start-up self-test (First launch's Continue) has passed.
    private(set) var started = false
    /// The app is in the foreground (between its return and its leaving; a picker it opened included).
    private var foreground = false
    /// A picker the app opened is up, from the press that opened it until its answer, so a second press
    /// that would open one opens none (openPicker).
    private var pickerUp = false
    /// The slot holds a session, a restart's kept Wiped or Check a backup's checked backup. held follows it.
    private var session = false {
        didSet { held = holds() }
    }
    /// The long call running, if any.
    private var running: Pending?
    /// The state the running long call was started from; its screen stands in for it.
    private var from = UiState(screen: .firstLaunch)
    /// The ceremony's mode: Home's choice, kept by start for its screens and the restarts.
    private var mode = Mode.mixed
    /// The ceremony's length: Length's choice, kept by start for the restarts.
    private var words = Words.twelve
    /// The loaded registry snapshot's header: Check now then runs the check against it on its own.
    private var snapshot: RegistryHeader?

    init(core: CeremonyCore, worker: Worker, clock: MonotonicClock, date: UtcDate, motion: MotionSource, testRegistry: Bool) {
        self.core = core
        self.worker = worker
        self.clock = clock
        self.date = date
        self.motion = motion
        self.testRegistry = testRegistry
        timers = Timers(clock: clock)
    }

    /// Check a backup's entries held now, a copy of the list (never drawn): the tests' look at their wiping.
    var entriesHeld: [Secret] { entries }

    /// The offline check's report (Android's offlineChanged; C5): offline is no usable path. After the
    /// start-up, going online while a session or Check a backup's file is held, or a long call runs,
    /// discards at once, and the start screen, Go offline, says why; on a screen past Go offline with
    /// nothing held, Go offline comes back, with nothing to say. Before the start-up self-test passes,
    /// and on First launch and Go offline, only the state changes.
    func pathReported(offline now: Bool) {
        if stopped() { return }
        state.offline = now
        switch CeremonyModel.afterPathReport(
            offline: now, started: started, holds: holds() || running != nil, needsOffline: needsOffline(state.screen))
        {
        case .nothing:
            break
        case .discard:
            discard(.offline)
        case .goOffline:
            show(.goOffline)
        }
    }

    /// Android's offlineChanged as a pure function: offline, or before the start-up self-test has
    /// passed, only the state changes; online after it, a session held (or a long call) is discarded at
    /// once, and a screen past Go offline that holds nothing goes back to Go offline.
    static func afterPathReport(offline: Bool, started: Bool, holds: Bool, needsOffline: Bool) -> PathStep {
        if offline || !started { return .nothing }
        if holds { return .discard }
        if needsOffline { return .goOffline }
        return .nothing
    }

    /// The app came back (the scene's active phase, Android's start). A configuration change, or a picker
    /// the app opened, never left the app. Otherwise the background rule comes first (60 s away wipes
    /// before anything shows). It never runs the start-up self-test: First launch's Continue does.
    func appReturned() {
        if stopped() { return }
        if foreground {
            timers.returned()
            return
        }
        tick()
        timers.returned()
        foreground = true
    }

    /// The app went to the background (the scene's background phase, Android's stop), not for a picker
    /// the app opened (the picker rule). During a long call and on a Protected screen the session is
    /// discarded at once; on a Public screen the privacy cover goes up and the background time starts.
    func appLeft() {
        if stopped() || !foreground { return }
        if !timers.left() { return }
        foreground = false
        let screen = state.screen
        if screen.isWorking || screen.isProtected {
            discard(.left)
        } else {
            state.overlay = .cover
        }
    }

    /// The app opens a picker next, over its own scene: a leaving that follows is no leaving (the picker
    /// rule), until the app's next resume.
    func pickerOpened() {
        timers.pickerOpened()
    }

    /// The app is active again (the scene's phase, Android's resume): the picker rule's exemption ends,
    /// and a picker the app opened is over, so its buttons are free again even when its answer was lost
    /// (Stage U's U2c).
    func appResumed() {
        pickerUp = false
        timers.resumed()
    }

    /// A tap anywhere (the screens' touch handler, before the tap reaches its control): the idle time
    /// starts again; a cover or a warning stays up until the tap on it takes it away (dismissOverlay).
    /// Nothing during a long call or on the stop screen.
    func input() {
        if busy() { return }
        timers.input()
    }

    /// A person reading the screen through VoiceOver (Q80 (b): a focus or a text read by its parts):
    /// input, as a tap is. The idle warning shows only after 9 minutes without input, so a reading ends
    /// it: on a Protected screen the cover it came over is back (only a tap shows a Protected screen
    /// again), on a Public screen the screen is. A cover stays up until a tap takes it away.
    func reading() {
        if busy() { return }
        timers.input()
        if state.overlay == .warning { state.overlay = state.screen.isProtected ? .cover : nil }
    }

    /// The tap that takes the cover or the warning away; it does nothing else.
    func dismissOverlay() {
        if busy() { return }
        timers.input()
        state.overlay = nil
    }

    /// The timers' step now: the app calls it each second, and every return to the app does.
    func tick() {
        if busy() { return }
        switch timers.step(onProtected: state.screen.isProtected, holdsSecrets: holds()) {
        case .backgroundWipe:
            discard(.background)
        case .idleWipe:
            discard(.idle)
        case .warn:
            if state.overlay != .warning { state.overlay = .warning }
        case .cover:
            if state.overlay == nil { state.overlay = .cover }
        case nil:
            break
        }
    }

    /// A recording or mirroring of the screen is reported or no longer reported.
    func recordingChanged(_ visible: Bool) {
        state.recording = visible
    }

    /// The screenshot response (docs/mobile-apps.md, "Screen capture protection: iPhone"; C5): a
    /// screenshot can keep whatever the screen showed, so on every screen, a secret held or not, Core's
    /// discard drops whatever session exists, and the start screen says why, as any discard's does. On
    /// First launch and Go offline, which hold nothing and need nothing offline, the screen stays and
    /// says so. A stopped app has nothing to discard.
    func discardAfterScreenshot() {
        if stopped() { return }
        discard(.screenshot)
    }

    /// A touch anywhere, with the event's uptime in milliseconds: on Device entropy that time, and the
    /// clock's nanoseconds as it arrives, go into the pool with no credit (docs/mobile-apps.md, "Touch
    /// and button timing"); anywhere else, nothing.
    func touched(uptimeMillis: Int64) {
        guard collecting() else { return }
        var timing = [UInt8](repeating: 0, count: 16)
        putInt64(&timing, 0, uptimeMillis)
        putInt64(&timing, 8, clock.nowNanos())
        let bytes = Secret(taking: timing)
        guard CeremonyModel.wipe(&timing) else { Ceremony.halt(.bridge) }
        extra(.inputTiming, bytes)
    }

    /// The privacy gate's "I'm alone, show words": the Protected screen behind it shows.
    func passGate() {
        if busy() { return }
        timers.input()
        state.gate = false
    }

    /// The system Back and the Back buttons of the scan screen, the code entry and each one-way choice's
    /// confirm screen: back to the screen before only where nothing is lost (Android's back: Length to
    /// Home, Home to Go offline, Go offline to First launch; Skip's confirm to the check prompt; the check
    /// QR to the seal card, and the scan screen, the confirms and the code entry to the check QR, each
    /// with the same check and nonce, the typed code wiped; on the words, their overview and the backup
    /// passphrase the page before, and on the descriptor QR the account QR; the BIP39 passphrase's entry
    /// to its question, the passphrase typed wiped; Check a backup's entry to Home, the file read and the
    /// letters typed wiped, and its re-check QR to its result; Load registry snapshot's result and About to
    /// Home); anywhere else it does nothing.
    func back() {
        let current = state
        switch current.screen {
        case .words, .wordsOverview, .backupPassphrase, .watchDescriptorQr:
            previousPage()
            return
        default:
            break
        }
        guard let previous = backTo(current.screen) else { return }
        if pressOn(current.screen) {
            show(previous) {
                $0.seal = current.seal
                $0.checkRequest = current.checkRequest
                $0.opened = current.opened
            }
        }
    }

    /// A key of the showing screen's pad, made on screen and page (lead decision M5-72's U3e): the dice
    /// pad's face, which replaces the pick (none at 256 rolls); the go-ahead code's symbol; the letter
    /// pad's letter on the read-back entry (none after a match), the backup's confirm and Check a backup's
    /// entry; the ASCII pad's character on the BIP39 passphrase's entry, from its page on show alone. A key
    /// left over from a screen or a page that has gone types nothing.
    func padKey(screen: Screen, page: Int, key: Character) {
        let current = state
        guard current.page == page, let entry = padEntry(current), pressOn(screen) else { return }
        if current.screen == .bip39Entry, !asciiPage(current.page).contains(key) { return }
        if current.screen == .dice {
            entry.replace(key)
        } else {
            entry.type(key)
        }
    }

    /// The Delete beside the showing screen's pad, made on screen and page: the last key typed (the dice
    /// pad has none). On Check a backup's entry, word N > 1's empty pad takes entry N - 1 back, its letters
    /// in the pad minus its last one, and its Secret is wiped; word 1's empty pad does nothing.
    func padDelete(screen: Screen, page: Int) {
        let current = state
        guard current.page == page, let entry = padEntry(current) else { return }
        if current.screen == .dice || !pressOn(screen) { return }
        if entry.length > 0 || current.screen != .backupCheckEntry {
            entry.delete()
            return
        }
        guard let last = entries.popLast() else { return }
        for index in 0..<max(0, last.count - 1) {
            entry.type(Character(Unicode.Scalar(last[index])))
        }
        last.wipe()
        show(.backupCheckEntry, page: entries.count)
    }

    /// The pad the showing screen offers and the entry its keys type into, or nil where none is offered.
    private func padEntry(_ state: UiState) -> PadEntry? {
        switch state.screen {
        case .dice: return (state.dice?.rolls ?? maxRolls) < maxRolls ? dicePick : nil
        case .codeEntry: return goAheadCode
        case .readbackEntry: return state.matched ? nil : readbackLetters
        case .backupConfirm, .backupCheckEntry: return backupLetters
        case .bip39Entry: return bip39Letters
        default: return nil
        }
    }

    /// The BIP39 passphrase's entry shows the ASCII pad's page of keys, the passphrase typed kept.
    private func keysPage(_ page: Int) {
        state.page = page
    }

    /// First launch's Continue: the start-up self-test behind its own screen, then Go offline. Once it
    /// has passed (First launch again by Back from Go offline), Go offline at once.
    func firstLaunchDone() {
        guard pressOn(.firstLaunch) else { return }
        if started {
            show(.goOffline)
        } else {
            selfTest()
        }
    }

    /// Go offline's Start: Home, only offline (online its button is disabled, and a press does nothing).
    func startOffline() {
        if state.offline, pressOn(.goOffline) { show(.home) }
    }

    /// Home's New seed (Mixed) or Dice-only seed: Length.
    func chooseMode(_ mode: Mode) {
        guard pressOn(.home) else { return }
        self.mode = mode
        show(.length)
    }

    /// Length's 12 or 24 words: the ceremony starts, in Home's mode.
    func chooseLength(_ words: Words) {
        if pressOn(.length) { start(words, mode) }
    }

    /// Device entropy's Continue: the commitment, which reads the phone's random source and fixes D (no
    /// extra reaches the pool after it), then Commitment with C.
    func deviceEntropyDone() {
        guard pressOn(.deviceEntropy), short({ $0.commit() }), let commitment = done({ $0.commitment() }) else { return }
        guard commitment.count == Wire.legLength else {
            failClosed()
            return
        }
        show(.commitment) { $0.commitment = hexGroups(commitment) }
    }

    /// Commitment's Continue: the dice.
    func commitmentDone() {
        if pressOn(.commitment), short({ $0.startDice() }) { showDice() }
    }

    /// The dice screen's confirm: the face picked on the pad is pushed to core and the pick is wiped.
    /// Nothing with no face picked or at 256 rolls, where its button is disabled.
    func confirmRoll() {
        guard pressOn(.dice), let dice = state.dice else { return }
        guard dicePick.length == 1, dice.rolls < maxRolls, let face = dicePick.keyAt(0).wholeNumberValue else { return }
        dicePick.wipe()
        if short({ $0.pushRoll(face) }) { showDice() }
    }

    /// The dice screen's undo: the last roll goes (the pick stays); nothing with no roll.
    func undoRoll() {
        guard pressOn(.dice), let dice = state.dice else { return }
        if dice.rolls > 0, short({ $0.undoRoll() }) { showDice() }
    }

    /// The dice screen's Done, once the minimum is met (below it the button is disabled; core would
    /// halt): core makes the seed (finish, a long call), then the check prompt, which shows no seal.
    func diceDone() {
        guard pressOn(.dice), let dice = state.dice, dice.rolls >= dice.minimum else { return }
        work({ $0.finish() }) { [self] _ in show(.checkPrompt) }
    }

    /// The prompt's "Check now (recommended)": the check starts (core draws its nonce), and from here
    /// only a verified go-ahead reaches the words; the seal shows from here on. With a loaded snapshot
    /// the check runs against it at once, on today's UTC date, as a short call (lead decision M5-54).
    /// Otherwise the seal card shows, holding the check QR its next page draws.
    func checkNow() {
        guard pressOn(.checkPrompt), short({ $0.startCheck() }), let seal = done({ $0.seal() }) else { return }
        if snapshot != nil {
            let today = date.today()
            guard let revealed = done({ $0.revealSnapshot(today: today) }) else { return }
            ended(revealed, seal: seal)
            return
        }
        guard let request = done({ $0.checkRequest() }) else { return }
        show(.sealCard) {
            $0.seal = seal
            $0.checkRequest = request
        }
    }

    /// The prompt's Skip: its confirm screen, since Skip is offered only before a check starts (rule 6).
    func skip() {
        if pressOn(.checkPrompt) { show(.skipConfirm) }
    }

    /// Skip's confirm: the words with no check, and a result that says the seal can be checked later.
    func skipConfirmed() {
        if pressOn(.skipConfirm), short({ $0.skipCheck() }) { show(.checkResult) { $0.skipped = true } }
    }

    /// The seal card's "Show check QR": its next page, the check QR, the same check and nonce.
    func showCheckQr() {
        if pressOn(.sealCard) { showInCheck(.checkQr) }
    }

    /// The check QR's "Scan go-ahead QR": the scan screen, with the same check and nonce.
    func scanQr() {
        if pressOn(.checkQr) { showInCheck(.scan) }
    }

    /// The check QR's or the scan screen's "Type go-ahead code": the code entry, its pad empty.
    func typeCode() {
        if pressOn(.checkQr) || pressOn(.scan) { showInCheck(.codeEntry) }
    }

    /// The scan screen's text, the first QR code its scanner read: core checks it as this check's
    /// go-ahead QR on today's UTC date (a long call), then judges it. A text core refuses returns to the
    /// scan screen, which says so and scans no more; the check, its nonce and its actions stay.
    func onGoAheadText(_ text: String) {
        guard pressOn(.scan) else { return }
        let seal = state.seal
        let date = self.date
        work({ $0.revealProof(today: date.today(), text: text) },
             refused: { [self] in showInCheck(.scan, scanRefusal: $0) }) { [self] in
            ended($0, seal: seal, proof: true)
        }
    }

    /// The scan screen's scanner stopped without a code: the screen says why and scans no more; anywhere
    /// else, or after a stop already said, nothing.
    func scanStopped(_ why: ScanStop) {
        if busy() || state.screen != .scan || state.scanStop != nil { return }
        state.scanStop = why
    }

    /// The check QR's "Match found": its confirm screen.
    func matchFound() {
        if pressOn(.checkQr) { showInCheck(.matchFoundConfirm) }
    }

    /// The check QR's "Cannot check": its confirm screen.
    func cannotCheck() {
        if pressOn(.checkQr) { showInCheck(.cannotCheckConfirm) }
    }

    /// The code entry's Done, with all 8 symbols typed: core verifies the code against this check's T and
    /// nonce. A verified one reveals the words; one that does not verify is refused, and the code entry
    /// says so with the check kept, the typed code wiped. The code is handed over as a Secret and wiped
    /// once core has it.
    func codeDone() {
        guard pressOn(.codeEntry), goAheadCode.isFull else { return }
        let seal = state.seal
        let reply = goAheadCode.handOver { code in call { $0.revealCode(code) } }
        switch reply {
        case .done(let revealed):
            ended(revealed, seal: seal)
        case .refused(let refusal) where refusal.group == .code:
            showInCheck(.codeEntry, codeRefused: true)
        default:
            settle(reply)
        }
    }

    /// Match found's confirm, "Destroy this seed": the seed is wiped unseen, then the collision result.
    func matchFoundConfirmed() {
        let seal = state.seal
        if pressOn(.matchFoundConfirm), short({ $0.matchFound() }) { show(.collision) { $0.seal = seal } }
    }

    /// Cannot check's confirm, "Start again": the seed is wiped unseen and a new ceremony starts from the
    /// kept Wiped.
    func cannotCheckConfirmed() {
        if pressOn(.cannotCheckConfirm), short({ $0.cannotCheck() }) { start(words, mode) }
    }

    /// The collision result's "Show the collision report": its QR, a Protected screen behind the gate.
    func showReport() {
        guard pressOn(.collision), let report = done({ $0.collisionReport() }) else { return }
        show(.collisionReport) { $0.report = report }
    }

    /// "Add fresh entropy", past the report's gate: a new ceremony from the kept Wiped, at least 99 rolls.
    func addFreshEntropy() {
        if pressOn(.collisionReport) { start(words, mode) }
    }

    /// The check result's "Show words": the first insert, through the privacy gate.
    func showWords() {
        if pressOn(.checkResult) { showInsert(0) }
    }

    /// Next on the words and the overview: the next page, while there is one; on a 24-word seed, past
    /// word 12, the device swap first. Nothing while a mismatch's insert is reviewed. On the backup
    /// passphrase its second page; on the account QR the descriptor QR; on the BIP39 passphrase's entry
    /// its "Next keys", the passphrase typed kept.
    func nextPage() {
        let current = state
        switch current.screen {
        case .words:
            guard let insert = current.insert else { return }
            let next = current.page + 1
            guard pressOn(.words), !current.reviewing, next < insert.count else { return }
            if next == insertsPerDevice, insert.count > insertsPerDevice {
                show(.deviceSwap, page: next) {
                    $0.swapTo = .words
                    $0.opened = current.opened
                }
            } else {
                showInsert(next)
            }
        case .wordsOverview:
            guard let first = current.overview?.first else { return }
            let next = current.page + 1
            guard pressOn(.wordsOverview), next * overviewWords < first.count else { return }
            if next * overviewWords == insertsPerDevice, first.count > insertsPerDevice {
                show(.deviceSwap, page: next) {
                    $0.swapTo = .wordsOverview
                    $0.opened = current.opened
                }
            } else {
                showOverview(next)
            }
        case .backupPassphrase:
            if pressOn(.backupPassphrase), current.page == 0 { showPassphrase(1) }
        case .watchAccountQr:
            if pressOn(.watchAccountQr) { show(.watchDescriptorQr) { $0.watch = current.watch } }
        case .bip39Entry:
            if pressOn(.bip39Entry), current.page < asciiPages - 1 { keysPage(current.page + 1) }
        default:
            break
        }
    }

    /// Previous on the words, the overview, the backup passphrase and the descriptor QR (and Back there):
    /// the page before, with no device swap; nothing on the first page or while a mismatch's insert is
    /// reviewed. On the BIP39 passphrase's entry its "Previous keys".
    func previousPage() {
        let current = state
        switch current.screen {
        case .words:
            if pressOn(.words), !current.reviewing, current.page > 0 { showInsert(current.page - 1) }
        case .wordsOverview:
            if pressOn(.wordsOverview), current.page > 0 { showOverview(current.page - 1) }
        case .backupPassphrase:
            if pressOn(.backupPassphrase), current.page > 0 { showPassphrase(current.page - 1) }
        case .watchDescriptorQr:
            if pressOn(.watchDescriptorQr) { show(.watchAccountQr) { $0.watch = current.watch } }
        case .bip39Entry:
            if pressOn(.bip39Entry), current.page > 0 { keysPage(current.page - 1) }
        default:
            break
        }
    }

    /// The words' "Overview": the overview's page that holds this insert.
    func toOverview() {
        let current = state
        if pressOn(.words), !current.reviewing { showOverview(current.page / overviewWords) }
    }

    /// The overview's "Insert view": the first insert of its page.
    func toInsertView() {
        let current = state
        if pressOn(.wordsOverview) { showInsert(current.page * overviewWords) }
    }

    /// The device swap's Continue: device 2 of 2's first page, through the privacy gate again.
    func swapDone() {
        let current = state
        guard pressOn(.deviceSwap) else { return }
        switch current.swapTo {
        case .words: showInsert(current.page)
        case .wordsOverview: showOverview(current.page)
        default: failClosed()
        }
    }

    /// The last insert's "Start the read-back": insert 1's read-back entry, its letter pad empty. A
    /// checked backup's words have none.
    func startReadback() {
        let current = state
        guard let insert = current.insert else { return }
        if pressOn(.words), !current.reviewing, current.opened == nil, current.page + 1 == insert.count { showReadback(1) }
    }

    /// The read-back entry's Done, with three or four letters typed: core compares them with the insert's
    /// first four letters. A match shows the whole word; a mismatch each face's verdict. The letters are
    /// handed over as a Secret and wiped once core has them.
    func readbackTyped() {
        let current = state
        guard let insert = current.insert else { return }
        guard pressOn(.readbackEntry), !current.matched, readbackLetters.length >= readbackMinLetters else { return }
        let reply = readbackLetters.handOver { letters in call { $0.checkReadback(insert.position, letters: letters) } }
        guard case .done(let readback) = reply else {
            settle(reply)
            return
        }
        switch readback {
        case .match(let complete):
            show(.readbackEntry, page: current.page) {
                $0.insert = insert
                $0.matched = true
                $0.complete = complete
            }
        case .mismatch(let mismatch):
            show(.readbackMismatch, page: current.page) {
                $0.insert = insert
                $0.mismatch = mismatch
            }
        }
    }

    /// Next after a match: the next insert's read-back, or once every insert has matched the read-back's
    /// end. A match on the last insert that core does not call complete is the shell's bug, and halts.
    func readbackNext() {
        let current = state
        guard let insert = current.insert, pressOn(.readbackEntry), current.matched else { return }
        if current.complete {
            show(.readbackDone)
        } else if insert.position < insert.count {
            showReadback(insert.position + 1)
        } else {
            failClosed()
        }
    }

    /// The mismatch's "Read it again": the same insert's entry, its letter pad empty, the verdicts wiped.
    func readbackAgain() {
        let current = state
        if pressOn(.readbackMismatch) { show(.readbackEntry, page: current.page) { $0.insert = current.insert } }
    }

    /// The mismatch's "Show the insert": the insert in insert view, the verdicts wiped; its one way on is
    /// back to its read-back.
    func reviewInsert() {
        let current = state
        if pressOn(.readbackMismatch) {
            show(.words, page: current.page) {
                $0.insert = current.insert
                $0.reviewing = true
            }
        }
    }

    /// The reviewed insert's "Back to the read-back": that insert's entry, its letter pad empty.
    func backToReadback() {
        let current = state
        if pressOn(.words), current.reviewing { show(.readbackEntry, page: current.page) { $0.insert = current.insert } }
    }

    /// The read-back's end, Next: the wallet summary, core's (public).
    func showSummary() {
        guard pressOn(.readbackDone), let summary = done({ $0.summary() }) else { return }
        show(.wallet) { $0.summary = summary }
    }

    /// The wallet summary's Next: the encrypted backup's offer.
    func summaryDone() {
        if pressOn(.wallet) { show(.backupOffer) }
    }

    /// The offer's "Make an encrypted backup": core generates the 8-word passphrase (once), then its first
    /// page, through the privacy gate.
    func makeBackup() {
        if pressOn(.backupOffer), short({ $0.generateBackupPassphrase() }) { showPassphrase(0) }
    }

    /// Skip, on the offer or on the save screen: the watch-only offer, with no backup; the encrypted
    /// file, if core made one, is wiped as the save screen goes.
    func skipBackup() {
        if pressOn(.backupOffer) || pressOn(.backupSave) { show(.watchOffer) }
    }

    /// The passphrase's second page, "I wrote it down": the confirm's first question, its pad empty.
    func passphraseWritten() {
        guard pressOn(.backupPassphrase), state.page == 1, let challenge = done({ $0.backupChallenge() }) else { return }
        firstPick = -1
        backupLetters.wipe()
        show(.backupConfirm) { $0.challenge = challenge }
    }

    /// The confirm's Done, with three or four letters typed: the letters, handed over as a Secret and
    /// wiped once read, are matched in-process to the question's choice whose first four letters (all of a
    /// three-letter word's) they are. None matching is a wrong answer at once; the first pick waits for
    /// the second's, and the two go to core. Both right: core encrypts the backup in memory (a long call:
    /// scrypt), then the save screen. Wrong: the passphrase again from its first page, saying so.
    func confirmTyped() {
        let current = state
        guard let challenge = current.challenge, challenge.questions.indices.contains(current.page) else { return }
        let question = challenge.questions[current.page]
        guard pressOn(.backupConfirm), backupLetters.length >= readbackMinLetters else { return }
        let pick = backupLetters.handOver { letters in
            question.choices.firstIndex { CeremonyModel.begins($0, letters) } ?? -1
        }
        if pick < 0 {
            wrongConfirm()
            return
        }
        if current.page == 0 {
            firstPick = pick
            show(.backupConfirm, page: 1) { $0.challenge = challenge }
            return
        }
        let first = firstPick
        firstPick = -1
        guard let right = done({ $0.confirmBackup(first, pick) }) else { return }
        if !right {
            wrongConfirm()
            return
        }
        work({ $0.encryptBackup() }) { [self] file in
            backupFile = file
            show(.backupSave) { $0.backupName = file.name }
        }
    }

    /// The save screen's Save (or Save again): the system's create-document picker, its suggested name
    /// core's, with the encrypted file's bytes (the iPhone's exporter writes them); the place it gives comes
    /// to backupPlaced.
    func saveBackup(_ pickers: DocumentPickers) {
        guard let file = backupFile else { return }
        openPicker(.backupSave) { pickers.create(name: file.name, bytes: file.bytes) }
    }

    /// The create-document picker's answer, while the save screen shows (a late answer does nothing):
    /// none, and the save screen stays; a place, and core's bytes go there in one write, then the file
    /// there is read back (at most one byte past core's limit) and core verifies it (a long call) before
    /// "Backup verified". A write or a read-back that fails, or a verify that refuses, returns to the save
    /// screen naming that step; the session and the encrypted file stay, for Save again. The bytes read
    /// back are wiped once core has them. Any answer frees the picker's buttons.
    func backupPlaced(_ place: DocumentPlace?) {
        pickerUp = false
        guard let file = backupFile, !busy(), state.screen == .backupSave else { return }
        timers.input()
        guard let place else { return }
        if !place.write(file.bytes) {
            show(.backupSave) {
                $0.backupName = file.name
                $0.saveFailure = SaveFailure(step: .write)
            }
            return
        }
        guard let read = place.readBack(limit: Core.backupMaxBytes) else {
            show(.backupSave) {
                $0.backupName = file.name
                $0.saveFailure = SaveFailure(step: .readBack)
            }
            return
        }
        work({ core in
            defer { read.wipe() }
            return core.verifyBackup(read)
        }, refused: { [self] refusal in
            if isBackupRefusal(refusal) {
                show(.backupSave) {
                    $0.backupName = file.name
                    $0.saveFailure = SaveFailure(step: .verify, refusal: refusal)
                }
            } else {
                failClosed()
            }
        }) { [self] _ in show(.backupVerified) }
    }

    /// "Backup verified"'s Next: the watch-only offer.
    func backupVerifiedDone() {
        if pressOn(.backupVerified) { show(.watchOffer) }
    }

    /// The watch-only offer's "Show watch-only QRs": the BIP39 passphrase's question, asked first.
    func showWatchOnly() {
        if pressOn(.watchOffer) { show(.bip39Ask) }
    }

    /// The watch-only offer's Skip: the registration's offer, with no export.
    func skipWatchOnly() {
        if pressOn(.watchOffer) { show(.registerOffer) }
    }

    /// The question's "No BIP39 passphrase": core's export of this seed (a short call), then its summary.
    func noBip39Passphrase() {
        guard pressOn(.bip39Ask), let export = done({ $0.watchOnly(passphrase: nil) }) else { return }
        show(.watchSummary) { $0.watch = export }
    }

    /// The question's "I use a passphrase": its entry, the ASCII pad empty, through the privacy gate.
    func withBip39Passphrase() {
        guard pressOn(.bip39Ask) else { return }
        bip39Letters.wipe()
        show(.bip39Entry)
    }

    /// The BIP39 passphrase's Done, with at least one character typed: the passphrase, handed over as a
    /// Secret and wiped once core has it, makes core's export of that passphrase's wallet, then its summary.
    func bip39Typed() {
        guard pressOn(.bip39Entry), bip39Letters.length > 0 else { return }
        let reply = bip39Letters.handOver { passphrase in call { $0.watchOnly(passphrase: passphrase) } }
        guard case .done(let export) = reply else {
            settle(reply)
            return
        }
        show(.watchSummary) { $0.watch = export }
    }

    /// The watch-only summary's Next: the account QR for Sparrow, through the privacy gate.
    func watchSummaryDone() {
        let current = state
        if pressOn(.watchSummary) { show(.watchAccountQr) { $0.watch = current.watch } }
    }

    /// The descriptor QR's Done: the registration's offer; the export goes, its QRs wiped.
    func watchDone() {
        if pressOn(.watchDescriptorQr) { show(.registerOffer) }
    }

    /// The registration's offer's "Show registration QR": core's QR of this seed's seal code, through the
    /// privacy gate.
    func showRegistration() {
        guard pressOn(.registerOffer), let registration = done({ $0.registration() }) else { return }
        show(.registerQr) { $0.registration = registration }
    }

    /// The registration's offer's Skip: D's offer in Mixed mode, else the checklist.
    func skipRegistration() {
        if pressOn(.registerOffer) { afterRegistration() }
    }

    /// The registration QR's Done: as Skip, the QR wiped.
    func registrationDone() {
        if pressOn(.registerQr) { afterRegistration() }
    }

    /// D's offer's "Show D", offered in Mixed mode alone: core's D, in a Secret, through the privacy gate.
    func showDeviceLeg() {
        guard pressOn(.revealDOffer), let leg = done({ $0.revealDeviceLeg() }) else { return }
        show(.revealD) { $0.deviceLeg = leg }
    }

    /// D's offer's Skip: the checklist.
    func skipDeviceLeg() {
        if pressOn(.revealDOffer) { show(.checklist) }
    }

    /// D's Done: the checklist, D wiped.
    func deviceLegDone() {
        if pressOn(.revealD) { show(.checklist) }
    }

    /// The checklist's Finish: core ends the session (the words go), and Home follows; a loaded snapshot
    /// stays.
    func finishCeremony() {
        guard pressOn(.checklist), short({ $0.end() }) else { return }
        session = false
        show(.home)
    }

    /// Home's Check a backup: the system's open-document picker; the file it gives comes to backupPicked.
    func checkBackup(_ pickers: DocumentPickers) {
        openPicker(.home) { pickers.openBackup() }
    }

    /// The open-document picker's answer, while Home shows: a file refused unless its name ends in .age
    /// (any letter case) and its provider sizes it within core's limit, both before any byte is read, then
    /// read on the worker behind "Working...", which stops one byte past the limit. A file that passes
    /// goes to the passphrase's entry, word 1 of 8, through the privacy gate, its bytes kept for core in a
    /// Secret and, with the entries typed, held under the timers and the offline rule from here (holds).
    func backupPicked(_ file: PickedFile?) {
        picked(file, suffix: Core.backupSuffix, limit: Core.backupMaxBytes, notNamed: .notAge, tooLarge: .tooLarge) { [self] bytes in
            checkFile = bytes
            dropEntries()
            backupLetters.wipe()
            show(.backupCheckEntry)
        }
    }

    /// The entry's Done, with three or four letters typed: the entry is taken as a Secret and the next
    /// word's entry follows; after the eighth, core opens the file with the eight (a long call: scrypt),
    /// and the entries are wiped once it returns. Opened: the slot holds the checked backup, and the
    /// result shows "Backup OK". Refused: the entry again from word 1, emptied, with core's text, and the
    /// file kept for another try.
    func entryTyped() {
        guard let file = checkFile, pressOn(.backupCheckEntry), backupLetters.length >= readbackMinLetters else { return }
        entries.append(backupLetters.take())
        if entries.count < passphraseWords {
            show(.backupCheckEntry, page: entries.count)
            return
        }
        let typed = entries
        work({ core in
            defer {
                for entry in typed {
                    entry.wipe()
                }
            }
            return core.openBackup(entries: typed, file: file)
        }, refused: { [self] refusal in
            if isBackupRefusal(refusal) {
                dropEntries()
                show(.backupCheckEntry) { $0.entryRefusal = refusal }
            } else {
                failClosed()
            }
        }) { [self] opened in
            checked = opened
            session = true
            show(.backupCheckResult) { $0.opened = opened }
        }
    }

    /// The result's "Show the words": the checked backup's first insert, through the privacy gate.
    func showBackupWords() {
        if pressOn(.backupCheckResult) { showInsert(0) }
    }

    /// The checked backup's last insert's Done: back to the result, with no read-back.
    func backupWordsDone() {
        let current = state
        guard let insert = current.insert else { return }
        if pressOn(.words), current.opened != nil, current.page + 1 == insert.count {
            let checked = self.checked
            show(.backupCheckResult) { $0.opened = checked }
        }
    }

    /// The result's "Re-check QR": the seal's T alone, with no nonce (Public).
    func showRecheck() {
        let checked = self.checked
        if pressOn(.backupCheckResult) { show(.backupRecheck) { $0.opened = checked } }
    }

    /// The result's Done: core drops the checked backup and its words (end), and Home follows.
    func closeBackup() {
        guard pressOn(.backupCheckResult), short({ $0.end() }) else { return }
        session = false
        dropChecked()
        show(.home)
    }

    /// Home's Load registry snapshot: the system's open-document picker; the file comes to snapshotPicked.
    func loadSnapshot(_ pickers: DocumentPickers) {
        openPicker(.home) { pickers.openSnapshot() }
    }

    /// The open-document picker's answer for Load registry snapshot, while Home shows: a file refused
    /// unless its name ends in .kcr and its provider sizes it within core's limit, then read on the
    /// worker, as Check a backup's. The read's reply starts core's verification on the worker (a second
    /// long call), on today's UTC date, the bytes held until the load is over. Verified, the slot holds
    /// the snapshot and its header is the model's; refused, the result says why, and a snapshot loaded
    /// before stays.
    func snapshotPicked(_ file: PickedFile?) {
        picked(file, suffix: Core.snapshotSuffix, limit: Core.snapshotMaxBytes, notNamed: .notKcr, tooLarge: .snapshotTooLarge) { [self] bytes in
            snapshotFile = bytes
            let date = self.date
            work({ $0.loadSnapshot(today: date.today(), file: bytes) }, refused: { [self] refusal in
                if isSnapshotRefusal(refusal) {
                    show(.snapshot) { $0.snapshotRefusal = refusal }
                } else {
                    failClosed()
                }
            }) { [self] header in
                snapshot = header
                show(.snapshot)
            }
        }
    }

    /// Load registry snapshot's result's Done: Home, which names the snapshot loaded.
    func snapshotDone() {
        if pressOn(.snapshot) { show(.home) }
    }

    /// Home's About: the version, this build's flavour and the source address.
    func about() {
        if pressOn(.home) { show(.about) }
    }

    /// The platform's end of the model: everything the slot holds goes, the kept Wiped and a loaded
    /// snapshot too, a long call running drops its result, and every pad's entry, QR code, word page,
    /// verdict, passphrase page, confirm choice, export and D on show is wiped, with the backup's, Check
    /// a backup's and the snapshot's files; the motion source stops.
    func wipeAll() {
        running?.discarded = true
        session = false
        snapshot = nil
        _ = call { $0.wipeAll() }
        for pad in [dicePick, goAheadCode, readbackLetters, backupLetters, bip39Letters] {
            pad.wipe()
        }
        let current = state
        current.checkRequest?.wipe()
        current.report?.wipe()
        current.insert?.wipe()
        for insert in current.overview ?? [] {
            insert.wipe()
        }
        current.mismatch?.wipe()
        current.passphrase?.wipe()
        current.challenge?.wipe()
        current.watch?.wipe()
        current.registration?.wipe()
        current.deviceLeg?.wipe()
        dropBackupFile()
        dropCheckFile()
        dropSnapshotFile()
        dropEntries()
        dropChecked()
        motion.stop()
    }

    /// New seed or Dice-only seed, from Length, and every restart, which core takes from the kept Wiped:
    /// core's start and its known-answer suite, a long call. The slot then holds a session: Mixed mode
    /// goes on to Device entropy; dice-only mode commits and opens the dice at once.
    func start(_ words: Words, _ mode: Mode) {
        self.words = words
        self.mode = mode
        work({ $0.start(words, mode) }) { [self] _ in
            session = true
            switch mode {
            case .mixed:
                show(.deviceEntropy)
            case .diceOnly:
                if short({ $0.commit() }), short({ $0.startDice() }) { showDice() }
            }
        }
    }

    /// A long call (Android's work): core runs on the worker behind busy ("Working...", or the start-up
    /// self-test's screen), which takes no input. done gets the value on the main thread and may enter the
    /// next screen; if it enters none, the screen the call was started from comes back as it was. A
    /// refusal goes back to that screen and to refused (by default a halt: a refusal from a call that
    /// refuses nothing is the shell's bug). A discard while it runs has called core's discard at once, so
    /// the call returns discarded, or is never made when the worker sees the discard first; either way the
    /// start screen follows. A discard between the worker's look at the flag and the call reaches core
    /// first (onWorker): a call core offers at home runs, what it made is discarded again on the worker,
    /// and the start screen follows; one it does not offer there halts the slot (lead decision M5-54's
    /// residual, fail closed). One long call at a time: a second is the shell's bug, and halts, as does a
    /// busy screen that takes input. The busy screen keeps the QR codes, word pages, verdicts, passphrase
    /// page, confirm choices, opened backup, export and D of the screen it stands for, so that screen
    /// comes back with them whole. done may start the next long call: the busy screen then stays. A value
    /// a discard or a halt drops goes to dropped, on whichever thread drops it.
    func work<T>(
        _ body: @escaping (CeremonyCore) -> Reply<T>,
        busy: Screen = .working,
        refused: ((Refusal) -> Void)? = nil,
        dropped: @escaping (T) -> Void = { _ in },
        done: @escaping (T) -> Void
    ) {
        if running != nil || stopped() || !busy.isWorking {
            failClosed()
            return
        }
        let pending = Pending()
        running = pending
        if !state.screen.isWorking { from = state }
        let previous = from
        show(busy) {
            $0.checkRequest = previous.checkRequest
            $0.report = previous.report
            $0.insert = previous.insert
            $0.overview = previous.overview
            $0.mismatch = previous.mismatch
            $0.passphrase = previous.passphrase
            $0.challenge = previous.challenge
            $0.opened = previous.opened
            $0.watch = previous.watch
            $0.registration = previous.registration
            $0.deviceLeg = previous.deviceLeg
        }
        let handed = Handed<T>()
        let core = self.core
        let latch = self.latch
        worker.run({
            handed.reply = CeremonyModel.onWorker(pending, core, latch, body, dropped)
        }, then: { [weak self] in
            guard let self else {
                if case .done(let value) = handed.reply { dropped(value) }
                return
            }
            landed(pending, handed.reply, busy: busy, refused: refused, dropped: dropped, done: done)
        })
    }

    /// A long call's reply on the main thread (the rest of Android's work).
    private func landed<T>(
        _ pending: Pending, _ handed: Reply<T>?, busy: Screen, refused: ((Refusal) -> Void)?,
        dropped: (T) -> Void, done: (T) -> Void
    ) {
        if running === pending { running = nil }
        guard let reply = handed else {
            failClosed()
            return
        }
        if case .done(let value) = reply, stopped() || pending.discarded { dropped(value) }
        if stopped() { return }
        if case .halted = reply {
            halted()
            return
        }
        if pending.discarded {
            toStart(pending.notice)
            return
        }
        switch reply {
        case .done(let value):
            done(value)
            if running == nil, state.screen == busy { showFrom() }
        case .refused(let refusal):
            showFrom()
            if let refused {
                refused(refusal)
            } else {
                failClosed()
            }
        case .discarded:
            toStart(nil)
        case .halted:
            halted()
        }
    }

    /// A long call's part on the worker, which looks at the discard flag before the call and again after
    /// it (Android's onWorker). A discard before the first look means no call at all. One between the
    /// first look and the call reaches core first (lead decision M5-54): a call core offers at home runs,
    /// and the second look finds the flag, so what it made is discarded again here; one core does not
    /// offer at home halts the slot there, and its reply is the halt status. A discard during the call
    /// makes core return discarded. A value the second look drops goes to dropped here, on the worker.
    private static func onWorker<T>(
        _ pending: Pending, _ core: CeremonyCore, _ latch: HaltLatch, _ body: (CeremonyCore) -> Reply<T>,
        _ dropped: (T) -> Void
    ) -> Reply<T> {
        if pending.discarded { return .discarded }
        let reply = called(latch) { body(core) }
        switch reply {
        case .halted, .discarded:
            return reply
        case .done, .refused:
            if !pending.discarded { return reply }
        }
        if case .done(let value) = reply { dropped(value) }
        switch called(latch, { core.discard() }) {
        case .done:
            return .discarded
        case .halted(let reason):
            return .halted(reason)
        case .refused, .discarded:
            // A discard that is refused or overtaken breaks the bridge's contract: the slot halts.
            if case .halted(let reason) = called(latch, { core.shellHalt() }) { return .halted(reason) }
            return .halted(.internal)
        }
    }

    /// The start-up self-test, from First launch's Continue: core's known-answer suite, a long call behind
    /// its own screen, then Go offline; any reply but done halts.
    private func selfTest() {
        work({ $0.selfTest() }, busy: .selfTest) { [self] _ in
            started = true
            show(.goOffline)
        }
    }

    /// Leaving the app, going online, a timer's wipe or a screenshot: core's discard, at once, even during
    /// a long call. The stage and a checked backup go; the kept Wiped and a loaded snapshot
    /// stay. With a long call running, its screen stays until its reply, then the start screen; otherwise
    /// the start screen now, saying why. A discard that is refused or overtaken breaks the bridge's
    /// contract and halts (C5's rule).
    private func discard(_ notice: Notice) {
        let pending = running
        if let pending {
            pending.discarded = true
            pending.notice = notice
        }
        session = false
        dropChecked()
        switch call({ $0.discard() }) {
        case .done:
            break
        case .halted:
            halted()
            return
        case .refused, .discarded:
            failClosed()
            return
        }
        guard pending == nil else { return }
        if notice == .screenshot, !needsOffline(state.screen) {
            show(state.screen, notice: notice)
        } else {
            toStart(notice)
        }
    }

    /// The start screen after a discard: until the start-up self-test has passed, First launch, with
    /// nothing to say (no session was held); then, saying why the session went, Home while the phone is
    /// offline (Q81) and Go offline while it is online.
    private func toStart(_ notice: Notice?) {
        if !started {
            show(.firstLaunch)
            return
        }
        show(state.offline ? .home : .goOffline, notice: notice)
    }

    /// The state a long call came from, as it was (its page and public values), when the call entered no
    /// other screen.
    private func showFrom() {
        let previous = from
        show(previous.screen, page: previous.page) {
            $0.dice = previous.dice
            $0.commitment = previous.commitment
            $0.seal = previous.seal
            $0.checkRequest = previous.checkRequest
            $0.report = previous.report
            $0.registry = previous.registry
            $0.proof = previous.proof
            $0.skipped = previous.skipped
            $0.codeRefused = previous.codeRefused
            $0.scanStop = previous.scanStop
            $0.scanRefusal = previous.scanRefusal
            $0.insert = previous.insert
            $0.overview = previous.overview
            $0.reviewing = previous.reviewing
            $0.swapTo = previous.swapTo
            $0.matched = previous.matched
            $0.complete = previous.complete
            $0.mismatch = previous.mismatch
            $0.summary = previous.summary
            $0.passphrase = previous.passphrase
            $0.wrongConfirm = previous.wrongConfirm
            $0.challenge = previous.challenge
            $0.backupName = previous.backupName
            $0.saveFailure = previous.saveFailure
            $0.fileRefusal = previous.fileRefusal
            $0.entryRefusal = previous.entryRefusal
            $0.opened = previous.opened
            $0.watch = previous.watch
            $0.registration = previous.registration
            $0.deviceLeg = previous.deviceLeg
            $0.snapshotRefusal = previous.snapshotRefusal
        }
    }

    /// The dice screen with core's counts now.
    private func showDice() {
        guard let progress = done({ $0.diceProgress() }) else { return }
        show(.dice) { $0.dice = progress }
    }

    /// The words in insert view at index (0-based): core's word page of insert index + 1, the ceremony's
    /// or, at home, the checked backup's (opened then marks them so).
    private func showInsert(_ index: Int) {
        guard let insert = done({ $0.wordPage(index + 1) }) else { return }
        let checked = self.checked
        show(.words, page: index) {
            $0.insert = insert
            $0.opened = checked
        }
    }

    /// The overview's page (0-based): core's word pages of its four inserts. A halt partway leaves the
    /// pages already read wiped.
    private func showOverview(_ page: Int) {
        var inserts: [WordPage] = []
        for position in (page * overviewWords + 1)...(page * overviewWords + overviewWords) {
            guard let insert = done({ $0.wordPage(position) }) else {
                for read in inserts {
                    read.wipe()
                }
                return
            }
            inserts.append(insert)
        }
        let checked = self.checked
        show(.wordsOverview, page: page) {
            $0.overview = inserts
            $0.opened = checked
        }
    }

    /// The read-back entry of insert position (1-based), its letter pad empty, with core's word page.
    private func showReadback(_ position: Int) {
        guard let insert = done({ $0.wordPage(position) }) else { return }
        readbackLetters.wipe()
        show(.readbackEntry, page: position - 1) { $0.insert = insert }
    }

    /// The backup passphrase's page (0 or 1), core's four words in a Secret; wrong after a wrong confirm.
    private func showPassphrase(_ page: Int, wrong: Bool = false) {
        guard let text = done({ $0.backupPassphrasePage(page) }) else { return }
        show(.backupPassphrase, page: page) {
            $0.passphrase = text
            $0.wrongConfirm = wrong
        }
    }

    /// A wrong confirm: the first pick forgotten, the passphrase again from its first page, saying so.
    private func wrongConfirm() {
        firstPick = -1
        showPassphrase(0, wrong: true)
    }

    /// Whether letters are word's first four letters, or all of a three-letter word's (core's
    /// TypedBackupPassphrase::from_first_four): compared byte by byte, nothing copied.
    private static func begins(_ word: Secret, _ letters: Secret) -> Bool {
        let length = min(word.count, 4)
        return letters.count == length && (0..<length).allSatisfy { word[$0] == letters[$0] }
    }

    private func dropBackupFile() {
        backupFile?.bytes.wipe()
        backupFile = nil
    }

    private func dropCheckFile() {
        checkFile?.wipe()
        checkFile = nil
    }

    private func dropSnapshotFile() {
        snapshotFile?.wipe()
        snapshotFile = nil
    }

    private func dropEntries() {
        for entry in entries {
            entry.wipe()
        }
        entries.removeAll()
    }

    private func dropChecked() {
        checked?.wipe()
        checked = nil
    }

    /// A file the open-document picker gave, while Home shows (anywhere else it does nothing): none, and
    /// Home stays; a file refused unless its name ends in suffix (any letter case) and its provider
    /// reports a size within limit, both before any byte is read, then read on the worker behind
    /// "Working...", which stops one byte past limit (a provider that sized it wrongly is refused too, as is
    /// a read that fails). A refused file is never read, or its bytes are wiped, and Home says why. A
    /// discard during the read wipes what it read. The bytes of a file that passes go to passed. Any
    /// answer, a late one too, frees the picker's buttons.
    private func picked(
        _ file: PickedFile?, suffix: String, limit: Int, notNamed: FileRefusal, tooLarge: FileRefusal,
        passed: @escaping (Secret) -> Void
    ) {
        pickerUp = false
        if busy() || state.screen != .home { return }
        timers.input()
        guard let file else { return }
        var refusal: FileRefusal?
        if !(file.name.map { CeremonyModel.endsWith($0, suffix) } ?? false) {
            refusal = notNamed
        } else if let size = file.size {
            if size < 0 || size > Int64(limit) { refusal = tooLarge }
        } else {
            refusal = .noSize
        }
        if let refusal {
            show(.home) { $0.fileRefusal = refusal }
            return
        }
        work({ _ in .done(file.read(limit: limit)) }, dropped: { $0?.wipe() }) { [self] bytes in
            guard let bytes, bytes.count <= limit else {
                bytes?.wipe()
                show(.home) { $0.fileRefusal = bytes == nil ? .unreadable : tooLarge }
                return
            }
            passed(bytes)
        }
    }

    /// Whether name ends in suffix, in any letter case (ASCII), as the Pi lists its stick's files.
    private static func endsWith(_ name: String, _ suffix: String) -> Bool {
        let tail = Array(name.utf8.suffix(suffix.utf8.count))
        guard tail.count == suffix.utf8.count else { return false }
        return zip(tail, suffix.utf8).allSatisfy { lowered($0) == lowered($1) }
    }

    private static func lowered(_ byte: UInt8) -> UInt8 {
        (0x41...0x5A).contains(byte) ? byte + 0x20 : byte
    }

    /// A press on screen's button that opens a system picker over the app (Save, Check a backup, Load
    /// registry snapshot): through pressOn, and only while no picker the app opened is up; then the
    /// picker rule's exemption (pickerOpened) and the picker. Its answer, or the next resume, frees the
    /// buttons (Stage U's U2c).
    private func openPicker(_ screen: Screen, _ open: () -> Void) {
        if pickerUp || !pressOn(screen) { return }
        pickerUp = true
        pickerOpened()
        open()
    }

    /// After the registration: D's offer in Mixed mode, where D exists, else the checklist.
    private func afterRegistration() {
        show(mode == .mixed ? .revealDOffer : .checklist)
    }

    /// One of the check's screens after the seal card, with the seal and its check QR.
    private func showInCheck(_ screen: Screen, codeRefused: Bool = false, scanRefusal: Refusal? = nil) {
        let current = state
        show(screen) {
            $0.seal = current.seal
            $0.checkRequest = current.checkRequest
            $0.codeRefused = codeRefused
            $0.scanRefusal = scanRefusal
        }
    }

    /// Where a go-ahead led: the words are available, and the result names the Seal ID and says against
    /// what; or the seed was wiped unseen, and the collision result follows, drawing its seal.
    private func ended(_ revealed: Revealed, seal: SealCard?, proof: Bool = false) {
        switch revealed {
        case .clear(let registry):
            show(.checkResult) {
                $0.seal = seal
                $0.registry = registry
                $0.proof = proof
            }
        case .collision(let registry):
            show(.collision) {
                $0.seal = seal
                $0.registry = registry
                $0.proof = proof
            }
        }
    }

    /// Shows screen (its page, notice and the public values fill sets), through the privacy gate when it
    /// is Protected and the screen it leaves is not (a long call's screen stands for the screen its call
    /// came from). Away from the app the privacy cover stays up.
    private func show(_ screen: Screen, page: Int = 0, notice: Notice? = nil, _ fill: (inout UiState) -> Void = { _ in }) {
        let current = state
        let leaving = current.screen.isWorking ? from.screen : current.screen
        var next = UiState(screen: screen)
        next.page = page
        next.gate = screen.isProtected && !leaving.isProtected
        next.overlay = foreground ? nil : .cover
        next.recording = current.recording
        next.offline = current.offline
        next.notice = notice
        next.diceOnly = mode == .diceOnly
        next.twoDevices = words == .twentyFour
        next.loaded = snapshot
        fill(&next)
        enter(next)
    }

    /// The next state, and what a screen holds while it shows: the motion source runs only on Device
    /// entropy; each pad's entry is wiped when its screen leaves; a QR code, word page, verdicts,
    /// passphrase page, confirm choices, export or D the state held and the next one does not are wiped
    /// (rule 5). The backup's encrypted file is wiped once neither the save screen nor a long call shows,
    /// Check a backup's file and entries once neither its entry nor a long call does, and Load registry
    /// snapshot's file once no long call does.
    private func enter(_ next: UiState) {
        let previous = state
        let before = previous.screen
        state = next
        wipeLeaving(previous.checkRequest, next)
        wipeLeaving(previous.report, next)
        wipeLeaving(previous.insert, next)
        for insert in previous.overview ?? [] {
            wipeLeaving(insert, next)
        }
        if let mismatch = previous.mismatch, mismatch !== next.mismatch { mismatch.wipe() }
        if let passphrase = previous.passphrase, passphrase !== next.passphrase { passphrase.wipe() }
        if let challenge = previous.challenge, !CeremonyModel.same(challenge, next.challenge) { challenge.wipe() }
        if let watch = previous.watch, watch.account !== next.watch?.account { watch.wipe() }
        if let registration = previous.registration, registration !== next.registration { registration.wipe() }
        if let leg = previous.deviceLeg, leg !== next.deviceLeg { leg.wipe() }
        if !next.screen.isWorking, next.screen != .backupSave { dropBackupFile() }
        if !next.screen.isWorking, next.screen != .backupCheckEntry {
            dropCheckFile()
            dropEntries()
        }
        if !next.screen.isWorking { dropSnapshotFile() }
        if next.screen == before { return }
        if before == .deviceEntropy { motion.stop() }
        if before == .dice { dicePick.wipe() }
        if before == .codeEntry { goAheadCode.wipe() }
        if before == .readbackEntry { readbackLetters.wipe() }
        if before == .backupConfirm || before == .backupCheckEntry { backupLetters.wipe() }
        if before == .bip39Entry { bip39Letters.wipe() }
        if next.screen == .deviceEntropy { motion.start { [weak self] in self?.motionSample($0) } }
    }

    /// Whether a challenge is the one next holds (its first choice's Secret, the same object).
    private static func same(_ challenge: Challenge, _ next: Challenge?) -> Bool {
        guard let mine = challenge.questions.first?.choices.first, let theirs = next?.questions.first?.choices.first else {
            return false
        }
        return mine === theirs
    }

    /// Wipes matrix unless next holds it.
    private func wipeLeaving(_ matrix: QrMatrix?, _ next: UiState) {
        if let matrix, matrix !== next.checkRequest, matrix !== next.report { matrix.wipe() }
    }

    /// Wipes insert unless next holds it, on its words page, its read-back or its overview.
    private func wipeLeaving(_ insert: WordPage?, _ next: UiState) {
        guard let insert, insert !== next.insert, !(next.overview ?? []).contains(where: { $0 === insert }) else { return }
        insert.wipe()
    }

    /// The shell's own bug, failed closed: the slot halts, and the stop screen follows.
    private func failClosed() {
        _ = call { $0.shellHalt() }
        halted()
    }

    /// After a halt the slot holds nothing and answers every call with the halt status: the stop screen,
    /// which only ends the process and names the first halt's reason. A long call still running has its
    /// reply ignored.
    private func halted() {
        running?.discarded = true
        session = false
        dropChecked()
        var stop = UiState(screen: .stop)
        stop.recording = state.recording
        stop.halt = latch.reason
        enter(stop)
    }

    private func stopped() -> Bool { state.screen == .stop }

    /// A long call runs, or the stop screen shows: input goes no further.
    private func busy() -> Bool { stopped() || state.screen.isWorking }

    /// What the timers' warning and wipe and going online's discard apply to is held: a session, a restart
    /// or a checked backup, or Check a backup's file and entries before the opening.
    private func holds() -> Bool { session || checkFile != nil }

    /// A press on screen's control reaches the model only while that screen shows, uncovered and past any
    /// privacy gate, with no long call running; it is input for the idle timer.
    private func pressOn(_ screen: Screen) -> Bool {
        let current = state
        if busy() || current.screen != screen || current.overlay != nil || current.gate { return false }
        timers.input()
        return true
    }

    /// Where Back goes from screen: only where nothing is lost; nil elsewhere.
    private func backTo(_ screen: Screen) -> Screen? {
        switch screen {
        case .goOffline: return .firstLaunch
        case .home: return .goOffline
        case .length: return .home
        case .skipConfirm: return .checkPrompt
        case .checkQr: return .sealCard
        case .scan, .codeEntry, .matchFoundConfirm, .cannotCheckConfirm: return .checkQr
        case .bip39Entry: return .bip39Ask
        case .backupCheckEntry, .snapshot, .about: return .home
        case .backupRecheck: return .backupCheckResult
        case .selfTest, .firstLaunch, .deviceEntropy, .commitment, .dice, .checkPrompt, .sealCard, .collision,
             .collisionReport, .checkResult, .words, .wordsOverview, .deviceSwap, .readbackEntry, .readbackMismatch,
             .readbackDone, .wallet, .backupOffer, .backupPassphrase, .backupConfirm, .backupSave, .backupVerified,
             .watchOffer, .bip39Ask, .watchSummary, .watchAccountQr, .watchDescriptorQr, .registerOffer, .registerQr,
             .revealDOffer, .revealD, .checklist, .backupCheckResult, .working, .stop:
            return nil
        }
    }

    /// Whether screen needs the phone offline: every screen from Home on.
    private func needsOffline(_ screen: Screen) -> Bool {
        switch screen {
        case .selfTest, .firstLaunch, .goOffline, .working, .stop:
            return false
        case .home, .length, .deviceEntropy, .commitment, .dice, .checkPrompt, .skipConfirm, .sealCard, .checkQr, .scan,
             .codeEntry, .matchFoundConfirm, .cannotCheckConfirm, .collision, .collisionReport, .checkResult, .words,
             .wordsOverview, .deviceSwap, .readbackEntry, .readbackMismatch, .readbackDone, .wallet, .backupOffer,
             .backupPassphrase, .backupConfirm, .backupSave, .backupVerified, .watchOffer, .bip39Ask, .bip39Entry,
             .watchSummary, .watchAccountQr, .watchDescriptorQr, .registerOffer, .registerQr, .revealDOffer, .revealD,
             .checklist, .backupCheckEntry, .backupCheckResult, .backupRecheck, .snapshot, .about:
            return true
        }
    }

    /// The slot is collecting and Device entropy shows: extras go into the pool (until the commitment).
    private func collecting() -> Bool {
        session && running == nil && state.screen == .deviceEntropy
    }

    /// A motion sample from the motion source: into the pool while collecting; wiped either way.
    private func motionSample(_ sample: Secret) {
        if collecting() {
            extra(.motion, sample)
        } else {
            sample.wipe()
        }
    }

    /// An uncredited extra into the pool; its bytes are wiped once core has them (rule 5).
    private func extra(_ source: Extra, _ bytes: Secret) {
        let reply = call { $0.addExtra(source, bytes) }
        bytes.wipe()
        settle(reply)
    }

    /// A short call on the main thread that must be done: true when it was; anything else halts.
    private func short(_ body: (CeremonyCore) -> Reply<Void>) -> Bool {
        settle(call(body))
    }

    /// A short call's value; nil once anything else has halted.
    private func done<T>(_ body: (CeremonyCore) -> Reply<T>) -> T? {
        let reply = call(body)
        if case .done(let value) = reply { return value }
        settle(reply)
        return nil
    }

    /// What a short call's reply leads to: true for done. The halt status ends on the stop screen, and a
    /// refusal or a discard, which no short call the screens make can give, is the shell's bug and halts.
    @discardableResult
    private func settle<T>(_ reply: Reply<T>) -> Bool {
        switch reply {
        case .done:
            return true
        case .halted:
            halted()
        case .refused, .discarded:
            failClosed()
        }
        return false
    }

    /// Every core call the model makes on the main thread: the first halt's reason is kept for the stop
    /// screen (Android's call, the app's one handler of KcHalt).
    private func call<T>(_ body: (CeremonyCore) -> Reply<T>) -> Reply<T> {
        CeremonyModel.called(latch) { body(core) }
    }

    /// A core call on whichever thread makes it, its halt's reason kept in latch.
    private static func called<T>(_ latch: HaltLatch, _ body: () -> Reply<T>) -> Reply<T> {
        let reply = body()
        if case .halted(let reason) = reply { latch.record(reason) }
        return reply
    }

    /// Zeroes bytes with memset_s; false if it did not.
    private static func wipe(_ bytes: inout [UInt8]) -> Bool {
        bytes.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return true }
            return memset_s(base, raw.count, 0, raw.count) == 0
        }
    }
}

/// value's eight bytes, big-endian, into bytes from at.
private func putInt64(_ bytes: inout [UInt8], _ at: Int, _ value: Int64) {
    for index in 0..<8 {
        bytes[at + index] = UInt8(truncatingIfNeeded: value >> (56 - 8 * index))
    }
}
