package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.BackupFile
import com.keepcrypt.entropy.ffi.Challenge
import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.DiceProgress
import com.keepcrypt.entropy.ffi.Extra
import com.keepcrypt.entropy.ffi.HaltReason
import com.keepcrypt.entropy.ffi.KcHalt
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.OpenedBackup
import com.keepcrypt.entropy.ffi.QrMatrix
import com.keepcrypt.entropy.ffi.Readback
import com.keepcrypt.entropy.ffi.Refusal
import com.keepcrypt.entropy.ffi.RefusalGroup
import com.keepcrypt.entropy.ffi.RegistryHeader
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Revealed
import com.keepcrypt.entropy.ffi.SealCard
import com.keepcrypt.entropy.ffi.Secret
import com.keepcrypt.entropy.ffi.Summary
import com.keepcrypt.entropy.ffi.WatchOnly
import com.keepcrypt.entropy.ffi.WordPage
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
 * What the screens draw (tasks/todo.md, M5 groups 14-18; lead decision M5-49): the screen's id and
 * page index, flags about it, and the public values a screen shows (the dice counts, C, the seal card,
 * the check QR, a snapshot's or proof's header, why a scan stopped, the wallet summary, the loaded
 * snapshot's header), never a secret but through a Secret reference: the QR codes are QrMatrix, the
 * words WordPage and a read-back's verdicts Readback.Mismatch, each holding its bytes in a Secret, and
 * the model wipes each one when no screen holds it any more (the collision report's carries the
 * destroyed seed's seal code). The backup (commit 20) holds its passphrase's page and its confirm's
 * choices so, each a Secret; its file is ciphertext, which the model keeps out of the state, and Check
 * a backup's opened backup holds public values only (its words stay in the slot). The other exports
 * (commit 21) hold theirs the same way: the watch-only export's QRs (the xpub) and the registration QR
 * (the seal code) are QrMatrix, and D a Secret.
 */
data class UiState(
    val screen: Screen,
    /**
     * The screen's page index: the words' or the overview's page, a read-back's insert, the backup
     * passphrase's page or its confirm's question, Check a backup's word, the BIP39 entry's page of keys.
     */
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
     * the seal card holds it for its next page, the check QR, and the code entry and the confirm screens
     * keep it too, so their Back finds the same check and nonce.
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
    /**
     * The insert on show (a WordPage, whose bytes a Secret holds): the words page's, page + 1, and the
     * read-back's (its entry, its match and its mismatch), from which they name its position and device.
     */
    val insert: WordPage? = null,
    /** The overview's four inserts, page's (words 4 x page + 1 to 4 x page + 4). */
    val overview: List<WordPage>? = null,
    /** The words page shows a read-back mismatch's insert: its one way on is back to that insert's read-back. */
    val reviewing: Boolean = false,
    /** The device swap's way on: the words page or the overview (swapTo) at page, the first of device 2 of 2. */
    val swapTo: Screen? = null,
    /** The read-back entry's insert matched: the screen shows the whole word, and Next. */
    val matched: Boolean = false,
    /** With matched: every insert has now matched, so Next leads to the read-back's end. */
    val complete: Boolean = false,
    /** The read-back mismatch's verdicts, face by face (held in a Secret), wiped when its screen leaves. */
    val mismatch: Readback.Mismatch? = null,
    /** The wallet summary (public, as the Pi's, Q29): the fingerprint and the first receive address. */
    val summary: Summary? = null,
    /** The seed has 24 words, on two devices (device 1 of 2 holds words 1-12), which the checklist says. */
    val twoDevices: Boolean = false,
    /** The backup passphrase's page on show (core's four words, held in a Secret), wiped when its screen leaves. */
    val passphrase: Secret? = null,
    /** The confirm found a wrong word: the passphrase shows again from its first page, saying so; the questions stay. */
    val wrongConfirm: Boolean = false,
    /** The confirm's two questions of four choices (each choice a Secret), page the one on show; wiped when the confirm leaves. */
    val challenge: Challenge? = null,
    /** The encrypted backup's suggested name on the save screen (public: "keepcrypt-backup-" and 8 random hex digits). */
    val backupName: String? = null,
    /** Why the last save failed, naming its step: the save screen says so, and the session stays. */
    val saveFailure: SaveFailure? = null,
    /** Why Check a backup opened no file (its name, its size or its read): Home says so. */
    val fileRefusal: FileRefusal? = null,
    /** Core refused the passphrase typed, or the file, on Check a backup's entry, which says so with core's text. */
    val entryRefusal: Refusal? = null,
    /**
     * Check a backup's opened backup (public: its fingerprint, seal card and re-check QR), on its result, its
     * re-check QR and its words, whose last insert then leads back to the result instead of to a read-back.
     */
    val opened: OpenedBackup? = null,
    /**
     * The watch-only export (its summary, public, Q29, and its account and descriptor QRs, each carrying
     * the xpub in a Secret), on the watch-only summary and its two QR screens; wiped when they go.
     */
    val watch: WatchOnly? = null,
    /** The registration QR (Protected: this seed's seal code), wiped when its screen leaves. */
    val registration: QrMatrix? = null,
    /** D on its screen (Protected: D and the rolls recreate the seed), in a Secret, wiped when the screen leaves. */
    val deviceLeg: Secret? = null,
    /** The loaded registry snapshot's header (public), which Home and Load registry snapshot's result name; the model's own, on every screen. */
    val loaded: RegistryHeader? = null,
    /** Core refused the snapshot picked (no registry key in this build, or a file that does not verify): the result says so. */
    val snapshotRefusal: Refusal? = null,
    /** Why the slot halted (a fixed code, the first halt's), on the stop screen alone, which names it in fixed text. */
    val halt: HaltReason? = null,
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
 *   which names the first halt's reason (KcHalt's) and which no input leaves; only its "Close app"
 *   does, which ends the process.
 * - A long call runs on the worker behind "Working..." (the start-up self-test behind its own
 *   screen), which takes no input (work); so does a picked file's read (lead decision M5-70 (g)).
 * - Leaving the app during a long call or on a Protected screen, and going online after the start-up
 *   (away from the app too: the offline monitor reports until the model's end), call core's discard
 *   at once, even during a long call; the call's discarded reply then returns the UI to its start
 *   screen (toStart). That start screen is certain for the long calls core offers at home, start, the
 *   self-test, Check a backup's openBackup and Load registry snapshot's loadSnapshot, and for a picked
 *   file's read, which makes no core call; finish, revealProof (the scanned go-ahead QR's check,
 *   commit 18), and the backup's encryptBackup and verifyBackup (commit 20), which it does not offer
 *   there, halt the slot instead when a discard reaches core between the worker's look at the discard
 *   flag and the call (fail closed: the stop screen; lead decision M5-54's residual, work). On a Public
 *   screen leaving puts the privacy cover up, and 60 s away wipes.
 * - The timers (Timers) cover, warn and wipe on each tick. While what their warning and wipe apply to is
 *   held (held), the phone keeps its screen on (lead decision M5-72 (b)).
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
 *   on the main thread, lead decision M5-54), and otherwise shows the seal card, then its check QR with
 *   the checker's answers, the scanned go-ahead QR (the scan screen, commit 18: its text is checked on
 *   the worker behind "Working..."), the typed go-ahead code, Match found and Cannot check (each one-way
 *   choice confirmed on its own screen). A wrong code, or a scanned QR core does not accept, is
 *   refused and the check stays, with its nonce. The check result names the Seal ID, and the
 *   collision result draws the destroyed seed's seal; after a scanned QR both say how many entries
 *   the seal's bucket holds, never a snapshot's total (lead decision M5-55). Match found wipes the seed
 *   unseen, then the collision-report QR (Protected) and "Add fresh entropy"; Cannot check wipes it and
 *   starts again. Both restarts are core's start from the kept Wiped, with the destroyed session's
 *   length and mode, so core sets the minimum (99 rolls after a collision).
 * - The words and the end of the ceremony (group 17; docs/mobile-apps.md, steps 10-12 and 17; the Pi's
 *   steps 8-10 and 15): the check result's "Show words" leads through the privacy gate ("I'm alone,
 *   show words", with the SeedBook's safety rules) to the words, one insert a page in insert view (its
 *   position, device, word, SeedBook number and faces 1-6, each page core's word page) and four a page
 *   in the overview, paged back and on; a 24-word seed's pages pass the device swap (Public, so the
 *   gate comes again) before word 13. The last insert starts the read-back: the first four letters of
 *   each insert in turn, typed on the letter pad and compared by core, a match showing the whole word
 *   and a mismatch each face's verdict (a mirror-pair misread named as one), from where the insert can
 *   be shown again or read again; once every insert has matched, the read-back's end, the wallet
 *   summary, the encrypted backup's offer, the other exports and the checklist, whose Finish ends the
 *   session in core (end) and returns Home. Every page's word pages and verdicts are wiped when it goes,
 *   and the typed letters when the entry goes.
 * - The encrypted backup (group 18; docs/mobile-apps.md, "Encrypted backup only" and step 13; the Pi's
 *   step 11, after the summary and before Finish): its offer, then core's 8-word passphrase, generated
 *   once, two pages of four (Protected, through the privacy gate), and its confirm, two questions of
 *   four choices, each answered with the word's first four letters on the letter pad (a three-letter
 *   word's three), matched to a choice in-process and the two picks handed to core; a wrong one shows
 *   the passphrase again, the questions the same. Core then encrypts in memory (a long call: scrypt),
 *   and the save screen offers the system's create-document picker with core's suggested name (the
 *   platform's DocumentPickers, the picker rule first). The place it gives takes one write of core's
 *   bytes, the file is read back and core verifies it (a long call) before "Backup verified"; a write,
 *   a read-back or a verify that fails names its step on the save screen, which offers Save again and
 *   Skip, and the session stays. The file's bytes are ciphertext, kept out of the state and zeroed when
 *   the save screen and its calls are over.
 * - The other exports (group 18; docs/mobile-apps.md, steps 14-16; docs/seal-watchonly-braille.md,
 *   "Watch-only export" and "Registering a new seal"; the Pi's steps 12-14, after the backup, its
 *   verified file or its Skip): each its offer (Public) and Skip. The watch-only export asks first
 *   whether a BIP39 passphrase is used; with one, its entry on the ASCII pad (Protected, through the
 *   privacy gate), handed to core as a Secret and wiped; then core's export (a short call) and its
 *   summary (Public, Q29: the fingerprint and the first receive address of that wallet, which says so
 *   for a passphrase's), the account QR for Sparrow and the descriptor QR for Bitcoin Core (Protected:
 *   each carries the xpub), paged back and on, the export wiped when they go. Then the registration's
 *   offer, which says to register once, and its QR (Protected: the seal code), once; then in Mixed mode
 *   alone D's offer, whose text is its warning, and D as 16 groups of 4 hex digits (Protected), wiped when
 *   it goes; a dice-only seed has no D, so the registration leads straight to the checklist.
 * - Check a backup (Home's, lead decision M5-48; docs/mobile-apps.md, "Checking a backup"): the system's
 *   open-document picker; the file it gives is refused unless its name ends in .age and its provider
 *   sizes it within core's limit, both before any byte is read; then it is read on the worker behind
 *   "Working..." (a slow provider never holds the main thread), the read stopping one byte past the
 *   limit, and its bytes are held in a Secret, wiped once the entry and its call are over. Then the
 *   passphrase's entry (Protected, through the gate): the first four letters of each of
 *   the 8 words on the letter pad, each entry taken as a Secret, and core opens the file with them (a
 *   long call: scrypt); a refusal returns to the entry, emptied, with core's text. Its result is Public:
 *   "Backup OK", the fingerprint and the Seal ID; the words, through the privacy gate on the words'
 *   screens, whose last insert leads back; the re-check QR; and Done, which ends it in core (end). From
 *   the read's acceptance the file and the entries typed are held under the timers and the offline
 *   rule as a session is (holds, as the Pi's BackupCheck stage holds them: docs/pi-firmware.md's
 *   warning and wipe "while a session or a checked backup is held"), until Back to Home, a discard, a
 *   halt, wipeAll or the opening; then the slot holds the checked backup under them as it holds a
 *   session: a discard, a timer's wipe or going online takes it, and Home follows only through Done.
 * - Load registry snapshot (Home's, lead decision M5-48; docs/mobile-apps.md, "Reading a snapshot"): the
 *   system's open-document picker; the file it gives is refused unless its name ends in .kcr and its
 *   provider sizes it within core's limit, both before any byte is read; then it is read on the worker
 *   behind "Working...", the read stopping one byte past the limit, as Check a backup's (so neither a
 *   slow provider nor a full-size snapshot, about 72 MiB, holds the main thread). Core verifies it on
 *   the worker (a second long call, which the read's reply starts) against this
 *   build's registry key, and its result (Public) shows its number, date, count and any freshness
 *   warning, or why core refused it (the shipping APK trusts no registry key yet). A verified snapshot
 *   is the model's (snapshotLoaded): Check now then runs the check against it on its own, and Home names
 *   it. It outlives sessions and discards, as the slot's does. A discard that lands after core loaded it
 *   but before the worker's second look (lead decision M5-54's window) leaves it in the slot but not
 *   here: Check now then shows the seal card, so the check goes to the checker, which fails toward
 *   asking, never toward the words.
 * - About (Home's): the version (every M5 build is a 0.0.0 development build), this build's flavour and
 *   the source address, as plain text; Back returns Home.
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
    private val mutableHeld = MutableStateFlow(false)

    /** What the screens draw. */
    val state: StateFlow<UiState> get() = mutable

    /**
     * Whether what the timers' warning and wipe apply to is held (holds): a session, a restart or a
     * checked backup, or Check a backup's file and entries from the read's acceptance. While it is, the
     * phone keeps its screen on (:app's MainActivity; lead decision M5-72 (b)), since a screen timeout
     * stops the activity, which is leaving the app, and would discard a words page while its insert is
     * punched (docs/pi-firmware.md: "slow punching or scanning is never cut short"). It changes only with
     * what is held (the setters of session and checkFile), never by a timer of its own: nothing is held
     * on First launch, Go offline or Home, nor after Finish's end, Check a backup's Done or Back, a
     * discard (a timer's wipe among them), a halt or wipeAll; the 30 s cover and the 10-minute wipe stay
     * the timers'.
     */
    val held: StateFlow<Boolean> get() = mutableHeld

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

    /**
     * The read-back's letters as the entry's letter pad types them (a Protected screen: rule 5, a
     * PadEntry, never a String): readbackTyped hands them to core, which wipes them, and they are wiped
     * when the read-back entry leaves.
     */
    val readbackLetters: PadEntry = letterPadEntry()

    /**
     * The backup's letters as the letter pad types them on its Protected screens (rule 5: a PadEntry):
     * the confirm's answer, which confirmTyped matches to a choice in-process, and Check a backup's entry
     * of each word, which entryTyped takes as a Secret; wiped when either screen leaves.
     */
    val backupLetters: PadEntry = letterPadEntry()

    /**
     * The BIP39 passphrase as its entry's ASCII pad types it (a Protected screen: rule 5, a PadEntry, up to
     * 100 printable ASCII characters): bip39Typed hands it to core as a Secret, and it is wiped when the
     * entry leaves.
     */
    val bip39Letters: PadEntry = asciiPadEntry()

    /** The encrypted backup core made in memory (ciphertext, never in the state), from its encryption until the save screen and its calls are over. */
    private var backupFile: BackupFile? = null

    /** The confirm's first answer, a choice's index (0-3), until the second is typed; -1 for none. */
    private var firstPick = -1

    /**
     * The file Check a backup read (its bytes, at most core's limit, in a Secret), while its passphrase's
     * entry and its call last. held follows it.
     */
    private var checkFile: Secret? = null
        set(value) {
            field = value
            mutableHeld.value = holds()
        }

    /**
     * The file Load registry snapshot read (its bytes, at most core's limit), while core's load of it
     * lasts: zeroed once the load is over, by its result, a discard, a halt or wipeAll, including a load
     * a discard or a halt left uncalled.
     */
    private var snapshotFile: ByteArray? = null

    /** Check a backup's entries typed so far, each a word's first four letters (or three) in a Secret, wiped with the entry. */
    private val entries = ArrayList<Secret>(PASSPHRASE_WORDS)

    /** The entries held now, a copy of the list (never drawn): the tests' look at their wiping, as PadEntry's zeroPastLength is. */
    internal val entriesHeld: List<Secret> get() = entries.toList()

    /** Check a backup's opened backup, while the slot holds it (from its opening until Done, a discard, a halt or wipeAll). */
    private var checked: OpenedBackup? = null

    /** The start-up self-test (First launch's Continue) has passed. */
    private var started = false

    /** The app is in the foreground (between its return and its leaving; a picker it opened included). */
    private var foreground = false

    /**
     * The slot holds a session, or waits at its restart after a check that ended without the words
     * (Match found, Cannot check or a collision, with the kept Wiped and, after a collision, its report),
     * or holds Check a backup's checked backup: from a start (or the backup's opening) until a discard, a
     * wipe or a halt. The timers and going online treat all three alike, as they treat Check a backup's
     * file and entries before the opening (holds); a discard takes the slot home either way, keeping the
     * Wiped (the 99-roll minimum stays). held follows it.
     */
    private var session = false
        set(value) {
            field = value
            mutableHeld.value = holds()
        }

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

    /**
     * The first halt's reason the model met (KcHalt's, which is the slot's first halt's; the shell's own
     * halt is the slot's too, internal unless the slot had halted before): set by call on whichever
     * thread meets the halt, and read on the main thread by halted, for the stop screen. It never
     * changes once set.
     */
    @Volatile
    private var haltReason: HaltReason? = null

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
     * while a session or Check a backup's file is held (holds) or a long call runs discards at once, and
     * the start screen, Go offline, says why; on a screen past Go offline with nothing held, Go offline
     * comes back, with nothing to say. Before the start-up self-test passes, and on First launch and Go
     * offline, only the state changes.
     */
    fun offlineChanged(airplaneMode: Boolean, wifiOff: Boolean) {
        if (stopped()) return
        val current = mutable.value.copy(airplaneMode = airplaneMode, wifiOff = wifiOff)
        mutable.value = current
        if (current.offline || !started) return
        if (holds() || running != null) {
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
     * the check prompt; the check QR to the seal card, and the scan screen, Match found's and Cannot
     * check's confirms and the code entry to the check QR, each with the same check and nonce and no core
     * call, the typed code wiped; on the words,
     * their overview and the backup passphrase the page before, as their Previous, and on the descriptor
     * QR the account QR; the BIP39 passphrase's entry to its question, the passphrase typed wiped, as
     * the Pi's KEY2 there; Check a backup's entry to Home, the file read and the letters typed wiped, as
     * the Pi's KEY2 there, and its re-check QR to its result; Load registry snapshot's result and About
     * to Home); anywhere else it does nothing, so it never ends a session, leaves a check, the read-back,
     * the backup, an export or a long call, or leaves the app.
     */
    fun back() {
        val current = mutable.value
        when (current.screen) {
            Screen.Words, Screen.WordsOverview, Screen.BackupPassphrase, Screen.WatchDescriptorQr -> {
                previousPage()
                return
            }
            else -> {}
        }
        val previous = backTo(current.screen) ?: return
        if (pressOn(current.screen)) show(previous, seal = current.seal, checkRequest = current.checkRequest, opened = current.opened)
    }

    /**
     * A key of the showing screen's pad (lead decision M5-72's U3e): the dice pad's face, which replaces
     * the pick (none at 256 rolls, where the pad is disabled); the go-ahead code's symbol; the letter
     * pad's letter on the read-back entry (none after a match), the backup's confirm and Check a backup's
     * entry; the ASCII pad's character on the BIP39 passphrase's entry, from its page on show alone. Like
     * every control's press it acts only through pressOn, so a key left under the cover, the warning or a
     * privacy gate, or left over from a screen that has gone, types nothing, and every key typed is input
     * for the idle timer, a touch's or an accessibility service's click alike. A key the pad does not show,
     * or past a full entry, changes nothing.
     */
    fun padKey(key: Char) {
        val current = mutable.value
        val entry = padEntry(current) ?: return
        if (!pressOn(current.screen)) return
        if (current.screen == Screen.Bip39Entry && key !in asciiPage(current.page)) return
        if (current.screen == Screen.Dice) entry.replace(key) else entry.type(key)
    }

    /**
     * The Delete beside the showing screen's pad, through pressOn as padKey: the last key typed (the dice
     * pad has none: a face replaces the pick). On Check a backup's entry, as the Pi's KEY1 on its one
     * entry buffer (pi/app/src/app.rs, typing), word N > 1's empty pad takes entry N - 1 back, its letters
     * in the pad minus its last one, and its Secret is wiped, so no copy of it outlives it; word 1's empty
     * pad does nothing.
     */
    fun padDelete() {
        val current = mutable.value
        val entry = padEntry(current) ?: return
        if (current.screen == Screen.Dice || !pressOn(current.screen)) return
        if (entry.length > 0 || current.screen != Screen.BackupCheckEntry) {
            entry.delete()
            return
        }
        val last = entries.removeLastOrNull() ?: return
        try {
            for (index in 0 until last.size - 1) entry.type(Char(last[index].toInt() and 0xFF))
        } finally {
            last.wipe()
        }
        show(Screen.BackupCheckEntry, page = entries.size)
    }

    /**
     * The pad the showing screen offers and the entry its keys type into, or null where none is offered:
     * the dice pad below 256 rolls, the code entry's, the read-back entry's before its match, the confirm's
     * and Check a backup's entry's (both backupLetters), and the BIP39 passphrase's entry's.
     */
    private fun padEntry(state: UiState): PadEntry? = when (state.screen) {
        Screen.Dice -> if ((state.dice?.rolls ?: MAX_ROLLS) < MAX_ROLLS) dicePick else null
        Screen.CodeEntry -> goAheadCode
        Screen.ReadbackEntry -> if (state.matched) null else readbackLetters
        Screen.BackupConfirm, Screen.BackupCheckEntry -> backupLetters
        Screen.Bip39Entry -> bip39Letters
        else -> null
    }

    /** The BIP39 passphrase's entry shows the ASCII pad's page of keys (the state's page there), the passphrase typed kept. */
    private fun keysPage(page: Int) {
        mutable.value = mutable.value.copy(page = page)
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
     * The prompt's "Check now (recommended)": the check starts (core draws its nonce), and from here
     * only a verified go-ahead reaches the words; the seal, which the prompt never shows, shows from
     * here on (lead decision M5-55). With a loaded snapshot the check runs against it at once, on
     * today's UTC date (the result warns of a Stale or Future snapshot), as a short call on the main
     * thread, since the FFI runs it under its lock as one (it only looks the seal up in the loaded
     * snapshot): no busy screen comes before its result, and no discard can land between a look at a
     * discard flag and the call (lead decision M5-54). Otherwise the seal card shows, holding the check QR
     * its next page draws.
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
     * The seal card's "Show check QR": its next page, the check QR with the checker's answers, the same
     * check and nonce (the Pi's seal card pages: the seal, then the check QR, then its actions; Back
     * returns to the seal).
     */
    fun showCheckQr() {
        if (pressOn(Screen.SealCard)) showInCheck(Screen.CheckQr)
    }

    /**
     * The check QR's "Scan go-ahead QR": the scan screen, with the same check and nonce. Its scanner
     * (the platform's) asks for the camera as the screen opens and hands its first text to
     * onGoAheadText; a stop without a code comes to scanStopped.
     */
    fun scanQr() {
        if (pressOn(Screen.CheckQr)) showInCheck(Screen.Scan)
    }

    /** The check QR's or the scan screen's "Type go-ahead code": the code entry, its pad empty. */
    fun typeCode() {
        if (pressOn(Screen.CheckQr) || pressOn(Screen.Scan)) showInCheck(Screen.CodeEntry)
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

    /** The check QR's "Match found": its confirm screen. */
    fun matchFound() {
        if (pressOn(Screen.CheckQr)) showInCheck(Screen.MatchFoundConfirm)
    }

    /** The check QR's "Cannot check": its confirm screen. */
    fun cannotCheck() {
        if (pressOn(Screen.CheckQr)) showInCheck(Screen.CannotCheckConfirm)
    }

    /**
     * The code entry's Done, with all 8 symbols typed: core verifies the code against this check's T
     * and nonce. A verified one reveals the words; one that does not verify is refused, and the code
     * entry says so with the check, its nonce and the check QR's actions kept (its Back), the typed
     * code wiped. The code is handed over as a Secret and wiped once core has it (PadEntry.handOver).
     */
    fun codeDone() {
        if (!pressOn(Screen.CodeEntry) || !goAheadCode.isFull) return
        val seal = mutable.value.seal
        val reply = goAheadCode.handOver { code -> call { Core.revealCode(code) } }
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

    /**
     * The check result's "Show words" (a verified go-ahead's, or Skip's): the first insert, through the
     * privacy gate, since the result is Public.
     */
    fun showWords() {
        if (pressOn(Screen.CheckResult)) showInsert(0)
    }

    /**
     * Next on the words (insert view) and the overview: the next page, while there is one; on a 24-word
     * seed, past word 12, the device swap first (the Pi's), then that view's next page. Nothing while a
     * mismatch's insert is reviewed, whose one way on is back to its read-back. On the backup passphrase:
     * its second page; on the account QR, the descriptor QR; on the BIP39 passphrase's entry, its "Next
     * keys": the ASCII pad's next page of keys, while there is one, the passphrase typed kept.
     */
    fun nextPage() {
        val current = mutable.value
        when (current.screen) {
            Screen.Words -> {
                val insert = current.insert ?: return
                val next = current.page + 1
                if (!pressOn(Screen.Words) || current.reviewing || next >= insert.count) return
                if (next == INSERTS_PER_DEVICE && insert.count > INSERTS_PER_DEVICE) {
                    show(Screen.DeviceSwap, page = next, swapTo = Screen.Words, opened = current.opened)
                } else {
                    showInsert(next)
                }
            }
            Screen.WordsOverview -> {
                val first = current.overview?.firstOrNull() ?: return
                val next = current.page + 1
                if (!pressOn(Screen.WordsOverview) || next * OVERVIEW_WORDS >= first.count) return
                if (next * OVERVIEW_WORDS == INSERTS_PER_DEVICE && first.count > INSERTS_PER_DEVICE) {
                    show(Screen.DeviceSwap, page = next, swapTo = Screen.WordsOverview, opened = current.opened)
                } else {
                    showOverview(next)
                }
            }
            Screen.BackupPassphrase -> if (pressOn(Screen.BackupPassphrase) && current.page == 0) showPassphrase(1)
            Screen.WatchAccountQr -> if (pressOn(Screen.WatchAccountQr)) show(Screen.WatchDescriptorQr, watch = current.watch)
            Screen.Bip39Entry -> if (pressOn(Screen.Bip39Entry) && current.page < ASCII_PAGES - 1) keysPage(current.page + 1)
            else -> {}
        }
    }

    /**
     * Previous on the words, the overview, the backup passphrase and the descriptor QR (and the system Back
     * there): the page before (the account QR before the descriptor QR), with no device swap (every page
     * names its device); nothing on the first page or while a mismatch's insert is reviewed. On the BIP39
     * passphrase's entry, its "Previous keys": the ASCII pad's page of keys before (the system Back there
     * is back's: the question).
     */
    fun previousPage() {
        val current = mutable.value
        when (current.screen) {
            Screen.Words -> if (pressOn(Screen.Words) && !current.reviewing && current.page > 0) showInsert(current.page - 1)
            Screen.WordsOverview -> if (pressOn(Screen.WordsOverview) && current.page > 0) showOverview(current.page - 1)
            Screen.BackupPassphrase -> if (pressOn(Screen.BackupPassphrase) && current.page > 0) showPassphrase(current.page - 1)
            Screen.WatchDescriptorQr -> if (pressOn(Screen.WatchDescriptorQr)) show(Screen.WatchAccountQr, watch = current.watch)
            Screen.Bip39Entry -> if (pressOn(Screen.Bip39Entry) && current.page > 0) keysPage(current.page - 1)
            else -> {}
        }
    }

    /** The words' "Overview": the overview's page that holds this insert (four words a page, for the paper copy). */
    fun toOverview() {
        val current = mutable.value
        if (pressOn(Screen.Words) && !current.reviewing) showOverview(current.page / OVERVIEW_WORDS)
    }

    /** The overview's "Insert view": the first insert of its page. */
    fun toInsertView() {
        val current = mutable.value
        if (pressOn(Screen.WordsOverview)) showInsert(current.page * OVERVIEW_WORDS)
    }

    /**
     * The device swap's Continue, once device 1 of 2 is closed and put away: the page it leads to,
     * device 2 of 2's first, through the privacy gate again, since the swap is Public.
     */
    fun swapDone() {
        val current = mutable.value
        if (!pressOn(Screen.DeviceSwap)) return
        when (current.swapTo) {
            Screen.Words -> showInsert(current.page)
            Screen.WordsOverview -> showOverview(current.page)
            else -> halt()
        }
    }

    /**
     * The last insert's "Start the read-back" (docs/seal-watchonly-braille.md, "Read-back from the
     * metal": mandatory, before the session ends): insert 1's read-back entry, its letter pad empty. A
     * checked backup's words have none (the Pi's).
     */
    fun startReadback() {
        val current = mutable.value
        val insert = current.insert ?: return
        if (pressOn(Screen.Words) && !current.reviewing && current.opened == null && current.page + 1 == insert.count) showReadback(1)
    }

    /**
     * The read-back entry's Done, with three or four letters typed (three for a blank fourth face; below
     * that, and after a match, it does nothing): core compares them with the insert's first four
     * letters. A match shows the whole word; a mismatch shows each face's verdict. The letters are
     * handed over as a Secret and wiped once core has them (PadEntry.handOver).
     */
    fun readbackTyped() {
        val current = mutable.value
        val insert = current.insert ?: return
        if (!pressOn(Screen.ReadbackEntry) || current.matched || readbackLetters.length < READBACK_MIN_LETTERS) return
        val reply = readbackLetters.handOver { letters -> call { Core.checkReadback(insert.position, letters) } }
        if (reply !is Reply.Done) {
            settle(reply)
            return
        }
        when (val readback = reply.value) {
            is Readback.Match ->
                show(Screen.ReadbackEntry, page = current.page, insert = insert, matched = true, complete = readback.complete)
            is Readback.Mismatch -> show(Screen.ReadbackMismatch, page = current.page, insert = insert, mismatch = readback)
        }
    }

    /**
     * Next after a match: the next insert's read-back, or once every insert has matched (core says so)
     * the read-back's end. A match on the last insert that core does not call complete is the shell's
     * bug, and halts.
     */
    fun readbackNext() {
        val current = mutable.value
        val insert = current.insert ?: return
        if (!pressOn(Screen.ReadbackEntry) || !current.matched) return
        when {
            current.complete -> show(Screen.ReadbackDone)
            insert.position < insert.count -> showReadback(insert.position + 1)
            else -> halt()
        }
    }

    /** The mismatch's "Read it again": the same insert's entry, its letter pad empty, the verdicts wiped. */
    fun readbackAgain() {
        val current = mutable.value
        if (pressOn(Screen.ReadbackMismatch)) show(Screen.ReadbackEntry, page = current.page, insert = current.insert)
    }

    /**
     * The mismatch's "Show the insert" (the Pi's KEY1 there): the insert in insert view, its faces to
     * compare with the metal face by face, the verdicts wiped; its one way on is back to its read-back.
     */
    fun reviewInsert() {
        val current = mutable.value
        if (pressOn(Screen.ReadbackMismatch)) show(Screen.Words, page = current.page, insert = current.insert, reviewing = true)
    }

    /** The reviewed insert's "Back to the read-back": that insert's entry, its letter pad empty. */
    fun backToReadback() {
        val current = mutable.value
        if (pressOn(Screen.Words) && current.reviewing) show(Screen.ReadbackEntry, page = current.page, insert = current.insert)
    }

    /** The read-back's end, Next: the wallet summary, core's (public: the fingerprint and the first receive address). */
    fun showSummary() {
        if (!pressOn(Screen.ReadbackDone)) return
        val summary = done { Core.summary() } ?: return
        show(Screen.Wallet, summary = summary.value)
    }

    /** The wallet summary's Next: the encrypted backup's offer, the first of the exports before the checklist (the Pi's step 11). */
    fun summaryDone() {
        if (pressOn(Screen.Wallet)) show(Screen.BackupOffer)
    }

    /**
     * The offer's "Make an encrypted backup": core generates the 8-word passphrase (once; the offer shows
     * only before it), then its first page, through the privacy gate (Protected).
     */
    fun makeBackup() {
        if (pressOn(Screen.BackupOffer) && short { Core.generateBackupPassphrase() }) showPassphrase(0)
    }

    /**
     * Skip, on the offer or on the save screen (where a save failed, or before one): the watch-only offer,
     * with no backup (the Pi's); the encrypted file, if core made one, is zeroed as the save screen goes.
     */
    fun skipBackup() {
        if (pressOn(Screen.BackupOffer) || pressOn(Screen.BackupSave)) show(Screen.WatchOffer)
    }

    /** The passphrase's second page, "I wrote it down": the confirm's first question, its letter pad empty. */
    fun passphraseWritten() {
        if (!pressOn(Screen.BackupPassphrase) || mutable.value.page != 1) return
        val challenge = done { Core.backupChallenge() } ?: return
        firstPick = -1
        backupLetters.wipe()
        show(Screen.BackupConfirm, challenge = challenge.value)
    }

    /**
     * The confirm's Done, with three or four letters typed (below that it does nothing): the letters,
     * handed over as a Secret and wiped once read (PadEntry.handOver), are matched in-process to the
     * question's choice whose first four letters (all of a three-letter word's) they are. None matching
     * is a wrong answer at once, as no choice can then be right; the first question's pick waits for the
     * second's, and the two go to core (confirmBackup). Both right: core drops its display copy of the
     * passphrase and encrypts the backup in memory (encryptBackup, a long call behind "Working...": scrypt
     * at log2 N = 18), then the save screen with core's suggested name. Wrong: the passphrase again from
     * its first page, saying so, the questions the same (the Pi's backup-confirm-wrong).
     */
    fun confirmTyped() {
        val current = mutable.value
        val questions = current.challenge?.questions ?: return
        if (current.page !in questions.indices) return
        val question = questions[current.page]
        if (!pressOn(Screen.BackupConfirm) || backupLetters.length < READBACK_MIN_LETTERS) return
        val pick = backupLetters.handOver { letters -> question.choices.indexOfFirst { begins(it, letters) } }
        if (pick < 0) {
            wrongConfirm()
            return
        }
        if (current.page == 0) {
            firstPick = pick
            show(Screen.BackupConfirm, page = 1, challenge = current.challenge)
            return
        }
        val first = firstPick
        firstPick = -1
        val right = done { Core.confirmBackup(first, pick) } ?: return
        if (!right.value) {
            wrongConfirm()
            return
        }
        work({ Core.encryptBackup() }) { file ->
            backupFile = file
            show(Screen.BackupSave, backupName = file.name)
        }
    }

    /**
     * The save screen's Save (or Save again): the system's create-document picker, its suggested name
     * core's, opened over the app after the picker rule's exemption (pickerOpened); the place it gives
     * comes to backupPlaced.
     */
    fun saveBackup(pickers: DocumentPickers) {
        val file = backupFile ?: return
        if (!pressOn(Screen.BackupSave)) return
        pickerOpened()
        pickers.create(file.name)
    }

    /**
     * The create-document picker's answer, while the save screen shows (a late answer, after a discard
     * say, does nothing): none, and the save screen stays; a place, and core's bytes go there in one
     * write, then the file there is read back (at most one byte past core's limit) and core verifies it
     * against this session (verifyBackup, a long call behind "Working...": scrypt) before "Backup
     * verified". A write or a read-back that fails, or a verify that refuses (core's text), returns to
     * the save screen naming that step; the session stays, and so does the encrypted file, for Save
     * again. The bytes read back are zeroed once core has them.
     */
    fun backupPlaced(place: DocumentPlace?) {
        val file = backupFile ?: return
        if (busy() || mutable.value.screen != Screen.BackupSave) return
        timers.input()
        if (place == null) return
        if (!place.write(file.bytes)) {
            show(Screen.BackupSave, backupName = file.name, saveFailure = SaveFailure(SaveStep.Write))
            return
        }
        val read = place.readBack(Core.BACKUP_MAX_BYTES)
        if (read == null) {
            show(Screen.BackupSave, backupName = file.name, saveFailure = SaveFailure(SaveStep.ReadBack))
            return
        }
        work(
            {
                try {
                    Core.verifyBackup(read)
                } finally {
                    read.fill(0)
                }
            },
            refused = { refusal ->
                if (isBackupRefusal(refusal)) {
                    show(Screen.BackupSave, backupName = file.name, saveFailure = SaveFailure(SaveStep.Verify, refusal))
                } else {
                    halt()
                }
            },
        ) { show(Screen.BackupVerified) }
    }

    /** "Backup verified"'s Next: the watch-only offer (the Pi's step 12). */
    fun backupVerifiedDone() {
        if (pressOn(Screen.BackupVerified)) show(Screen.WatchOffer)
    }

    /**
     * The watch-only offer's "Show watch-only QRs" (docs/mobile-apps.md, step 14; the Pi's step 12): the
     * BIP39 passphrase's question, asked before the export (swb, "Watch-only export": with a passphrase,
     * the export is that passphrase's wallet).
     */
    fun showWatchOnly() {
        if (pressOn(Screen.WatchOffer)) show(Screen.Bip39Ask)
    }

    /** The watch-only offer's Skip: the registration's offer, with no export. */
    fun skipWatchOnly() {
        if (pressOn(Screen.WatchOffer)) show(Screen.RegisterOffer)
    }

    /** The question's "No BIP39 passphrase": core's export of this seed (a short call), then its summary. */
    fun noBip39Passphrase() {
        if (!pressOn(Screen.Bip39Ask)) return
        val export = done { Core.watchOnly(null) } ?: return
        show(Screen.WatchSummary, watch = export.value)
    }

    /** The question's "I use a passphrase": its entry, the ASCII pad empty, through the privacy gate (Protected). */
    fun withBip39Passphrase() {
        if (!pressOn(Screen.Bip39Ask)) return
        bip39Letters.wipe()
        show(Screen.Bip39Entry)
    }

    /**
     * The BIP39 passphrase's Done, with at least one character typed (with none it does nothing: core
     * refuses an empty passphrase, and "No BIP39 passphrase" is the way to leave it out): the passphrase,
     * handed over as a Secret and wiped once core has it (PadEntry.handOver), makes core's export of that
     * passphrase's wallet (a short call), then its summary, which says it is that wallet's.
     */
    fun bip39Typed() {
        if (!pressOn(Screen.Bip39Entry) || bip39Letters.length == 0) return
        val reply = bip39Letters.handOver { passphrase -> call { Core.watchOnly(passphrase) } }
        if (reply !is Reply.Done) {
            settle(reply)
            return
        }
        show(Screen.WatchSummary, watch = reply.value)
    }

    /** The watch-only summary's Next: the account QR for Sparrow, through the privacy gate (Protected: the xpub). */
    fun watchSummaryDone() {
        val current = mutable.value
        if (pressOn(Screen.WatchSummary)) show(Screen.WatchAccountQr, watch = current.watch)
    }

    /** The descriptor QR's Done: the registration's offer; the export goes, its QRs wiped (they carry the xpub). */
    fun watchDone() {
        if (pressOn(Screen.WatchDescriptorQr)) show(Screen.RegisterOffer)
    }

    /**
     * The registration's offer's "Show registration QR" (docs/seal-watchonly-braille.md, "Registering a
     * new seal"; the Pi's step 13): core's QR of this seed's seal code, through the privacy gate
     * (Protected); the offer comes once in a ceremony, and says to register once, never from a restore.
     */
    fun showRegistration() {
        if (!pressOn(Screen.RegisterOffer)) return
        val registration = done { Core.registration() } ?: return
        show(Screen.RegisterQr, registration = registration.value)
    }

    /** The registration's offer's Skip: D's offer in Mixed mode, else the checklist (the Pi's after_register). */
    fun skipRegistration() {
        if (pressOn(Screen.RegisterOffer)) afterRegistration()
    }

    /** The registration QR's Done: as Skip, the QR wiped. */
    fun registrationDone() {
        if (pressOn(Screen.RegisterQr)) afterRegistration()
    }

    /**
     * D's offer's "Show D" (docs/mobile-apps.md, step 16; the Pi's step 14), offered in Mixed mode alone,
     * where D exists (core halts the call in dice-only mode): core's D, in a Secret, through the privacy
     * gate (Protected), as 16 groups of 4 hex digits for verify.py on an offline computer.
     */
    fun showDeviceLeg() {
        if (!pressOn(Screen.RevealDOffer)) return
        val leg = done { Core.revealDeviceLeg() } ?: return
        show(Screen.RevealD, deviceLeg = leg.value)
    }

    /** D's offer's Skip: the checklist. */
    fun skipDeviceLeg() {
        if (pressOn(Screen.RevealDOffer)) show(Screen.Checklist)
    }

    /** D's Done: the checklist, D wiped. */
    fun deviceLegDone() {
        if (pressOn(Screen.RevealD)) show(Screen.Checklist)
    }

    /**
     * The checklist's Finish (docs/mobile-apps.md, step 17): core ends the session (end: the words go),
     * and Home follows, with no session held; a loaded snapshot stays, as on the Pi.
     */
    fun finishCeremony() {
        if (!pressOn(Screen.Checklist) || !short { Core.end() }) return
        session = false
        show(Screen.Home)
    }

    /**
     * Home's Check a backup (lead decision M5-48): the system's open-document picker, opened over the app
     * after the picker rule's exemption (pickerOpened); the file it gives comes to backupPicked.
     */
    fun checkBackup(pickers: DocumentPickers) {
        if (!pressOn(Screen.Home)) return
        pickerOpened()
        pickers.open()
    }

    /**
     * The open-document picker's answer, while Home shows (a late answer does nothing): none, and Home
     * stays; a file, refused unless its name ends in .age (any letter case, as the Pi lists them) and its
     * provider reports a size within core's limit, both before any byte is read, then read on the worker
     * behind "Working...", which stops one byte past the limit (a provider that sized it wrongly is
     * refused too). A refused file is never read, or its bytes are zeroed, and Home says why; a discard
     * during the read zeroes them, and the start screen follows (picked). A file that passes goes to the
     * passphrase's entry, word 1 of 8, through the privacy gate (Protected), its bytes kept for core in a
     * Secret and, with the entries typed, held under the timers and the offline rule from here (holds).
     */
    fun backupPicked(file: PickedFile?) {
        picked(file, Core.BACKUP_SUFFIX, Core.BACKUP_MAX_BYTES, FileRefusal.NotAge, FileRefusal.TooLarge) { bytes ->
            checkFile = Secret(bytes)
            dropEntries()
            backupLetters.wipe()
            show(Screen.BackupCheckEntry)
        }
    }

    /**
     * The entry's Done, with three or four letters typed (below that it does nothing): the entry is taken
     * as a Secret (the pad emptied), and the next word's entry follows; after the eighth, core opens the
     * file with the eight (openBackup, a long call behind "Working...": scrypt), and the entries are
     * wiped once it returns. Opened: the slot holds the checked backup, and the result shows "Backup OK".
     * Refused (an entry that names no word, a wrong passphrase, a file that does not read): the entry
     * again from word 1, emptied, with core's text, and the file kept for another try, as the Pi's.
     */
    fun entryTyped() {
        val file = checkFile ?: return
        if (!pressOn(Screen.BackupCheckEntry) || backupLetters.length < READBACK_MIN_LETTERS) return
        entries.add(backupLetters.take())
        if (entries.size < PASSPHRASE_WORDS) {
            show(Screen.BackupCheckEntry, page = entries.size)
            return
        }
        val typed = entries.toList()
        work(
            {
                try {
                    Core.openBackup(typed, file)
                } finally {
                    for (entry in typed) entry.wipe()
                }
            },
            refused = { refusal ->
                if (isBackupRefusal(refusal)) {
                    dropEntries()
                    show(Screen.BackupCheckEntry, entryRefusal = refusal)
                } else {
                    halt()
                }
            },
        ) { opened ->
            checked = opened
            session = true
            show(Screen.BackupCheckResult, opened = opened)
        }
    }

    /** The result's "Show the words": the checked backup's first insert, through the privacy gate (the result is Public). */
    fun showBackupWords() {
        if (pressOn(Screen.BackupCheckResult)) showInsert(0)
    }

    /** The checked backup's last insert's Done (the Pi's Press there): back to the result, with no read-back. */
    fun backupWordsDone() {
        val current = mutable.value
        val insert = current.insert ?: return
        if (pressOn(Screen.Words) && current.opened != null && current.page + 1 == insert.count) {
            show(Screen.BackupCheckResult, opened = checked)
        }
    }

    /** The result's "Re-check QR": the seal's T alone, with no nonce (Public). */
    fun showRecheck() {
        if (pressOn(Screen.BackupCheckResult)) show(Screen.BackupRecheck, opened = checked)
    }

    /** The result's Done (the Pi's): core drops the checked backup and its words (end), and Home follows. */
    fun closeBackup() {
        if (!pressOn(Screen.BackupCheckResult) || !short { Core.end() }) return
        session = false
        dropChecked()
        show(Screen.Home)
    }

    /**
     * Home's Load registry snapshot (lead decision M5-48; docs/mobile-apps.md, "Reading a snapshot"): the
     * system's open-document picker, opened over the app after the picker rule's exemption (pickerOpened);
     * the file it gives comes to snapshotPicked.
     */
    fun loadSnapshot(pickers: DocumentPickers) {
        if (!pressOn(Screen.Home)) return
        pickerOpened()
        pickers.openSnapshot()
    }

    /**
     * The open-document picker's answer for Load registry snapshot, while Home shows (a late answer does
     * nothing): none, and Home stays; a file, refused unless its name ends in .kcr (any letter case, as the
     * Pi lists them) and its provider reports a size within core's limit, both before any byte is read,
     * then read on the worker behind "Working...", which stops one byte past the limit, as Check a
     * backup's (picked). The read's reply starts core's verification on the worker, "Working..." still
     * showing (loadSnapshot, a long call: the signature, the entries and the bucket roots), on today's UTC
     * date, the bytes held by the model until the load is over (snapshotFile): its result, a discard, a
     * halt or wipeAll zeroes them, whether or not core's call was made. Verified, the slot holds the
     * snapshot and its header is the model's (snapshotLoaded): the result shows its number, date and count
     * and any freshness warning, and Check now runs the check against it on its own. Refused (no registry
     * key in this build, as the shipping APK until M9; a file that does not verify), the result says why,
     * and a snapshot loaded before stays, in the slot and here.
     */
    fun snapshotPicked(file: PickedFile?) {
        picked(file, Core.SNAPSHOT_SUFFIX, Core.SNAPSHOT_MAX_BYTES, FileRefusal.NotKcr, FileRefusal.SnapshotTooLarge) { bytes ->
            snapshotFile = bytes
            work(
                { Core.loadSnapshot(date.today(), bytes) },
                refused = { refusal -> if (isSnapshotRefusal(refusal)) show(Screen.Snapshot, snapshotRefusal = refusal) else halt() },
            ) { header ->
                snapshotLoaded(header)
                show(Screen.Snapshot)
            }
        }
    }

    /** Load registry snapshot's result's Done: Home, which names the snapshot loaded. */
    fun snapshotDone() {
        if (pressOn(Screen.Snapshot)) show(Screen.Home)
    }

    /** Home's About: the version, this build's flavour and the source address (its Back returns Home). */
    fun about() {
        if (pressOn(Screen.Home)) show(Screen.About)
    }

    /** The timers' step now: the platform calls it each second (runTimers), and every return to the app does. */
    fun tick() {
        if (busy()) return
        val current = mutable.value
        when (timers.step(isProtected(current.screen), holds())) {
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
     * kept Wiped and a loaded snapshot too, a long call running drops its result, the pads' entries, the
     * QR codes, word pages, verdicts, passphrase page, confirm choices, watch-only export and D on show,
     * the backup's file, Check a backup's file, entries and opened backup and Load registry snapshot's
     * file are wiped, and the motion source and the offline monitor stop. A halted slot holds nothing
     * already.
     */
    fun wipeAll() {
        running?.discarded = true
        session = false
        snapshot = null
        call { Core.wipeAll() }
        dicePick.wipe()
        goAheadCode.wipe()
        readbackLetters.wipe()
        backupLetters.wipe()
        bip39Letters.wipe()
        val current = mutable.value
        current.checkRequest?.wipe()
        current.report?.wipe()
        current.insert?.wipe()
        for (insert in current.overview.orEmpty()) insert.wipe()
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
     * revealProof (the scanned go-ahead QR's check), encryptBackup and verifyBackup (the backup's,
     * commit 20), which core does not offer at home, halt the slot (fail closed: the stop screen instead
     * of the start screen, in a window of microseconds; M5-54's residual); Check a backup's openBackup
     * and Load registry snapshot's loadSnapshot, which core offers at home, run as a start does. A halt is the stop screen. One long call
     * at a time: a second is the shell's bug, and halts, as does a busy screen that takes input. The
     * busy screen keeps the QR codes, word pages, verdicts, passphrase page, confirm choices, opened
     * backup, watch-only export and D of the screen it stands for (drawing none), so that screen comes
     * back with them whole; the next other screen wipes them. done may start the next long call (Load
     * registry snapshot's load, from its read's): the busy screen then stays, standing for the same
     * screen. A value a discard or a halt drops goes to dropped, on whichever thread drops it (a picked
     * file's read gives its bytes there to be zeroed), and so does a Done value the worker gave back to a
     * scope cancelled before the main thread took it (the holder's end, which cancels the scope before
     * its wipeAll: the main thread's part then never runs, and the finally its cancellation passes
     * through drops the value, on the main thread).
     */
    fun <T> work(
        core: () -> Reply<T>,
        busy: Screen = Screen.Working,
        refused: (Refusal) -> Unit = { halt() },
        dropped: (T) -> Unit = {},
        done: (T) -> Unit,
    ) {
        if (running != null || stopped() || !isWorking(busy)) {
            halt()
            return
        }
        val pending = Pending()
        running = pending
        if (!isWorking(mutable.value.screen)) from = mutable.value
        show(
            busy,
            checkRequest = from.checkRequest,
            report = from.report,
            insert = from.insert,
            overview = from.overview,
            mismatch = from.mismatch,
            passphrase = from.passphrase,
            challenge = from.challenge,
            opened = from.opened,
            watch = from.watch,
            registration = from.registration,
            deviceLeg = from.deviceLeg,
        )
        scope.launch {
            var handed: Reply<T>? = null
            val reply = try {
                withContext(worker) { onWorker(pending, core, dropped).also { handed = it } }.also { handed = null }
            } finally {
                val lost = handed
                if (lost is Reply.Done) dropped(lost.value)
            }
            if (running === pending) running = null
            if (reply is Reply.Done && (stopped() || pending.discarded)) dropped(reply.value)
            if (stopped()) return@launch
            when {
                reply == null -> halted()
                pending.discarded -> toStart(pending.notice)
                else -> when (reply) {
                    is Reply.Done -> {
                        done(reply.value)
                        if (running == null && mutable.value.screen == busy) showFrom()
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
     * and the call reaches core first (lead decision M5-54): a start, the self-test, Check a backup's
     * openBackup or Load registry snapshot's loadSnapshot, which core offers at home, then runs, and the second look finds the flag, so what it
     * made is discarded again here, on the worker, before its reply goes back (a cancelled scope, the
     * holder's end, which cancels it before wipeAll, cannot skip this, and a Done value it gives back to
     * that scope goes to dropped in work's finally, on the main thread); finish, revealProof,
     * encryptBackup and verifyBackup, which core does not offer at home, halt
     * the slot there, and their reply is the halt status (M5-54's residual: the stop screen, fail closed). A discard during the call makes core
     * return discarded, and one after the second look found the call done in core, so its own core
     * discard took what the call made. A discard during a picked file's read, which makes no core call,
     * is found by the second look, as one after a call core offers at home. A value the second look
     * drops goes to dropped here, on the worker. Null is the halt status.
     */
    private fun <T> onWorker(pending: Pending, core: () -> Reply<T>, dropped: (T) -> Unit): Reply<T>? {
        if (pending.discarded) return Reply.Discarded
        val reply = call(core) ?: return null
        if (reply is Reply.Discarded || !pending.discarded) return reply
        if (reply is Reply.Done) dropped(reply.value)
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
     * call. The stage and a checked backup go (its opened backup here too); the kept Wiped and a loaded
     * snapshot stay. With a long call running, its screen stays until its reply, then the start screen;
     * otherwise the start screen now, saying why.
     */
    private fun discard(notice: Notice) {
        val pending = running
        if (pending != null) {
            pending.discarded = true
            pending.notice = notice
        }
        session = false
        dropChecked()
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
            insert = previous.insert,
            overview = previous.overview,
            reviewing = previous.reviewing,
            swapTo = previous.swapTo,
            matched = previous.matched,
            complete = previous.complete,
            mismatch = previous.mismatch,
            summary = previous.summary,
            passphrase = previous.passphrase,
            wrongConfirm = previous.wrongConfirm,
            challenge = previous.challenge,
            backupName = previous.backupName,
            saveFailure = previous.saveFailure,
            fileRefusal = previous.fileRefusal,
            entryRefusal = previous.entryRefusal,
            opened = previous.opened,
            watch = previous.watch,
            registration = previous.registration,
            deviceLeg = previous.deviceLeg,
            snapshotRefusal = previous.snapshotRefusal,
        )
    }

    /** The dice screen with core's counts now. */
    private fun showDice() {
        val progress = done { Core.diceProgress() } ?: return
        show(Screen.Dice, dice = progress.value)
    }

    /**
     * The words in insert view at index (0-based): core's word page of insert index + 1, the ceremony's or,
     * at home, the checked backup's (opened then marks them so).
     */
    private fun showInsert(index: Int) {
        val insert = done { Core.wordPage(index + 1) } ?: return
        show(Screen.Words, page = index, insert = insert.value, opened = checked)
    }

    /**
     * The overview's page (0-based): core's word pages of its four inserts. A halt partway leaves the
     * pages already read wiped, since no state holds them.
     */
    private fun showOverview(page: Int) {
        val inserts = ArrayList<WordPage>(OVERVIEW_WORDS)
        for (position in page * OVERVIEW_WORDS + 1..page * OVERVIEW_WORDS + OVERVIEW_WORDS) {
            val insert = done { Core.wordPage(position) }
            if (insert == null) {
                for (read in inserts) read.wipe()
                return
            }
            inserts.add(insert.value)
        }
        show(Screen.WordsOverview, page = page, overview = inserts, opened = checked)
    }

    /** The read-back entry of insert position (1-based), its letter pad empty, with core's word page for its header and match. */
    private fun showReadback(position: Int) {
        val insert = done { Core.wordPage(position) } ?: return
        readbackLetters.wipe()
        show(Screen.ReadbackEntry, page = position - 1, insert = insert.value)
    }

    /**
     * The backup passphrase's page (0 or 1), core's four words in a Secret, through the privacy gate from
     * a Public screen; wrong after a wrong confirm, which the first page says.
     */
    private fun showPassphrase(page: Int, wrong: Boolean = false) {
        val text = done { Core.backupPassphrasePage(page) } ?: return
        show(Screen.BackupPassphrase, page = page, passphrase = text.value, wrongConfirm = wrong)
    }

    /** A wrong confirm: the first pick forgotten, the passphrase again from its first page, saying so. */
    private fun wrongConfirm() {
        firstPick = -1
        showPassphrase(0, wrong = true)
    }

    /**
     * Whether letters are word's first four letters, or all of a three-letter word's (core's
     * TypedBackupPassphrase::from_first_four, which completes them): compared byte by byte, nothing copied.
     */
    private fun begins(word: Secret, letters: Secret): Boolean {
        val length = minOf(word.size, 4)
        return letters.size == length && (0 until length).all { word[it] == letters[it] }
    }

    /** The backup's encrypted file, zeroed and dropped. */
    private fun dropBackupFile() {
        backupFile?.wipe()
        backupFile = null
    }

    /** Check a backup's file, wiped and dropped. */
    private fun dropCheckFile() {
        checkFile?.wipe()
        checkFile = null
    }

    /** Load registry snapshot's file, zeroed and dropped. */
    private fun dropSnapshotFile() {
        snapshotFile?.fill(0)
        snapshotFile = null
    }

    /** Check a backup's entries typed, each wiped, and none left. */
    private fun dropEntries() {
        for (entry in entries) entry.wipe()
        entries.clear()
    }

    /** Check a backup's opened backup, its re-check QR wiped, once the slot no longer holds the backup. */
    private fun dropChecked() {
        checked?.wipe()
        checked = null
    }

    /**
     * A file the open-document picker gave, while Home shows (a late answer, after a discard say, does
     * nothing): none, and Home stays; a file refused unless its name ends in suffix (any letter case, as
     * the Pi lists its stick's) and its provider reports a size within limit, both on the main thread
     * before any byte is read (notNamed or tooLarge, and an unknown size), then read on the worker behind
     * "Working..." (a long call: a slow provider or a full-size snapshot never holds the main thread,
     * lead decision M5-70 (g)), which stops one byte past limit (a provider that sized it wrongly is
     * refused too, tooLarge, as is a read that fails). A refused file is never read, or its bytes are
     * zeroed, and Home says why. A discard during the read (a leave or going online: the timers wait
     * while it runs) zeroes what it read, and the start screen follows, as after any long call. The bytes
     * of a file that passes go to passed, on the main thread, for it to zero.
     */
    private fun picked(file: PickedFile?, suffix: String, limit: Int, notNamed: FileRefusal, tooLarge: FileRefusal, passed: (ByteArray) -> Unit) {
        if (busy() || mutable.value.screen != Screen.Home) return
        timers.input()
        if (file == null) return
        val size = file.size
        val refusal = when {
            file.name?.endsWith(suffix, ignoreCase = true) != true -> notNamed
            size == null -> FileRefusal.NoSize
            size < 0 || size > limit -> tooLarge
            else -> null
        }
        if (refusal != null) {
            show(Screen.Home, fileRefusal = refusal)
            return
        }
        work({ Reply.Done(file.read(limit)) }, dropped = { bytes -> bytes?.fill(0) }) { bytes ->
            if (bytes == null || bytes.size > limit) {
                bytes?.fill(0)
                show(Screen.Home, fileRefusal = if (bytes == null) FileRefusal.Unreadable else tooLarge)
            } else {
                passed(bytes)
            }
        }
    }

    /**
     * Load registry snapshot's verified header: the slot holds that snapshot, so Check now runs the check
     * against it on its own (docs/mobile-apps.md, step 9) and Home names it, until wipeAll (it outlives
     * sessions and discards, as the slot's does).
     */
    private fun snapshotLoaded(header: RegistryHeader) {
        snapshot = header
    }

    /** After the registration (its QR or its Skip): D's offer in Mixed mode, where D exists, else the checklist (the Pi's after_register). */
    private fun afterRegistration() {
        show(if (mode == Mode.Mixed) Screen.RevealDOffer else Screen.Checklist)
    }

    /** One of the check's screens after the seal card, with the seal and its check QR (the same check and nonce). */
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
        insert: WordPage? = null,
        overview: List<WordPage>? = null,
        reviewing: Boolean = false,
        swapTo: Screen? = null,
        matched: Boolean = false,
        complete: Boolean = false,
        mismatch: Readback.Mismatch? = null,
        summary: Summary? = null,
        passphrase: Secret? = null,
        wrongConfirm: Boolean = false,
        challenge: Challenge? = null,
        backupName: String? = null,
        saveFailure: SaveFailure? = null,
        fileRefusal: FileRefusal? = null,
        entryRefusal: Refusal? = null,
        opened: OpenedBackup? = null,
        watch: WatchOnly? = null,
        registration: QrMatrix? = null,
        deviceLeg: Secret? = null,
        snapshotRefusal: Refusal? = null,
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
                insert = insert,
                overview = overview,
                reviewing = reviewing,
                swapTo = swapTo,
                matched = matched,
                complete = complete,
                mismatch = mismatch,
                summary = summary,
                twoDevices = words == Words.TwentyFour,
                passphrase = passphrase,
                wrongConfirm = wrongConfirm,
                challenge = challenge,
                backupName = backupName,
                saveFailure = saveFailure,
                fileRefusal = fileRefusal,
                entryRefusal = entryRefusal,
                opened = opened,
                watch = watch,
                registration = registration,
                deviceLeg = deviceLeg,
                loaded = snapshot,
                snapshotRefusal = snapshotRefusal,
            ),
        )
    }

    /**
     * The next state, and what a screen holds while it shows: the motion source runs only on Device
     * entropy; the dice pad's pick is wiped when the dice screen leaves, the typed go-ahead code when
     * the code entry does, the read-back's letters when its entry does, and the backup's letters when
     * its confirm or Check a backup's entry does, and the BIP39 passphrase when its entry does; a QR code,
     * word page, read-back verdicts, passphrase page, confirm choices, watch-only export or D the state
     * held and the next one does not are wiped (rule 5: the collision report's and the registration's
     * carry a seal code, the watch-only QRs the xpub, the words and verdicts are the seed's, the
     * passphrase opens its backup, and D and the rolls recreate the seed). The backup's encrypted file is zeroed once neither the save screen nor a long call shows,
     * Check a backup's file and entries once neither its entry nor a long call does, and Load registry
     * snapshot's file once no long call does.
     */
    private fun enter(next: UiState) {
        val previous = mutable.value
        val before = previous.screen
        mutable.value = next
        wipeLeaving(previous.checkRequest, next)
        wipeLeaving(previous.report, next)
        wipeLeaving(previous.insert, next)
        for (insert in previous.overview.orEmpty()) wipeLeaving(insert, next)
        val mismatch = previous.mismatch
        if (mismatch != null && mismatch !== next.mismatch) mismatch.wipe()
        val passphrase = previous.passphrase
        if (passphrase != null && passphrase !== next.passphrase) passphrase.wipe()
        val challenge = previous.challenge
        if (challenge != null && challenge !== next.challenge) challenge.wipe()
        val watch = previous.watch
        if (watch != null && watch !== next.watch) watch.wipe()
        val registration = previous.registration
        if (registration != null && registration !== next.registration) registration.wipe()
        val leg = previous.deviceLeg
        if (leg != null && leg !== next.deviceLeg) leg.wipe()
        if (!isWorking(next.screen) && next.screen != Screen.BackupSave) dropBackupFile()
        if (!isWorking(next.screen) && next.screen != Screen.BackupCheckEntry) {
            dropCheckFile()
            dropEntries()
        }
        if (!isWorking(next.screen)) dropSnapshotFile()
        if (next.screen == before) return
        if (before == Screen.DeviceEntropy) motion.stop()
        if (before == Screen.Dice) dicePick.wipe()
        if (before == Screen.CodeEntry) goAheadCode.wipe()
        if (before == Screen.ReadbackEntry) readbackLetters.wipe()
        if (before == Screen.BackupConfirm || before == Screen.BackupCheckEntry) backupLetters.wipe()
        if (before == Screen.Bip39Entry) bip39Letters.wipe()
        if (next.screen == Screen.DeviceEntropy) motion.start(this::motionSample)
    }

    /** Wipes matrix unless next holds it. */
    private fun wipeLeaving(matrix: QrMatrix?, next: UiState) {
        if (matrix != null && matrix !== next.checkRequest && matrix !== next.report) matrix.wipe()
    }

    /** Wipes insert unless next holds it, on its words page, its read-back or its overview. */
    private fun wipeLeaving(insert: WordPage?, next: UiState) {
        if (insert == null || insert === next.insert || next.overview.orEmpty().any { it === insert }) return
        insert.wipe()
    }

    /** The shell's own bug, failed closed: the slot halts, and the stop screen follows. */
    private fun halt() {
        call<Unit> { Core.halt() }
        halted()
    }

    /**
     * After a halt the slot holds nothing and answers every call with the halt status: the stop screen,
     * which only ends the process and names the first halt's reason. A long call still running has its
     * reply ignored.
     */
    private fun halted() {
        running?.discarded = true
        session = false
        dropChecked()
        enter(UiState(Screen.Stop, recording = mutable.value.recording, halt = haltReason))
    }

    private fun stopped(): Boolean = mutable.value.screen == Screen.Stop

    /** A long call runs, or the stop screen shows: input goes no further. */
    private fun busy(): Boolean = stopped() || isWorking(mutable.value.screen)

    /**
     * What the timers' warning and wipe and going online's discard apply to is held (docs/pi-firmware.md,
     * "Protected screens and idle": "while a session or a checked backup is held"): a session, a restart
     * or a checked backup (session), or Check a backup's file and entries before the opening (checkFile,
     * from the read's acceptance until the entry and its call are over), as the Pi's BackupCheck stage
     * holds them (holds_secrets); held is its value, kept by the setters of both.
     */
    private fun holds(): Boolean = session || checkFile != null

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
     * Where Back goes from screen: only where nothing is lost, before any session, in the check from the
     * check QR to the seal card and from a confirm screen or the code entry to the screen that offered it,
     * from the BIP39 passphrase's entry to its question, in Check a backup from its entry Home and from its
     * re-check QR to its result, and from Load registry snapshot's result and About Home; null elsewhere
     * (the words', the overview's, the backup passphrase's and the descriptor QR's page before is back's
     * own).
     */
    private fun backTo(screen: Screen): Screen? = when (screen) {
        Screen.GoOffline -> Screen.FirstLaunch
        Screen.Home -> Screen.GoOffline
        Screen.Length -> Screen.Home
        Screen.SkipConfirm -> Screen.CheckPrompt
        Screen.CheckQr -> Screen.SealCard
        Screen.Scan, Screen.CodeEntry, Screen.MatchFoundConfirm, Screen.CannotCheckConfirm -> Screen.CheckQr
        Screen.Bip39Entry -> Screen.Bip39Ask
        Screen.BackupCheckEntry, Screen.Snapshot, Screen.About -> Screen.Home
        Screen.BackupRecheck -> Screen.BackupCheckResult
        Screen.SelfTest, Screen.FirstLaunch, Screen.DeviceEntropy, Screen.Commitment, Screen.Dice, Screen.CheckPrompt,
        Screen.SealCard, Screen.Collision, Screen.CollisionReport, Screen.CheckResult, Screen.Words, Screen.WordsOverview,
        Screen.DeviceSwap, Screen.ReadbackEntry, Screen.ReadbackMismatch, Screen.ReadbackDone, Screen.Wallet,
        Screen.BackupOffer, Screen.BackupPassphrase, Screen.BackupConfirm, Screen.BackupSave, Screen.BackupVerified,
        Screen.WatchOffer, Screen.Bip39Ask, Screen.WatchSummary, Screen.WatchAccountQr, Screen.WatchDescriptorQr,
        Screen.RegisterOffer, Screen.RegisterQr, Screen.RevealDOffer, Screen.RevealD, Screen.Checklist,
        Screen.BackupCheckResult, Screen.Working, Screen.Stop -> null
    }

    /** Whether screen needs airplane mode on and Wi-Fi off (Q57): every screen from Home on, Check a backup's, Load registry snapshot's and About too. */
    private fun needsOffline(screen: Screen): Boolean = when (screen) {
        Screen.SelfTest, Screen.FirstLaunch, Screen.GoOffline, Screen.Working, Screen.Stop -> false
        Screen.Home, Screen.Length, Screen.DeviceEntropy, Screen.Commitment, Screen.Dice, Screen.CheckPrompt,
        Screen.SkipConfirm, Screen.SealCard, Screen.CheckQr, Screen.Scan, Screen.CodeEntry, Screen.MatchFoundConfirm,
        Screen.CannotCheckConfirm, Screen.Collision, Screen.CollisionReport, Screen.CheckResult, Screen.Words,
        Screen.WordsOverview, Screen.DeviceSwap, Screen.ReadbackEntry, Screen.ReadbackMismatch, Screen.ReadbackDone,
        Screen.Wallet, Screen.BackupOffer, Screen.BackupPassphrase, Screen.BackupConfirm, Screen.BackupSave,
        Screen.BackupVerified, Screen.WatchOffer, Screen.Bip39Ask, Screen.Bip39Entry, Screen.WatchSummary,
        Screen.WatchAccountQr, Screen.WatchDescriptorQr, Screen.RegisterOffer, Screen.RegisterQr, Screen.RevealDOffer,
        Screen.RevealD, Screen.Checklist, Screen.BackupCheckEntry, Screen.BackupCheckResult, Screen.BackupRecheck,
        Screen.Snapshot, Screen.About -> true
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
     * stop screen on the main thread; the first halt's reason is kept for it (haltReason).
     */
    private fun <T> call(core: () -> Reply<T>): Reply<T>? {
        try {
            return core()
        } catch (halt: KcHalt) {
            if (haltReason == null) haltReason = halt.reason
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
