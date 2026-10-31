package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.HaltReason
import com.keepcrypt.entropy.ffi.KcHalt
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Refusal
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.WordPage
import com.keepcrypt.entropy.ffi.Words
import kotlin.coroutines.CoroutineContext
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Runnable

// Test support for :screens' common tests (tasks/todo.md, M5 groups 14-16). The model's tests run it on
// the test's own thread: its main scope is unconfined, so a long call's reply is handled at once (or a
// HeldMain's, which can keep it), and its worker holds each long call until the test runs it, so the
// test can act while "Working..." shows. The clock, the offline monitor and the motion source are fakes the test moves; the UTC date is
// vectors/kcr.json's. The tests that reach the slot do so through Core over the host library, one test
// class per JVM (screens/build.gradle.kts), since a halt latches the process's slot for good.

/** A clock the test sets. */
internal class FakeClock : MonotonicClock {
    var now = 0L

    override fun nowMillis(): Long = now

    override fun nowNanos(): Long = now * 1_000_000
}

/**
 * The UTC date the model reads: vectors/kcr.json's own (2026-03-01, read when first asked), the date its
 * snapshots' freshness is pinned against, so the check's tests read each freshness on a fixed date; or
 * the day a test sets (YYYYMMDD), a later one where a freshness warning is the point.
 */
internal class FakeDate : UtcDate {
    var day: Int? = null

    override fun today(): Int = day ?: kcrToday()
}

/** A worker that keeps each long call until run, in order. */
internal class HeldWorker : CoroutineDispatcher() {
    private val held = ArrayDeque<Runnable>()

    /** How many long calls wait. */
    val waiting: Int get() = held.size

    /** How many long calls it has run. */
    var ran = 0
        private set

    override fun dispatch(context: CoroutineContext, block: Runnable) {
        held.addLast(block)
    }

    /** Runs every long call waiting, and what each one's reply leads to. */
    fun run() {
        while (held.isNotEmpty()) runNext()
    }

    /** Runs the first long call waiting, and what its reply leads to (a long call its reply starts then waits). */
    fun runNext() {
        held.removeFirst().run()
        ran += 1
    }
}

/**
 * A main thread the test can hold: until held, it runs everything at once, as the unconfined scope does;
 * once held, it keeps each continuation (a long call's start, its reply) until run, so the test can act
 * between the worker's reply and the main thread's part of it.
 */
internal class HeldMain : CoroutineDispatcher() {
    private val held = ArrayDeque<Runnable>()

    /** Whether it keeps what is dispatched to it. */
    var holding = false

    /** How many continuations wait. */
    val waiting: Int get() = held.size

    override fun isDispatchNeeded(context: CoroutineContext): Boolean = holding

    override fun dispatch(context: CoroutineContext, block: Runnable) {
        held.addLast(block)
    }

    /** Runs every continuation waiting, and what each one dispatches here in turn. */
    fun run() {
        while (held.isNotEmpty()) held.removeFirst().run()
    }
}

/** An offline monitor the test switches; it starts offline (airplane mode on, Wi-Fi off). */
internal class FakeOffline : OfflineMonitor {
    var airplaneMode = true
    var wifiOff = true
    var starts = 0
    private var report: ((Boolean, Boolean) -> Unit)? = null

    val started: Boolean get() = report != null

    /** What a start reads: offline or online, both states alike. */
    var offline: Boolean
        get() = airplaneMode && wifiOff
        set(value) {
            airplaneMode = value
            wifiOff = value
        }

    override fun start(report: (airplaneMode: Boolean, wifiOff: Boolean) -> Unit) {
        starts += 1
        this.report = report
        report(airplaneMode, wifiOff)
    }

    override fun stop() {
        report = null
    }

    /** The phone goes offline (airplane mode on, Wi-Fi off) or online (both the other way). */
    fun set(offline: Boolean) {
        set(offline, offline)
    }

    /** The phone's two states change. */
    fun set(airplaneMode: Boolean, wifiOff: Boolean) {
        this.airplaneMode = airplaneMode
        this.wifiOff = wifiOff
        report?.invoke(airplaneMode, wifiOff)
    }
}

/** A motion source the test drives: it counts its starts and keeps its last receiver, for a late sample. */
internal class FakeMotion : MotionSource {
    var starts = 0
    private var report: ((ByteArray) -> Unit)? = null
    private var last: ((ByteArray) -> Unit)? = null

    val running: Boolean get() = report != null

    override fun start(report: (sample: ByteArray) -> Unit) {
        starts += 1
        this.report = report
        last = report
    }

    override fun stop() {
        report = null
    }

    /** A sample from the phone, if the model is listening; false when it is not. */
    fun sample(bytes: ByteArray): Boolean {
        val receiver = report ?: return false
        receiver(bytes)
        return true
    }

    /** A sample that was on its way when the model stopped listening (an event queued before the stop). */
    fun late(bytes: ByteArray) {
        last?.invoke(bytes)
    }
}

/** A model over fakes, and the fakes; scope is the model's main scope (unconfined, unless a test gives its own: one it cancels, or a HeldMain's). */
internal class Rig(scope: CoroutineScope = CoroutineScope(Dispatchers.Unconfined)) {
    val clock = FakeClock()
    val date = FakeDate()
    val worker = HeldWorker()
    val offline = FakeOffline()
    val motion = FakeMotion()
    val model = CeremonyModel(scope, worker, clock, date, offline, motion, testRegistry = true)

    val screen: Screen get() = model.state.value.screen

    /** The app's first start: First launch, the first screen, before any core call (lead decision M5-50). */
    fun startUp(): Rig {
        model.appReturned()
        return this
    }

    /** Through the start and First launch's Continue, which runs the start-up self-test (its long call run), to Go offline. */
    fun toGoOffline(): Rig {
        startUp()
        model.firstLaunchDone()
        worker.run()
        return this
    }

    /** Through the start-up self-test and Go offline (the fake starts offline) to Home. */
    fun toHome(): Rig {
        toGoOffline()
        model.startOffline()
        return this
    }

    /**
     * A discard's landing (leaving the app, going online or a timer's wipe, Q57, once the start-up
     * self-test has passed; core's own discarded reply, with no notice): the start screen, saying why,
     * with nothing held. The start screen is Go
     * offline, as built (group 15, M5-50); where a wipe lands while the phone is still offline is the
     * owner's open Q81, and only this line names it (Stage U's U2b).
     */
    fun assertDiscarded(notice: Notice?, what: String = "the discard") {
        assertEquals(Screen.GoOffline, screen, what + ": the start screen")
        assertEquals(notice, model.state.value.notice, what + ": the notice")
        assertFalse(model.held.value, what + ": something is still held")
    }

    /** Every pad's entry, as its length: the dice's pick, the code, the read-back's, the backup's and Check a backup's letters, the BIP39 passphrase. */
    fun padLengths(): List<Int> = with(model) {
        listOf(dicePick, goAheadCode, readbackLetters, backupLetters, bip39Letters).map { it.length }
    }

    /** After a discard: no seal, check, report, word page, overview, verdict, summary, passphrase, challenge, opened backup, export or D on show, and every pad's entry wiped. */
    fun assertNothingSecretShown(what: String) {
        val state = model.state.value
        val shown = listOf(
            state.seal, state.checkRequest, state.report, state.insert, state.overview, state.mismatch, state.summary,
            state.passphrase, state.challenge, state.opened, state.watch, state.registration, state.deviceLeg,
        )
        assertTrue(shown.all { it == null }, "$what: something of the session is still on show")
        assertEquals(listOf(0, 0, 0, 0, 0), padLengths(), "$what: a pad's entry outlived the discard")
    }

    /** A key pressed on the showing screen's pad, on its page, as its screens make the press (the model's padKey). */
    fun press(key: Char) {
        model.padKey(screen, model.state.value.page, key)
    }

    /** keys pressed in turn on the showing screen's pad (press). */
    fun press(keys: String) {
        for (key in keys) press(key)
    }

    /** The Delete beside the showing screen's pad, on its page (the model's padDelete). */
    fun pressDelete() {
        model.padDelete(screen, model.state.value.page)
    }

    /** From Home through Length and the start (its long call run) to the ceremony's first screen. */
    fun begin(mode: Mode, words: Words): Rig {
        model.chooseMode(mode)
        model.chooseLength(words)
        worker.run()
        return this
    }

    /**
     * n rolls through the dice pad's keys (press) and Confirm, the faces 1 to 6 in turn from 1
     * on each call, so two calls are no vector's rolls (StartScreensTest pushes dice-50-words12's own rolls
     * where the faces matter).
     */
    fun roll(n: Int) {
        repeat(n) { index ->
            press(DICE_KEYS[index % DICE_KEYS.length])
            model.confirmRoll()
        }
    }

    /**
     * From Home: a dice-only seed of vectors/kcr.json's dice gate seed named seed (its rolls picked on the
     * pad's keys and confirmed), the dice's Done (finish, its long call run), then Skip and its confirm:
     * Skip's result, from where Show words leads to that seed's words (WordsScreensTest, ReadbackScreensTest).
     */
    fun toSkippedResult(seed: String): Rig {
        begin(Mode.DiceOnly, if (kcrWords(seed).size == 24) Words.TwentyFour else Words.Twelve)
        for (face in kcrRolls(seed)) {
            press(face)
            model.confirmRoll()
        }
        model.diceDone()
        worker.run()
        model.skip()
        model.skipConfirmed()
        return this
    }

    /** Skip's result's Show words, then the privacy gate's "I'm alone, show words": insert 1's page. */
    fun toWords(): Rig {
        model.showWords()
        model.passGate()
        return this
    }

    /**
     * From Home: the 12-word dice-only seed named seed to Skip's result (toSkippedResult), its words paged to
     * the last insert, every insert read back (its first four letters, a three-letter word's three, on the
     * pad's keys), the read-back's end and the wallet summary (BackupScreensTest, CheckBackupScreensTest).
     */
    fun toSummary(seed: String): Rig {
        val words = kcrWords(seed)
        check(words.size == INSERTS_PER_DEVICE)
        toSkippedResult(seed).toWords()
        repeat(words.size - 1) { model.nextPage() }
        model.startReadback()
        for (word in words) {
            press(word.take(4))
            model.readbackTyped()
            model.readbackNext()
        }
        model.showSummary()
        return this
    }

    /** The backup passphrase's words on the page on show, read in-process from its Secret (compared, never printed). */
    fun passphraseWords(): List<String> {
        val state = model.state.value
        val text = checkNotNull(state.passphrase) { "no passphrase page on show" }
        return passphraseLines(state.page, text).map { it.substringAfter(' ') }
    }

    /**
     * From the wallet summary: the offer's "Make an encrypted backup", the privacy gate, the passphrase's
     * two pages read in-process, then "I wrote it down"; the eight words, in order.
     */
    fun toConfirm(): List<String> {
        model.summaryDone()
        model.makeBackup()
        model.passGate()
        val words = passphraseWords().toMutableList()
        model.nextPage()
        words.addAll(passphraseWords())
        model.passphraseWritten()
        return words
    }

    /** On the confirm, the answer to the question on show pressed on the letter pad: word's first four letters (a three-letter word's three), then Done. */
    fun answer(word: String) {
        press(word.take(4))
        model.confirmTyped()
    }

    /** On the confirm, both questions answered from passphrase (its words in order), and the encryption's long call run: the save screen. */
    fun confirm(passphrase: List<String>) {
        repeat(2) {
            val state = model.state.value
            val question = checkNotNull(state.challenge).questions[state.page]
            answer(passphrase[question.position - 1])
        }
        worker.run()
    }

    /** From the watch-only offer, every export skipped (the watch-only export, the registration and, in Mixed mode, D): the checklist. */
    fun skipExports() {
        model.skipWatchOnly()
        model.skipRegistration()
        if (screen == Screen.RevealDOffer) model.skipDeviceLeg()
        check(screen == Screen.Checklist) { "the exports skipped did not lead to the checklist" }
    }

    /**
     * From Home: Load registry snapshot with kcr.json's snapshot named name, picked as the open-document
     * picker gives a file (its name ending in .kcr, its size), its read and core's load on the worker run,
     * then the result's Done: Home, with the snapshot loaded (the check's and the words' tests).
     */
    fun loadSnapshot(name: String): Rig {
        val bytes = kcrSnapshot(name)
        model.loadSnapshot(FakePickers())
        model.snapshotPicked(FakeFile(name + ".kcr", bytes.size.toLong(), bytes))
        worker.run()
        check(screen == Screen.Snapshot && model.state.value.loaded != null) { "the snapshot did not load" }
        model.snapshotDone()
        check(screen == Screen.Home) { "the snapshot's result did not return Home" }
        return this
    }

    /**
     * From Home: a new seed (Mixed) of 12 words, Device entropy's Continue (the commitment), C read from
     * the commitment screen, 50 rolls, the dice's Done (finish, its long call run), Skip and its confirm,
     * the words read back from the pages the state holds (each copy wiped at once), the read-back's end and
     * the wallet summary (ExportScreensTest). C, as the commitment screen showed it (public).
     */
    fun toMixedSummary(): String {
        begin(Mode.Mixed, Words.Twelve)
        model.deviceEntropyDone()
        val commitment = checkNotNull(model.state.value.commitment) { "no C on the commitment screen" }
        model.commitmentDone()
        roll(50)
        model.diceDone()
        worker.run()
        model.skip()
        model.skipConfirmed()
        toWords()
        repeat(INSERTS_PER_DEVICE - 1) { model.nextPage() }
        model.startReadback()
        repeat(INSERTS_PER_DEVICE) {
            val word = checkNotNull(model.state.value.insert).word()
            for (index in 0 until minOf(4, word.size)) model.readbackLetters.type(Char(word[index].toInt()))
            word.wipe()
            model.readbackTyped()
            model.readbackNext()
        }
        model.showSummary()
        check(screen == Screen.Wallet) { "the mixed seed did not reach its wallet summary" }
        return commitment
    }
}

/**
 * M5-54's fail-closed residual for call, a long call core does not offer at home (finish, revealProof,
 * encryptBackup, verifyBackup), from rig's screen, the stage where the model makes it: run as its own long
 * call (work), the worker's first look finds no discard, and a discard (going online) lands before core's
 * call, so the call meets the slot at home, which halts: the stop screen with the slot's halt, internal,
 * not the start screen a call core offers at home would end on (its result discarded again on the
 * worker). The call's refusal is kept, not halted on as the model's calls do, so only core's own halt
 * reaches the stop screen here. The halt latches the process's slot, so each call's pin is a class, and
 * a JVM, of its own.
 */
internal fun assertTheResidualHalts(rig: Rig, call: () -> Reply<*>) {
    val screen = rig.screen
    var refused: Refusal? = null
    var gave = false
    rig.model.work({
        rig.offline.set(false)
        call()
    }, refused = { refused = it }) { gave = true }
    assertEquals(Screen.Working, rig.screen, screenId(screen) + ": the call's screen")
    rig.worker.run()
    assertNull(refused, screenId(screen) + ": core refused the call, so the stop screen below is not its halt")
    assertFalse(gave, screenId(screen) + ": the call gave a value")
    assertEquals(Screen.Stop, rig.screen, screenId(screen) + ": a discard in the window halts (M5-54)")
    assertEquals(HaltReason.Internal, rig.model.state.value.halt, screenId(screen) + ": the stage rule's halt")
    assertEquals(HaltReason.Internal, assertFailsWith<KcHalt>("the slot halted") { Core.selfTest() }.reason)
}

/** A backup a ceremony of its own saved: the file's bytes, the passphrase's words and the wallet's fingerprint. */
internal class SavedBackup(val file: ByteArray, val passphrase: List<String>, val fingerprint: ByteArray) {
    companion object {
        /** A backup's name as core suggests them. */
        const val NAME = "keepcrypt-backup-0123abcd.age"

        /**
         * vectors/kcr.json's dice-50-words12 backed up, saved once in this JVM (a test class's one process)
         * by a ceremony of the first test that asks (its passphrase read in-process, compared and never
         * printed), which then ends it (Finish), so the slot is at home again: Check a backup's tests and
         * the walk open it.
         */
        val shared: SavedBackup by lazy {
            val rig = Rig().toHome().toSummary("dice-50-words12")
            val fingerprint = assertNotNull(rig.model.state.value.summary).fingerprint.copyOf()
            val passphrase = rig.toConfirm()
            rig.confirm(passphrase)
            val place = FakePlace()
            rig.model.saveBackup(FakePickers())
            rig.model.backupPlaced(place)
            rig.worker.run()
            assertEquals(Screen.BackupVerified, rig.screen)
            rig.model.backupVerifiedDone()
            rig.skipExports()
            rig.model.finishCeremony()
            SavedBackup(assertNotNull(place.saved), passphrase, fingerprint)
        }
    }
}

/** The document pickers' fake: what the model asked of them, nothing opened. */
internal class FakePickers : DocumentPickers {
    val created = ArrayList<String>()
    var opens = 0
    var snapshotOpens = 0

    override fun create(name: String) {
        created.add(name)
    }

    override fun open() {
        opens += 1
    }

    override fun openSnapshot() {
        snapshotOpens += 1
    }
}

/**
 * A place the create-document picker gave, in memory: its write fails when told to, and its read-back
 * gives what was written (or what readBack makes of it, or null for a read that fails). It keeps the
 * array the model handed to write, and the one it handed back, so the tests see both zeroed.
 */
internal class FakePlace(
    private val writes: Boolean = true,
    private val reads: (ByteArray) -> ByteArray? = { it },
) : DocumentPlace {
    var writeCalls = 0
    var readCalls = 0
    var readLimit = -1

    /** The model's own array, as handed to write. */
    var handed: ByteArray? = null

    /** What was written, copied as it came. */
    var saved: ByteArray? = null

    /** The array readBack gave the model. */
    var given: ByteArray? = null

    override fun write(bytes: ByteArray): Boolean {
        writeCalls += 1
        handed = bytes
        if (!writes) return false
        saved = bytes.copyOf()
        return true
    }

    override fun readBack(limit: Int): ByteArray? {
        readCalls += 1
        readLimit = limit
        val file = saved ?: return null
        val back = reads(file.copyOf())
        given = back
        return back
    }
}

/**
 * A file the open-document picker gave, in memory: its name, its size and bytes (null for a read that
 * fails); it counts its reads, and while it reads (on the model's worker) runs reading, which stands for
 * what happens on the main thread while a slow provider's read lasts.
 */
internal class FakeFile(
    override val name: String?,
    override val size: Long?,
    private val bytes: ByteArray?,
    private val reading: () -> Unit = {},
) : PickedFile {
    var reads = 0
    var readLimit = -1

    /** The array read gave the model. */
    var given: ByteArray? = null

    override fun read(limit: Int): ByteArray? {
        reads += 1
        readLimit = limit
        reading()
        val copy = bytes?.copyOf()
        given = copy
        return copy
    }
}

/** Whether every byte of bytes is zero. */
internal fun zeroed(bytes: ByteArray?): Boolean = bytes != null && bytes.all { it == 0.toByte() }

/** Whether insert's word is word: compared byte by byte, its copy wiped, nothing printed (the words are public vectors, never logged). */
internal fun sameWord(insert: WordPage, word: String): Boolean {
    val bytes = insert.word()
    val same = bytes.size == word.length && word.indices.all { bytes[it] == word[it].code.toByte() }
    bytes.wipe()
    return same
}

/** Whether insert's page was wiped: its Secret zeroed, so its position, count and word length read 0. */
internal fun wiped(insert: WordPage): Boolean = insert.position == 0 && insert.count == 0 && insert.word().size == 0
