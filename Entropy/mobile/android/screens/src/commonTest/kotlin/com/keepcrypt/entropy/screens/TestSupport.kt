package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.WordPage
import com.keepcrypt.entropy.ffi.Words
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Runnable

// Test support for :screens' common tests (tasks/todo.md, M5 groups 14-16). The model's tests run it on
// the test's own thread: its main scope is unconfined, so a long call's reply is handled at once, and
// its worker holds each long call until the test runs it, so the test can act while "Working..."
// shows. The clock, the offline monitor and the motion source are fakes the test moves; the UTC date is
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
        while (held.isNotEmpty()) {
            held.removeFirst().run()
            ran += 1
        }
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

/** A model over fakes, and the fakes; scope is the model's main scope (unconfined, unless a test cancels its own). */
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

    /** From Home through Length and the start (its long call run) to the ceremony's first screen. */
    fun begin(mode: Mode, words: Words): Rig {
        model.chooseMode(mode)
        model.chooseLength(words)
        worker.run()
        return this
    }

    /**
     * n rolls through the dice pad and Confirm, the faces 1 to 6 in turn from 1 on each call, so two calls
     * are no vector's rolls (StartScreensTest pushes dice-50-words12's own rolls where the faces matter).
     */
    fun roll(n: Int) {
        repeat(n) { index ->
            model.dicePick.replace(DICE_KEYS[index % DICE_KEYS.length])
            model.confirmRoll()
        }
    }

    /**
     * From Home: a dice-only seed of vectors/kcr.json's dice gate seed named seed (its rolls picked on the
     * pad and confirmed), the dice's Done (finish, its long call run), then Skip and its confirm: Skip's
     * result, from where Show words leads to that seed's words (WordsScreensTest, ReadbackScreensTest).
     */
    fun toSkippedResult(seed: String): Rig {
        begin(Mode.DiceOnly, if (kcrWords(seed).size == 24) Words.TwentyFour else Words.Twelve)
        for (face in kcrRolls(seed)) {
            model.dicePick.replace(face)
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
     * the last insert, every insert read back (its first four letters, a three-letter word's three), the
     * read-back's end and the wallet summary (BackupScreensTest, CheckBackupScreensTest).
     */
    fun toSummary(seed: String): Rig {
        val words = kcrWords(seed)
        check(words.size == INSERTS_PER_DEVICE)
        toSkippedResult(seed).toWords()
        repeat(words.size - 1) { model.nextPage() }
        model.startReadback()
        for (word in words) {
            for (letter in word.take(4)) model.readbackLetters.type(letter)
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

    /** On the confirm, the answer to the question on show typed on the letter pad: word's first four letters (a three-letter word's three), then Done. */
    fun answer(word: String) {
        for (letter in word.take(4)) model.backupLetters.type(letter)
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
}

/** The document pickers' fake: what the model asked of them, nothing opened. */
internal class FakePickers : DocumentPickers {
    val created = ArrayList<String>()
    var opens = 0

    override fun create(name: String) {
        created.add(name)
    }

    override fun open() {
        opens += 1
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

/** A file the open-document picker gave, in memory: its name, its size and bytes (null for a read that fails); it counts its reads. */
internal class FakeFile(override val name: String?, override val size: Long?, private val bytes: ByteArray?) : PickedFile {
    var reads = 0
    var readLimit = -1

    /** The array read gave the model. */
    var given: ByteArray? = null

    override fun read(limit: Int): ByteArray? {
        reads += 1
        readLimit = limit
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
