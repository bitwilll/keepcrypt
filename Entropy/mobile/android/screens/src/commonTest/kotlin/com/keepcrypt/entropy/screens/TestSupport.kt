package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Words
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Runnable

// Test support for :screens' common tests (tasks/todo.md, M5 groups 14 and 15). The model's tests run
// it on the test's own thread: its main scope is unconfined, so a long call's reply is handled at once,
// and its worker holds each long call until the test runs it, so the test can act while "Working..."
// shows. The clock, the offline monitor and the motion source are fakes the test moves. The tests that
// reach the slot do so through Core over the host library, one test class per JVM
// (screens/build.gradle.kts), since a halt latches the process's slot for good.

/** A clock the test sets. */
internal class FakeClock : MonotonicClock {
    var now = 0L

    override fun nowMillis(): Long = now

    override fun nowNanos(): Long = now * 1_000_000
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
    val worker = HeldWorker()
    val offline = FakeOffline()
    val motion = FakeMotion()
    val model = CeremonyModel(scope, worker, clock, offline, motion, testRegistry = true)

    val screen: Screen get() = model.state.value.screen

    /** The app's first start, through its self-test to the first screen. */
    fun startUp(): Rig {
        model.appReturned()
        worker.run()
        return this
    }

    /** Through the start-up, First launch and Go offline (the fake starts offline) to Home. */
    fun toHome(): Rig {
        startUp()
        model.firstLaunchDone()
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
}
