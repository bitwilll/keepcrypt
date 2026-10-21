package com.keepcrypt.entropy.screens

import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Runnable

// Test support for :screens' common tests (tasks/todo.md, M5 group 14). The model's tests run it on
// the test's own thread: its main scope is unconfined, so a long call's reply is handled at once, and
// its worker holds each long call until the test runs it, so the test can act while "Working..."
// shows. The clock and the offline monitor are fakes the test moves. The tests that reach the slot do
// so through Core over the host library, one test class per JVM (screens/build.gradle.kts), since a
// halt latches the process's slot for good.

/** A clock the test sets. */
internal class FakeClock : MonotonicClock {
    var now = 0L

    override fun nowMillis(): Long = now
}

/** A worker that keeps each long call until run, in order. */
internal class HeldWorker : CoroutineDispatcher() {
    private val held = ArrayDeque<Runnable>()

    /** How many long calls wait. */
    val waiting: Int get() = held.size

    override fun dispatch(context: CoroutineContext, block: Runnable) {
        held.addLast(block)
    }

    /** Runs every long call waiting, and what each one's reply leads to. */
    fun run() {
        while (held.isNotEmpty()) held.removeFirst().run()
    }
}

/** An offline monitor the test switches; it starts offline (airplane mode on, Wi-Fi off). */
internal class FakeOffline : OfflineMonitor {
    var offline = true
    var starts = 0
    private var report: ((Boolean) -> Unit)? = null

    val started: Boolean get() = report != null

    override fun start(report: (offline: Boolean) -> Unit) {
        starts += 1
        this.report = report
        report(offline)
    }

    override fun stop() {
        report = null
    }

    /** The phone goes offline or online. */
    fun set(offline: Boolean) {
        this.offline = offline
        report?.invoke(offline)
    }
}

/** A model over fakes, and the fakes; scope is the model's main scope (unconfined, unless a test cancels its own). */
internal class Rig(scope: CoroutineScope = CoroutineScope(Dispatchers.Unconfined)) {
    val clock = FakeClock()
    val worker = HeldWorker()
    val offline = FakeOffline()
    val model = CeremonyModel(scope, worker, clock, offline, testRegistry = true)

    val screen: Screen get() = model.state.value.screen

    /** The app's first start, through its self-test to the first screen. */
    fun startUp(): Rig {
        model.appReturned()
        worker.run()
        return this
    }
}
