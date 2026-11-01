package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import kotlin.test.Test

/**
 * M5-54's residual for the dice's Done (finish), with 99 rolls of a 24-word seed in (tasks/todo.md, Stage U's U2e; assertTheResidualHalts): a discard that lands
 * between the worker's first look and core's call halts the slot, fail closed. Its own JVM (forkEvery),
 * since the halt latches the process's slot for good.
 */
class ResidualFinishHaltTest {
    @Test
    fun aDiscardBetweenTheWorkersLookAndTheCallHalts() {
        val rig = Walk.to(Screen.Dice)
        rig.roll(99)
        assertTheResidualHalts(rig) { Core.finish() }
    }
}
