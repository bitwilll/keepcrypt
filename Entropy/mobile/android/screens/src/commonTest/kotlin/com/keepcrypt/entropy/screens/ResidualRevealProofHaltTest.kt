package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import kotlin.test.Test

/**
 * M5-54's residual for a scanned go-ahead QR's check (revealProof), from the scan screen, where the model
 * makes it (tasks/todo.md, Stage U's U2e; assertTheResidualHalts): a discard that lands between the
 * worker's first look and core's call halts the slot, fail closed. Its own JVM (forkEvery), since the
 * halt latches the process's slot for good.
 */
class ResidualRevealProofHaltTest {
    @Test
    fun aDiscardBetweenTheWorkersLookAndTheCallHalts() {
        val rig = Walk.to(Screen.Scan)
        assertTheResidualHalts(rig) { Core.revealProof(rig.date.today(), "not a proof") }
    }
}
