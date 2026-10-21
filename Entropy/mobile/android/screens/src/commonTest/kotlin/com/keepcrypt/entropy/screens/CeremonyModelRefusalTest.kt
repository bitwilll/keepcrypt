package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.KcHalt
import com.keepcrypt.entropy.ffi.Refusal
import com.keepcrypt.entropy.ffi.Reply
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.fail

/**
 * The model's default answer to a refusal (tasks/todo.md, M5 group 14): a long call made with no
 * refused handler refuses nothing, so a refusal from it is the shell's bug, and the model halts the
 * real slot and shows the stop screen. Its own JVM (forkEvery), since the halt latches the process's
 * slot for good.
 */
class CeremonyModelRefusalTest {
    @Test
    fun aRefusalFromACallWithNoHandlerHalts() {
        val rig = Rig().startUp()
        rig.model.work<Unit>({ Reply.Refused(Refusal.WrongCode) }) { fail("a refused call gives no value") }
        rig.worker.run()
        assertEquals(Screen.Stop, rig.screen)
        assertFailsWith<KcHalt>("the slot halted") { Core.selfTest() }
    }
}
