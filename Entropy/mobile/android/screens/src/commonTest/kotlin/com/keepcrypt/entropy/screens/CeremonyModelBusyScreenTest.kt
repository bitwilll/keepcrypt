package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.KcHalt
import com.keepcrypt.entropy.ffi.Reply
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.fail

/**
 * The model's guard on a long call's screen (tasks/todo.md, M5 group 14): a long call runs behind a
 * busy screen, which takes no input ("Working..." or the start-up self-test's), so a call made behind
 * a screen that takes input (Home here) is the shell's bug, and the model halts the real slot before
 * the call is made and shows the stop screen. Its own JVM (forkEvery), since the halt latches the
 * process's slot for good.
 */
class CeremonyModelBusyScreenTest {
    @Test
    fun aLongCallBehindAScreenThatTakesInputHalts() {
        val rig = Rig().toHome()
        assertEquals(Screen.Home, rig.screen)
        rig.model.work<Unit>({ Reply.Done(Unit) }, busy = Screen.Home) { fail("the call is never made") }
        assertEquals(Screen.Stop, rig.screen, "a busy screen that takes input halts")
        assertEquals(0, rig.worker.waiting, "nothing went to the worker")
        assertFailsWith<KcHalt>("the slot halted") { Core.selfTest() }
    }
}
