package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.KcHalt
import com.keepcrypt.entropy.ffi.Reply
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.fail

/**
 * The model on a real halt (tasks/todo.md, M5 group 14): a second long call while one runs is the
 * shell's bug, so the model halts the slot itself and shows the stop screen; the first call's reply,
 * when it comes, changes nothing; no input, return, leaving or report leaves the stop screen; and the
 * model's wipeAll on the halted slot, whose wipe answers with the halt status, ends quietly (its one
 * catch of KcHalt). Its own JVM (forkEvery), since the halt latches the process's slot for good.
 */
class CeremonyModelHaltTest {
    @Test
    fun aSecondLongCallHaltsAndNothingLeavesTheStopScreen() {
        val rig = Rig().startUp()
        assertEquals(Screen.FirstLaunch, rig.screen)
        var first = false
        rig.model.work<Unit>({ Reply.Done(Unit) }) { first = true }
        assertEquals(Screen.Working, rig.screen)
        rig.model.work<Unit>({ Reply.Done(Unit) }) { fail("the second call is never made") }
        assertEquals(Screen.Stop, rig.screen, "a second long call halts")
        assertFailsWith<KcHalt>("the slot halted") { Core.selfTest() }
        rig.worker.run()
        assertEquals(false, first, "the first call's reply changes nothing after the halt")
        assertEquals(Screen.Stop, rig.screen)
        rig.model.appLeft()
        rig.model.appReturned()
        rig.offline.set(false)
        rig.model.input()
        rig.model.tick()
        rig.model.wipeAll()
        rig.model.work<Unit>({ Reply.Done(Unit) }) { fail("nothing runs on the stop screen") }
        assertEquals(0, rig.worker.waiting)
        assertEquals(Screen.Stop, rig.screen)
    }
}
