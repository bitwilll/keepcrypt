package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.KcHalt
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * First launch comes before any core call (tasks/todo.md, M5 group 15; lead decision M5-50;
 * docs/mobile-apps.md, steps 1-3): the test halts the real slot first, so any call the model made
 * would get the halt status and end on the stop screen. The start, a tick, the system Back, a leave
 * and a return, going online and offline and ten minutes without input all leave First launch
 * showing with nothing on the worker; only its Continue makes the first call, the start-up self-test,
 * which meets the halt. Its own JVM (forkEvery), since the halt latches the process's slot for good.
 */
class NoCoreCallBeforeContinueTest {
    @Test
    fun nothingReachesCoreBeforeFirstLaunchsContinue() {
        assertFailsWith<KcHalt>("the slot halted") { Core.halt() }
        val rig = Rig().startUp()
        rig.model.tick()
        rig.model.back()
        rig.model.appLeft()
        rig.model.appReturned()
        rig.model.dismissOverlay()
        rig.offline.set(false)
        rig.offline.set(true)
        rig.clock.now = Timers.WIPE_MILLIS
        rig.model.tick()
        assertEquals(Screen.FirstLaunch, rig.screen, "a core call before First launch's Continue met the halt")
        assertEquals(0, rig.worker.waiting, "no long call before First launch's Continue")
        rig.model.firstLaunchDone()
        assertEquals(Screen.SelfTest, rig.screen)
        assertEquals(1, rig.worker.waiting, "Continue's self-test")
        rig.worker.run()
        assertEquals(Screen.Stop, rig.screen, "the self-test, the first call, met the halt")
    }
}
