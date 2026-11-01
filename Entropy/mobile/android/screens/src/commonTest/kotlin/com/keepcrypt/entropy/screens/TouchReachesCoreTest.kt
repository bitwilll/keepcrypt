package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.KcHalt
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Words
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * A touch on Device entropy is handed to core's add_extra (tasks/todo.md, M5 group 15): StartScreensTest
 * proves that no extra reaches core anywhere else; this proves that a touch reaches it there. An extra
 * carries no credit, so a collecting slot answers alike with or without one, but add_extra outside
 * Collecting halts: the test commits the slot behind the model's back (the model still shows Device
 * entropy and still takes extras), so the touch that follows halts the real slot only if the model
 * handed it to core. Its own JVM (forkEvery), since the halt latches the process's slot for good.
 */
class TouchReachesCoreTest {
    @Test
    fun aTouchOnDeviceEntropyIsHandedToCore() {
        val rig = Rig().toHome().begin(Mode.Mixed, Words.Twelve)
        assertEquals(Screen.DeviceEntropy, rig.screen)
        assertTrue(Core.commit() is Reply.Done, "the slot committed behind the model")
        rig.model.touched(1)
        assertEquals(Screen.Stop, rig.screen, "the touch never reached core's add_extra, which halts once committed")
        assertFailsWith<KcHalt>("the slot halted") { Core.selfTest() }
    }
}
