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
 * A motion sample on Device entropy is handed to core's add_extra and then zeroed (tasks/todo.md, M5
 * group 15): StartScreensTest proves that no sample reaches core anywhere else; this proves that one
 * reaches it there. An extra carries no credit, so a collecting slot answers alike with or without
 * one, but add_extra outside Collecting halts: the test commits the slot behind the model's back (the
 * model still shows Device entropy and still listens), so the sample that follows halts the real slot
 * only if the model handed it to core. Its own JVM (forkEvery), since the halt latches the process's
 * slot for good.
 */
class MotionReachesCoreTest {
    @Test
    fun aMotionSampleOnDeviceEntropyIsHandedToCoreAndZeroed() {
        val rig = Rig().toHome().begin(Mode.Mixed, Words.Twelve)
        assertEquals(Screen.DeviceEntropy, rig.screen)
        assertTrue(Core.commit() is Reply.Done, "the slot committed behind the model")
        val sample = ByteArray(20) { 7 }
        assertTrue(rig.motion.sample(sample), "the model listens on Device entropy")
        assertEquals(Screen.Stop, rig.screen, "the sample never reached core's add_extra, which halts once committed")
        assertTrue(sample.all { it == 0.toByte() }, "the sample is zeroed when core has had it, a halt or not")
        assertFailsWith<KcHalt>("the slot halted") { Core.selfTest() }
    }
}
