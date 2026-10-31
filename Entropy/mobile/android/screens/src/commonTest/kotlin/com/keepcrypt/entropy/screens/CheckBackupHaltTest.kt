package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.KcHalt
import com.keepcrypt.entropy.ffi.Reply
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job

/**
 * A halt between a picked file's read and the main thread's part of it (tasks/todo.md, M5 group 18; lead
 * decision M5-70 (g)): Check a backup's read made on the worker, whose second look found no discard, its
 * reply kept for the main thread, then a second long call, the shell's bug, which halts the slot. When
 * the main thread takes the reply it finds the halt, zeroes what the read gave (work's main-thread drop)
 * and the stop screen stays. Its own JVM (forkEvery), since the halt latches the process's slot for good.
 */
class CheckBackupHaltTest {
    @Test
    fun aHaltAfterTheWorkersSecondLookZeroesWhatTheReadGave() {
        val main = HeldMain()
        val rig = Rig(CoroutineScope(Job() + main)).toHome()
        rig.model.checkBackup(FakePickers())
        rig.model.appLeft()
        rig.model.appReturned()
        val file = FakeFile("keepcrypt-backup-0123abcd.age", 100L, ByteArray(100) { 1 })
        main.holding = true
        rig.model.backupPicked(file)
        main.run()
        rig.worker.runNext()
        assertEquals(1, file.reads)
        assertEquals(1, main.waiting, "the read's reply waits for the main thread")
        assertFalse(zeroed(file.given), "the bytes read wait for the main thread")
        rig.model.work<Unit>({ Reply.Done(Unit) }) { fail("the second call is never made") }
        assertEquals(Screen.Stop, rig.screen, "a second long call halts")
        assertFailsWith<KcHalt>("the slot halted") { Core.selfTest() }
        main.run()
        assertTrue(zeroed(file.given), "what the read gave was zeroed")
        assertEquals(Screen.Stop, rig.screen, "the read's reply leaves the stop screen as it is")
        assertEquals(0, rig.worker.waiting, "nothing more reached the worker")
    }
}
