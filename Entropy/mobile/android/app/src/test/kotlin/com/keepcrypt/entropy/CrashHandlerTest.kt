package com.keepcrypt.entropy

import com.keepcrypt.entropy.ffi.HaltReason
import com.keepcrypt.entropy.ffi.KcHalt
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

/**
 * The crash path's order (tasks/todo.md, M5 group 14), with fakes for its two steps: the wipe first,
 * then the end of the process, and the end even when the wipe throws (KcHalt from a halted slot). On
 * the emulator CrashTest throws for real on the main thread, judged from the shell.
 */
class CrashHandlerTest {
    @Test
    fun itWipesThenEndsTheProcess() {
        val steps = ArrayList<String>()
        val handler = CrashHandler(wipe = { steps.add("wipe") }, end = { steps.add("end") })
        handler.uncaughtException(Thread.currentThread(), IllegalStateException("a test's exception"))
        assertEquals(listOf("wipe", "end"), steps)
    }

    @Test
    fun theProcessEndsEvenWhenTheWipeThrows() {
        val steps = ArrayList<String>()
        val handler = CrashHandler(
            wipe = {
                steps.add("wipe")
                throw KcHalt(HaltReason.Internal)
            },
            end = { steps.add("end") },
        )
        assertThrows(KcHalt::class.java) {
            handler.uncaughtException(Thread.currentThread(), IllegalStateException("a test's exception"))
        }
        assertEquals(listOf("wipe", "end"), steps)
    }
}
