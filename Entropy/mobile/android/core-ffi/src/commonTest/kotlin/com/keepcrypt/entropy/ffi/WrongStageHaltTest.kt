package com.keepcrypt.entropy.ffi

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * A call in a stage that does not offer it halts, and every later call does too (tasks/todo.md, M5
 * group 13; group 8's rule, through the bridge): commit at home is the shell's bug, the slot halts
 * and drops what it held, and from then on each of the 38 calls, a discard and a wipe among them,
 * throws KcHalt, its reason internal (M5 commit U3a), as is Core.halt's own after it. Its own process
 * (forkEvery), since the halt latches the process's slot for good.
 */
class WrongStageHaltTest {
    @Test
    fun aCallInTheWrongStageHaltsAndEveryLaterCallHalts() {
        assertTrue(Core.selfTest() is Reply.Done, "a live slot first")
        assertEquals(HaltReason.Internal, assertFailsWith<KcHalt> { Core.commit() }.reason)
        val today = M5_DAY
        val every: List<() -> Any?> = listOf(
            { Core.selfTest() },
            { Core.start(Words.Twelve, Mode.DiceOnly) },
            { Core.addExtra(Extra.InputTiming, byteArrayOf(1)) },
            { Core.commit() },
            { Core.startDice() },
            { Core.pushRoll(1) },
            { Core.undoRoll() },
            { Core.finish() },
            { Core.skipCheck() },
            { Core.startCheck() },
            { Core.matchFound() },
            { Core.cannotCheck() },
            { Core.generateBackupPassphrase() },
            { Core.end() },
            { Core.discard() },
            { Core.wipeAll() },
            { Core.deviceProgress() },
            { Core.commitment() },
            { Core.diceProgress() },
            { Core.seal() },
            { Core.checkRequest() },
            { Core.revealCode(secretOf("0000-0000")) },
            { Core.revealSnapshot(today) },
            { Core.revealProof(today, "not a ur") },
            { Core.collisionReport() },
            { Core.wordPage(1) },
            { Core.checkReadback(1, secretOf("aban")) },
            { Core.summary() },
            { Core.backupPassphrasePage(0) },
            { Core.backupChallenge() },
            { Core.confirmBackup(0, 1) },
            { Core.encryptBackup() },
            { Core.verifyBackup(byteArrayOf(1)) },
            { Core.watchOnly(null) },
            { Core.registration() },
            { Core.revealDeviceLeg() },
            { Core.loadSnapshot(today, byteArrayOf(1)) },
            { Core.openBackup(List(8) { secretOf("aban") }, Secret(byteArrayOf(1))) },
        )
        assertTrue(every.size == 38, "one call per op")
        for (call in every) assertEquals(HaltReason.Internal, assertFailsWith<KcHalt> { call() }.reason)
        assertEquals(HaltReason.Internal, assertFailsWith<KcHalt> { Core.halt() }.reason)
    }
}
