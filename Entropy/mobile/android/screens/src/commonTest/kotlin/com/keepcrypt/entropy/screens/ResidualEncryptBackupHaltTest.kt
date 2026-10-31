package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import kotlin.test.Test

/**
 * M5-54's residual for the backup's encryption (encryptBackup), from the save screen, where core offers
 * it again once the confirm is right (tasks/todo.md, Stage U's U2e; assertTheResidualHalts): a discard
 * that lands between the worker's first look and core's call halts the slot, fail closed. Its own JVM
 * (forkEvery), since the halt latches the process's slot for good.
 */
class ResidualEncryptBackupHaltTest {
    @Test
    fun aDiscardBetweenTheWorkersLookAndTheCallHalts() {
        val rig = Walk.to(Screen.BackupSave)
        assertTheResidualHalts(rig) { Core.encryptBackup() }
    }
}
