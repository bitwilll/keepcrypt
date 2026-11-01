package com.keepcrypt.entropy.ffi

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Core.kt's copies of core's backup-file limits (tasks/todo.md, M5 group 18: Check a backup checks the
 * name and the size before any byte is read), pinned against core's own source as WireTablesTest pins
 * wire.rs's tables: BACKUP_SUFFIX is core/src/backup.rs's FILE_NAME_SUFFIX, which ends every name core
 * suggests, and BACKUP_MAX_BYTES is core/src/backup/age.rs's MAX_FILE_BYTES, past which core refuses a
 * file as Backup(TooLarge), so a limit changed on either side fails here before it reaches a phone.
 */
class BackupFileTest {
    /** The one line of path that defines name: its value, the text after "= " and before ";". */
    private fun constant(path: String, declaration: String): String {
        val found = entropyFile(path).lines().filter { it.startsWith(declaration + " = ") && it.endsWith(";") }
        assertEquals(1, found.size, "one " + declaration + " in " + path)
        return found[0].removePrefix(declaration + " = ").removeSuffix(";")
    }

    @Test
    fun theBackupSuffixIsCoresFileNameSuffix() {
        assertEquals("\"" + Core.BACKUP_SUFFIX + "\"", constant("core/src/backup.rs", "const FILE_NAME_SUFFIX: &str"))
    }

    @Test
    fun theBackupSizeLimitIsCoresMaxFileBytes() {
        val value = constant("core/src/backup/age.rs", "pub(crate) const MAX_FILE_BYTES: usize")
        val product = Regex("^(\\d+) \\* (\\d+)$").find(value)
        val bytes = if (product != null) product.groupValues[1].toInt() * product.groupValues[2].toInt() else value.toInt()
        assertEquals(bytes, Core.BACKUP_MAX_BYTES)
    }
}
