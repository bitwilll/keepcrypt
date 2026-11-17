package com.keepcrypt.entropy.ffi

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Core.kt's copies of the snapshot file's limits (tasks/todo.md, M5 group 18: Load registry snapshot
 * checks the name and the size before any byte is read), pinned against their sources as BackupFileTest
 * pins the backup's: SNAPSHOT_SUFFIX is the .kcr the Pi lists its stick's snapshots by (pi/app's
 * hal.rs), and SNAPSHOT_MAX_BYTES plus the date's 4 bytes is keepcrypt-jni's MAX_INPUT, past which a
 * call halts before a byte is read, so a file the phone lets through never halts the slot by its size.
 */
class SnapshotFileTest {
    @Test
    fun theSnapshotSuffixIsTheOneThePiListsSnapshotsBy() {
        val found = entropyFile("pi/app/src/hal.rs").lines().filter { it.contains("eq_ignore_ascii_case(\".kcr\")") }
        assertEquals(1, found.size, "one .kcr test in pi/app/src/hal.rs")
        assertEquals(".kcr", Core.SNAPSHOT_SUFFIX)
    }

    @Test
    fun theSnapshotSizeLimitIsTheJniInputLimitAfterTheDate() {
        val declaration = "const MAX_INPUT: usize = "
        val found = entropyFile("ffi/jni/src/lib.rs").lines().filter { it.startsWith(declaration) && it.endsWith(";") }
        assertEquals(1, found.size, "one MAX_INPUT in ffi/jni/src/lib.rs")
        val value = found[0].removePrefix(declaration).removeSuffix(";")
        val sum = Regex("^4 \\+ (\\d+) \\+ (\\d+) \\* \\(1 << (\\d+)\\)$").find(value)
        val parts = checkNotNull(sum) { "MAX_INPUT is 4 + header + entry * (1 << n)" }.groupValues
        assertEquals(parts[1].toInt() + parts[2].toInt() * (1 shl parts[3].toInt()), Core.SNAPSHOT_MAX_BYTES)
        assertEquals(75_497_594, Core.SNAPSHOT_MAX_BYTES)
    }
}
