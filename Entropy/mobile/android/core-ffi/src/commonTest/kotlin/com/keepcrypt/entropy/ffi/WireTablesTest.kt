package com.keepcrypt.entropy.ffi

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame

/**
 * Wire.kt's copies of wire.rs's tables (tasks/todo.md, M5 group 9: "The status code table is pinned by
 * a Rust test and Kotlin's copy by a JVM test"), pinned against keepcrypt-ffi's own source,
 * ffi/src/wire.rs: the four status bytes, the op table (every pub const ...: u32, in order), the
 * refusal codes against its PINNED table and the halt codes against its PINNED_HALTS (M5 commit U3a),
 * name for name, code for code and in order, so a code changed, swapped, added or dropped on either
 * side fails here before it reaches a phone.
 */
class WireTablesTest {
    private val wire = entropyFile("ffi/src/wire.rs")

    /** The value of wire.rs's pub const name: type = value;. */
    private fun constant(name: String, type: String): Int {
        val found = Regex("^pub const " + name + ": " + type + " = (\\d+);$", RegexOption.MULTILINE).findAll(wire).toList()
        assertEquals(1, found.size, "one pub const " + name + " in wire.rs")
        return found[0].groupValues[1].toInt()
    }

    @Test
    fun theStatusBytesAreWireRs() {
        assertEquals(constant("OK", "u8"), Wire.OK)
        assertEquals(constant("REFUSED", "u8"), Wire.REFUSED)
        assertEquals(constant("DISCARDED", "u8"), Wire.DISCARDED)
        assertEquals(constant("HALTED", "u8"), Wire.HALTED)
    }

    @Test
    fun theOpTableIsWireRs() {
        val kotlin = listOf(
            "SELF_TEST" to Wire.SELF_TEST,
            "START" to Wire.START,
            "ADD_EXTRA" to Wire.ADD_EXTRA,
            "COMMIT" to Wire.COMMIT,
            "START_DICE" to Wire.START_DICE,
            "PUSH_ROLL" to Wire.PUSH_ROLL,
            "UNDO_ROLL" to Wire.UNDO_ROLL,
            "FINISH" to Wire.FINISH,
            "SKIP_CHECK" to Wire.SKIP_CHECK,
            "START_CHECK" to Wire.START_CHECK,
            "MATCH_FOUND" to Wire.MATCH_FOUND,
            "CANNOT_CHECK" to Wire.CANNOT_CHECK,
            "GENERATE_BACKUP_PASSPHRASE" to Wire.GENERATE_BACKUP_PASSPHRASE,
            "END" to Wire.END,
            "DISCARD" to Wire.DISCARD,
            "WIPE_ALL" to Wire.WIPE_ALL,
            "DEVICE_PROGRESS" to Wire.DEVICE_PROGRESS,
            "COMMITMENT" to Wire.COMMITMENT,
            "DICE_PROGRESS" to Wire.DICE_PROGRESS,
            "SEAL" to Wire.SEAL,
            "CHECK_REQUEST" to Wire.CHECK_REQUEST,
            "REVEAL_CODE" to Wire.REVEAL_CODE,
            "REVEAL_SNAPSHOT" to Wire.REVEAL_SNAPSHOT,
            "REVEAL_PROOF" to Wire.REVEAL_PROOF,
            "COLLISION_REPORT" to Wire.COLLISION_REPORT,
            "WORD_PAGE" to Wire.WORD_PAGE,
            "CHECK_READBACK" to Wire.CHECK_READBACK,
            "SUMMARY" to Wire.SUMMARY,
            "BACKUP_PASSPHRASE_PAGE" to Wire.BACKUP_PASSPHRASE_PAGE,
            "BACKUP_CHALLENGE" to Wire.BACKUP_CHALLENGE,
            "CONFIRM_BACKUP" to Wire.CONFIRM_BACKUP,
            "ENCRYPT_BACKUP" to Wire.ENCRYPT_BACKUP,
            "VERIFY_BACKUP" to Wire.VERIFY_BACKUP,
            "WATCH_ONLY" to Wire.WATCH_ONLY,
            "REGISTRATION" to Wire.REGISTRATION,
            "REVEAL_DEVICE_LEG" to Wire.REVEAL_DEVICE_LEG,
            "LOAD_SNAPSHOT" to Wire.LOAD_SNAPSHOT,
            "OPEN_BACKUP" to Wire.OPEN_BACKUP,
        )
        val rust = Regex("^pub const ([A-Z_]+): u32 = (\\d+);$", RegexOption.MULTILINE).findAll(wire)
            .map { it.groupValues[1] to it.groupValues[2].toInt() }.toList()
        assertEquals(rust, kotlin)
        assertEquals((1..38).toList(), kotlin.map { it.second })
        assertEquals(0, kotlin.count { it.second == Wire.HALT }, "HALT is no op of the table")
    }

    /** A refusal's name as wire.rs's PINNED table writes it: core's error path. */
    private fun rustName(refusal: Refusal): String = when (refusal.group) {
        RefusalGroup.Code -> "Code(" + refusal.name + ")"
        RefusalGroup.Core -> "Core(" + refusal.name + ")"
        RefusalGroup.Snapshot -> "Core(Snapshot(" + refusal.name + "))"
        RefusalGroup.Ur -> "Core(Snapshot(Ur(" + refusal.name + ")))"
        RefusalGroup.Backup -> "Core(Backup(" + refusal.name + "))"
    }

    @Test
    fun theRefusalCodesAreWireRsPinnedTable() {
        val start = wire.indexOf("const PINNED: [(&str, u8); ")
        val end = wire.indexOf("];", start)
        assertEquals(true, start >= 0 && end > start, "wire.rs's PINNED table")
        val pinned = Regex("\\(\"([A-Za-z()]+)\", (\\d+)\\),").findAll(wire.substring(start, end))
            .map { it.groupValues[1] to it.groupValues[2].toInt() }.toList()
        val count = Regex("const PINNED: \\[\\(&str, u8\\); (\\d+)\\]").find(wire)?.groupValues?.get(1)?.toInt()
        assertEquals(count, pinned.size, "every entry of PINNED read")
        assertEquals(pinned, Refusal.entries.map { rustName(it) to it.code })
        for (refusal in Refusal.entries) assertSame(refusal, Refusal.of(refusal.code))
    }

    @Test
    fun theHaltCodesAreWireRsPinnedHalts() {
        val start = wire.indexOf("const PINNED_HALTS: [(&str, u8); ")
        val end = wire.indexOf("];", start)
        assertEquals(true, start >= 0 && end > start, "wire.rs's PINNED_HALTS table")
        val pinned = Regex("\\(\"([A-Za-z]+)\", (\\d+)\\),").findAll(wire.substring(start, end))
            .map { it.groupValues[1] to it.groupValues[2].toInt() }.toList()
        val count = Regex("const PINNED_HALTS: \\[\\(&str, u8\\); (\\d+)\\]").find(wire)?.groupValues?.get(1)?.toInt()
        assertEquals(count, pinned.size, "every entry of PINNED_HALTS read")
        assertEquals(pinned, HaltReason.entries.map { it.name to it.code })
        for (reason in HaltReason.entries) assertSame(reason, HaltReason.of(reason.code))
    }
}
