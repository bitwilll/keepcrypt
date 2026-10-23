package com.keepcrypt.entropy.screens

import kotlin.test.assertEquals

/**
 * The registry vectors the collision check's tests take (tasks/todo.md, M5 group 16; rule 12: vectors/
 * only): vectors/kcr.json's date, its snapshots by name and its two proofs' go-ahead QR texts, read
 * through the platform's test code as :core-ffi's tests read the vectors (lead decision M5-43): on the
 * JVM, androidHostTest's actual of entropyFile, under the directory screens/build.gradle.kts names in
 * kc.entropy. vectorgen.py writes kcr.json with each snapshot's name followed by its kcr_hex, and a
 * proof's name by its kcp1_hex and then, for the two P4 proofs (lead decision M5-42), its ur, so each is
 * read as that run of fields, exactly once, with no JSON reader of this module's own.
 */
internal expect fun entropyFile(path: String): String

private val kcrJson: String by lazy { entropyFile("vectors/kcr.json") }

/** The one match of pattern in kcr.json, its first group. */
private fun kcrField(pattern: String, what: String): String {
    val found = Regex(pattern).findAll(kcrJson).toList()
    assertEquals(1, found.size, "kcr.json holds " + what + " once")
    return found[0].groupValues[1]
}

/** kcr.json's today (YYYYMMDD), the date its snapshots' freshness is pinned against (2026-03-01). */
internal fun kcrToday(): Int = kcrField("\"today\": (\\d{8}),", "today").toInt()

/** The bytes of kcr.json's snapshot named name (its kcr_hex). */
internal fun kcrSnapshot(name: String): ByteArray {
    val hex = kcrField("\"name\": \"" + Regex.escape(name) + "\",\\s*\"kcr_hex\": \"([0-9a-f]*)\"", "the snapshot " + name)
    assertEquals(0, hex.length % 2, "an even number of hex digits")
    return ByteArray(hex.length / 2) { i -> hex.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
}

/** The go-ahead QR text of kcr.json's proof named name (its ur field, lower case; lead decision M5-42). */
internal fun kcrProofUr(name: String): String = kcrField(
    "\"name\": \"" + Regex.escape(name) + "\",\\s*\"kcp1_hex\": \"[0-9a-f]*\",\\s*\"ur\": \"([a-z0-9:/-]*)\"",
    "the proof " + name + " with its ur",
)
