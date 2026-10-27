package com.keepcrypt.entropy.screens

import kotlin.test.assertEquals

/**
 * The registry vectors the collision check's and the words' tests take (tasks/todo.md, M5 groups 16 and
 * 17; rule 12: vectors/ only): vectors/kcr.json's date, its snapshots by name, its two proofs' go-ahead
 * QR texts and its dice gate seeds' rolls and words, read through the platform's test code as
 * :core-ffi's tests read the vectors (lead decision M5-43): on the JVM, androidHostTest's actual of
 * entropyFile, under the directory screens/build.gradle.kts names in kc.entropy. vectorgen.py writes
 * kcr.json with each snapshot's name followed by its kcr_hex, a proof's name by its kcp1_hex and then,
 * for the two P4 proofs (lead decision M5-42), its ur, and a dice seed's name by its rolls, its word
 * count and its mnemonic, so each is read as that run of fields, exactly once, with no JSON reader of
 * this module's own. The words are public vectors, but no test prints them: a test compares them and
 * names only the insert.
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

/** The match of kcr.json's dice seed named name: its rolls, its word count and its mnemonic, in that order. */
private fun kcrSeed(name: String, group: Int): String {
    val found = Regex(
        "\"name\": \"" + Regex.escape(name) + "\",\\s*\"rolls\": \"([1-6]+)\",\\s*\"words\": (12|24),\\s*\"mnemonic\": \"([a-z ]+)\"",
    ).findAll(kcrJson).toList()
    assertEquals(1, found.size, "kcr.json holds the seed " + name + " once")
    return found[0].groupValues[group]
}

/** The rolls of kcr.json's dice seed named name, each a face 1-6. */
internal fun kcrRolls(name: String): String = kcrSeed(name, 1)

/** The words of kcr.json's dice seed named name, in order (public vectors, never printed). */
internal fun kcrWords(name: String): List<String> {
    val words = kcrSeed(name, 3).split(" ")
    assertEquals(kcrSeed(name, 2).toInt(), words.size, "the seed " + name + "'s word count")
    return words
}
