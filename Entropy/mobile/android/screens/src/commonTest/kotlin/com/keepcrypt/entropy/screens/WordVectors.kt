package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.WordPage
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The braille vectors the words' tests take (tasks/todo.md, M5 group 17; rule 12: vectors/ only):
 * vectors/braille.json's insert of a word (its SeedBook number, faces 1-5, lighter face and mirror
 * partners) and a letter's dots, read through entropyFile as kcr.json is (RegistryVectors.kt).
 * vectorgen.py writes each word's entry on one line, its fields in that order, and each letter's cell
 * with its letter followed by its dots, so each is read as that run of fields, exactly once.
 */
private val brailleJson: String by lazy { entropyFile("vectors/braille.json") }

/** braille.json's insert of a word: its SeedBook number, faces 1-5 (null for a blank), its lighter face and mirror partners. */
internal class BrailleInsert(val number: Int, val faces: List<Char?>, val lighterFace: Int?, val mirrors: List<Char?>)

/** A list of braille.json's: five items, each a one-letter string or null. */
private fun letters(list: String): List<Char?> {
    val items = list.split(",").map { it.trim() }
    assertEquals(5, items.size, "five faces")
    return items.map { if (it == "null") null else it.removeSurrounding("\"").single() }
}

/** braille.json's insert of word. */
internal fun brailleInsert(word: String): BrailleInsert {
    val found = Regex(
        "\\{\"number\": (\\d+), \"word\": \"" + Regex.escape(word) + "\", \"faces\": \\[([^\\]]*)\\], " +
            "\"lighter_face\": (null|[1-5]), \"mirror_partners\": \\[([^\\]]*)\\]",
    ).findAll(brailleJson).toList()
    assertEquals(1, found.size, "braille.json holds one entry for the word")
    val groups = found[0].groupValues
    return BrailleInsert(groups[1].toInt(), letters(groups[2]), groups[3].toIntOrNull(), letters(groups[4]))
}

/** braille.json's dots of letter, dot d at bit d - 1. */
internal fun brailleDots(letter: Char): Int {
    val found = Regex("\"letter\": \"" + letter + "\",\\s*\"dots\": \"([1-6]+)\"").findAll(brailleJson).toList()
    assertEquals(1, found.size, "braille.json holds one cell for the letter")
    var dots = 0
    for (digit in found[0].groupValues[1]) dots = dots or (1 shl (digit - '1'))
    return dots
}

/**
 * Whether insert's page is braille.json's insert of word, face by face as the insert view draws it: its
 * SeedBook number, each face's letter (a blank face none) with that letter's dots, the lighter face and
 * the mirror partners. Each is compared, never printed (a SeedBook number or a face's dots name the
 * letter as well as the letter does): a message names only the insert and the face.
 */
internal fun assertInsertOf(insert: WordPage, word: String, what: String) {
    val expected = brailleInsert(word)
    assertTrue(expected.number == insert.seedbook, what + ": the SeedBook number")
    for (n in 1..5) {
        val face = insert.face(n)
        val letter = expected.faces[n - 1]
        assertTrue(face.letter == letter, what + ": face " + n + "'s letter")
        assertTrue((letter == null) == face.isBlank, what + ": face " + n + " blank or not")
        assertTrue((if (letter == null) 0 else brailleDots(letter)) == face.dots, what + ": face " + n + "'s dots")
        assertTrue((expected.lighterFace == n) == face.isLighter, what + ": face " + n + " lighter or not")
        assertTrue(face.mirrorPartner == expected.mirrors[n - 1], what + ": face " + n + "'s mirror partner")
    }
}
