package com.keepcrypt.entropy.screens

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The shared screen table (tasks/todo.md, M6 item D1; Q86; docs/mobile-apps.md, "Architecture" and
 * "Session lifetime"): mobile/screens.json lists every screen of both phone apps, in the Screen enum's
 * order, each with its id (screenId), its Kotlin constant's name, its fixed title (screenTitle) and its
 * kind (isProtected: Protected or Public). The iPhone's Swift CeremonyModel is a second copy of this
 * module's, so the table is what holds the two to one list: this test holds Screen.kt to the file line
 * for line, and KeepCryptTests' ScreenTableTests holds the iPhone's Screen.swift to it. The file is read
 * as text and compared whole (no JSON reader of this module's own): its first line, its one "about"
 * line of prose, the screens' opening, one line per screen exactly as rendered here from the enum, and
 * its close. So any change to the enum, an id, a title or a kind fails here until the table changes
 * with it, and so does any other edit of the table's lines.
 */
class ScreenTableTest {
    /** A screen's line in the table, as this test renders it from Screen.kt. */
    private fun row(screen: Screen): String {
        val kind = if (isProtected(screen)) "Protected" else "Public"
        return "    {\"id\": \"" + screenId(screen) + "\", \"name\": \"" + screen.name + "\", \"title\": \"" +
            screenTitle(screen) + "\", \"kind\": \"" + kind + "\"}"
    }

    @Test
    fun theSharedTableIsScreenKtLineForLine() {
        for (screen in Screen.entries) {
            for (text in listOf(screenId(screen), screen.name, screenTitle(screen))) {
                assertTrue(text.isNotEmpty() && text.all { it in ' '..'~' && it != '"' && it != '\\' }, screen.name + ": a value the table cannot hold as written")
            }
        }
        val lines = entropyFile("mobile/screens.json").split("\n")
        val rows = Screen.entries.size
        assertEquals(rows + 6, lines.size, "the table's lines: its opening, about, the screens' opening, one per screen, its close and the final newline")
        assertEquals("{", lines[0], "the table's first line")
        assertTrue(Regex("  \"about\": \"[ -!#-\\[\\]-~]+\",").matches(lines[1]), "the table's about line")
        assertEquals("  \"screens\": [", lines[2], "the screens' opening")
        for ((index, screen) in Screen.entries.withIndex()) {
            val comma = if (index < rows - 1) "," else ""
            assertEquals(row(screen) + comma, lines[3 + index], "screen " + (index + 1) + ", " + screen.name + ": mobile/screens.json is not Screen.kt's")
        }
        assertEquals(listOf("  ]", "}", ""), lines.subList(3 + rows, lines.size), "the table's close")
    }
}
