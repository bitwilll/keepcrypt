package com.keepcrypt.entropy.screens

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * No control's tag is a screen's id (tasks/todo.md, M5 group 6; commit 21h): a screen's id is the test
 * tag of that screen's root alone, so the emulator tests find a screen by it (Ui.on) and a control by
 * its own tag (Ui.tap). Home's About once had the tag about, the About screen's id, and UI Automator
 * matched the About root, gone from the window, and clicked its centre (Entropy Android run 40681107802).
 * So each screen's id is written once in :screens' commonMain sources, in screenId's own table, and no
 * string literal anywhere else there (a tag, a test tag, a when branch's value) is one: a tag built at
 * run time (the pads' key_ tags) is not read, and none starts as a screen's id does. On the JVM, since
 * it lists the source tree under kc.entropy (screens/build.gradle.kts).
 */
class ScreenIdsTest {
    @Test
    fun eachScreensIdIsWrittenOnceInTheScreensSourcesInScreenIdsOwnTable() {
        val ids = Screen.entries.map(::screenId)
        assertEquals(Screen.entries.size, ids.toSet().size, "each screen has an id of its own")
        val root = File(checkNotNull(System.getProperty("kc.entropy")) { "screens/build.gradle.kts sets kc.entropy" })
        val sources = root.resolve("mobile/android/screens/src/commonMain").walkTopDown()
            .filter { it.isFile && it.name.endsWith(".kt") }
            .sortedBy { it.path }
            .toList()
        assertTrue(sources.any { it.name == "Screen.kt" }, "the sources hold Screen.kt")
        val literal = Regex("\"([a-z0-9_]+)\"")
        val written = HashMap<String, MutableList<Pair<File, String>>>()
        for (file in sources) {
            for (line in file.readLines()) {
                for (match in literal.findAll(line)) written.getOrPut(match.groupValues[1]) { ArrayList() }.add(file to line)
            }
        }
        for (screen in Screen.entries) {
            val id = screenId(screen)
            val at = written[id].orEmpty()
            val where = at.map { it.first.name + ": " + it.second.trim() }
            assertEquals(1, at.size, id + " is written once in :screens' commonMain, in screenId's table: " + where)
            assertEquals("Screen.kt", at[0].first.name, id + " is written in Screen.kt alone")
            assertEquals("Screen." + screen.name + " -> \"" + id + "\"", at[0].second.trim(), id + " is screenId's table's entry")
        }
    }
}
