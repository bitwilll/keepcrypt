package com.keepcrypt.entropy.screens

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The names TalkBack is given (tasks/todo.md, Stage U's commit U3g): every screen's pane title
 * (screenTitle) is its own, fixed and non-blank, and neither the privacy gate's, the cover's nor the idle
 * warning's; the state's pane title is the gate's while a gate stands and the screen's otherwise; and
 * each kind of QR code has a name of its own that says it is a QR code. All are constants, built from no
 * value a screen shows, so announcing one names no secret.
 */
class ScreenTitlesTest {
    @Test
    fun eachScreenHasAFixedPaneTitleOfItsOwn() {
        val titles = Screen.entries.map(::screenTitle)
        assertTrue(titles.none { it.isBlank() }, "a blank title")
        assertEquals(Screen.entries.size, titles.toSet().size, "each screen has a title of its own")
        val others = setOf(PRIVACY_GATE_TITLE, COVER_TITLE, IDLE_WARNING_TITLE)
        assertEquals(3, others.size)
        assertTrue(titles.none { it in others }, "a screen's title is the gate's, the cover's or the warning's")
        for (screen in Screen.entries) {
            assertEquals(screenTitle(screen), paneTitle(UiState(screen)), screenId(screen))
            assertEquals(PRIVACY_GATE_TITLE, paneTitle(UiState(screen, gate = true)), screenId(screen) + " behind a gate")
        }
    }

    @Test
    fun eachKindOfQrCodeIsNamedByItsKindAlone() {
        val names = QrKind.entries.map { it.spoken }
        assertEquals(QrKind.entries.size, names.toSet().size, "each kind has a name of its own")
        assertTrue(names.all { "QR code" in it }, "a name that does not say it is a QR code: $names")
    }
}
