package com.keepcrypt.entropy.screens

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The press guard's rule (tasks/todo.md, Stage U's U2i; lead decision M5-79): a new view (screen, gate or
 * overlay) admits no touch before its first frame nor in the 300 ms after it, and every touch from then on;
 * a frame reported for a view no longer shown opens nothing; a view that stays (the dice's rolls, a pad's
 * keys, another page) keeps admitting. DoubleTapTest holds its wiring on the phone (Screens' root pointer
 * handler), where a double tap's second touch landed on the next screen's Back before it.
 */
class PressGuardTest {
    private val prompt = ShownView(Screen.CheckPrompt, gate = false, overlay = null)
    private val confirm = ShownView(Screen.SkipConfirm, gate = false, overlay = null)
    private val gated = ShownView(Screen.Words, gate = true, overlay = null)
    private val words = ShownView(Screen.Words, gate = false, overlay = null)
    private val covered = ShownView(Screen.Words, gate = false, overlay = Overlay.Cover)

    /** guard showing view, its first frame at frame. */
    private fun PressGuard.at(view: ShownView, frame: Long): PressGuard {
        showing(view)
        drawn(view, frame)
        return this
    }

    @Test
    fun aNewViewAdmitsNoTouchBeforeItsFirstFrame() {
        val guard = PressGuard()
        guard.showing(prompt)
        assertFalse(guard.admits(prompt, 0), "a touch before any frame")
        assertFalse(guard.admits(prompt, 10_000), "a touch long after the change, still before any frame")
    }

    @Test
    fun aNewViewAdmitsTouchesFrom300msAfterItsFirstFrame() {
        val guard = PressGuard().at(prompt, 1_000)
        assertFalse(guard.admits(prompt, 1_000), "at the first frame")
        assertFalse(guard.admits(prompt, 1_299), "299 ms after it")
        assertTrue(guard.admits(prompt, 1_300), "300 ms after it")
        assertTrue(guard.admits(prompt, 60_000), "long after it")
    }

    @Test
    fun aDoubleTapsSecondTouchOnTheNextScreenDoesNothing() {
        val guard = PressGuard().at(prompt, 0)
        assertTrue(guard.admits(prompt, 5_000), "the first touch: Skip")
        guard.at(confirm, 5_016)
        assertFalse(guard.admits(confirm, 5_060), "the second touch, 60 ms after the first, on the confirm screen")
        assertTrue(guard.admits(confirm, 5_316), "a deliberate press once the confirm has been seen")
    }

    @Test
    fun aTouchOnAViewTheGuardHasNotSeenYetIsRefused() {
        val guard = PressGuard().at(prompt, 0)
        assertFalse(guard.admits(confirm, 5_000), "the model shows the confirm, not yet composed or drawn")
    }

    @Test
    fun aFrameReportedForAViewNoLongerShownOpensNothing() {
        val guard = PressGuard()
        guard.showing(prompt)
        guard.showing(confirm)
        guard.drawn(prompt, 0)
        assertFalse(guard.admits(confirm, 1_000), "the old view's frame opened the new one")
        guard.drawn(confirm, 1_000)
        assertTrue(guard.admits(confirm, 1_300))
    }

    @Test
    fun theGatePassedTheCoverAndItsRemovalAreEachANewView() {
        val guard = PressGuard().at(gated, 0)
        assertTrue(guard.admits(gated, 400), "the gate's own button, once seen")
        guard.at(words, 410)
        assertFalse(guard.admits(words, 470), "the words just past the gate")
        guard.at(covered, 31_000)
        assertFalse(guard.admits(covered, 31_100), "the cover just up")
        guard.at(words, 32_000)
        assertFalse(guard.admits(words, 32_050), "the words just uncovered")
        assertTrue(guard.admits(words, 32_300))
    }

    @Test
    fun aViewThatStaysKeepsAdmittingAndItsFirstFrameIsKept() {
        val guard = PressGuard().at(words, 0)
        guard.showing(words)
        guard.drawn(words, 10_000)
        assertTrue(guard.admits(words, 400), "another page of the same screen, or a key, reopened the guard")
    }
}
