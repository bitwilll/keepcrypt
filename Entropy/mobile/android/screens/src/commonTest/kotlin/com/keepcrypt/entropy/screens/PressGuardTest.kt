package com.keepcrypt.entropy.screens

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The press guard's rule (tasks/todo.md, Stage U's U2i; lead decision M5-79): a new view (screen, gate or
 * overlay) admits no touch while it is not yet composed nor in the 300 ms after the frame that composed it,
 * and every touch from then on, judged by the touch's own time; a view that stays (the dice's rolls, a pad's
 * keys, another page) keeps its first composition's time. DoubleTapTest holds its wiring on the phone
 * (Screens' SideEffect and root pointer handler), where a double tap's second touch landed on the next
 * screen's Back before it.
 */
class PressGuardTest {
    private val prompt = ShownView(Screen.CheckPrompt, gate = false, overlay = null)
    private val confirm = ShownView(Screen.SkipConfirm, gate = false, overlay = null)
    private val gated = ShownView(Screen.Words, gate = true, overlay = null)
    private val words = ShownView(Screen.Words, gate = false, overlay = null)
    private val covered = ShownView(Screen.Words, gate = false, overlay = Overlay.Cover)

    @Test
    fun nothingIsAdmittedBeforeAnyViewIsComposed() {
        val guard = PressGuard()
        assertFalse(guard.admits(prompt, 0), "a touch at the start")
        assertFalse(guard.admits(prompt, 10_000), "a touch long after, no view composed")
    }

    @Test
    fun aNewViewAdmitsTouchesFrom300msAfterTheFrameThatComposedIt() {
        val guard = PressGuard()
        guard.composed(prompt, 1_000)
        assertFalse(guard.admits(prompt, 1_000), "in the frame that composed it")
        assertFalse(guard.admits(prompt, 1_299), "299 ms after it")
        assertTrue(guard.admits(prompt, 1_300), "300 ms after it")
        assertTrue(guard.admits(prompt, 60_000), "long after it")
    }

    @Test
    fun aDoubleTapsSecondTouchOnTheNextScreenDoesNothing() {
        val guard = PressGuard()
        guard.composed(prompt, 0)
        assertTrue(guard.admits(prompt, 5_000), "the first touch: Skip")
        guard.composed(confirm, 5_016)
        assertFalse(guard.admits(confirm, 5_060), "the second touch, 60 ms after the first, on the confirm screen")
        assertTrue(guard.admits(confirm, 5_316), "a deliberate press once the confirm has been seen")
    }

    @Test
    fun aSecondTouchHandledLateIsJudgedByItsOwnTime() {
        val guard = PressGuard()
        guard.composed(prompt, 0)
        guard.composed(confirm, 5_016)
        // A slow frame kept the second touch (down at 5 060) waiting; it is handled long after, by its own time.
        assertFalse(guard.admits(confirm, 5_060), "the touch's time, not the time it is handled, decides")
    }

    @Test
    fun aTouchOnAViewNotYetComposedIsRefused() {
        val guard = PressGuard()
        guard.composed(prompt, 0)
        assertFalse(guard.admits(confirm, 5_000), "the model shows the confirm, not yet composed")
        assertTrue(guard.admits(prompt, 5_000), "a touch on the view composed and held")
    }

    @Test
    fun theGatePassedTheCoverAndItsRemovalAreEachANewView() {
        val guard = PressGuard()
        guard.composed(gated, 0)
        assertTrue(guard.admits(gated, 400), "the gate's own button, once seen")
        guard.composed(words, 410)
        assertFalse(guard.admits(words, 470), "the words just past the gate")
        guard.composed(covered, 31_000)
        assertFalse(guard.admits(covered, 31_100), "the cover just up")
        guard.composed(words, 32_000)
        assertFalse(guard.admits(words, 32_050), "the words just uncovered")
        assertTrue(guard.admits(words, 32_300))
    }

    @Test
    fun aViewThatStaysKeepsTheTimeItWasFirstComposed() {
        val guard = PressGuard()
        guard.composed(words, 0)
        guard.composed(words, 10_000)
        assertTrue(guard.admits(words, 400), "a recomposition of the same view (a page, a roll, a key) reopened the guard")
    }
}
