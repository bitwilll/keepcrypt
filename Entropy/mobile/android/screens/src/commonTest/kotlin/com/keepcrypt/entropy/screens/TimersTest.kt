package com.keepcrypt.entropy.screens

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Every timer rule and boundary on a fake clock (tasks/todo.md, M5 group 14): the cover at 30 s on a
 * Protected screen, the warning at 9 minutes and the idle wipe at 10 while a session is held, the
 * background wipe at 60 s away (59 s keeps, 60 s wipes), and the picker rule.
 */
class TimersTest {
    private val clock = FakeClock()
    private val timers = Timers(clock)

    private fun at(millis: Long, onProtected: Boolean, holdsSecrets: Boolean): TimerStep? {
        clock.now = millis
        return timers.step(onProtected, holdsSecrets)
    }

    @Test
    fun aProtectedScreenIsCoveredAt30sAndAPublicOneNever() {
        assertNull(at(29_999, onProtected = true, holdsSecrets = false))
        assertEquals(TimerStep.Cover, at(30_000, onProtected = true, holdsSecrets = false))
        assertEquals(TimerStep.Cover, at(30_000, onProtected = true, holdsSecrets = true))
        assertNull(at(30_000, onProtected = false, holdsSecrets = true))
        assertNull(at(539_999, onProtected = false, holdsSecrets = false))
    }

    @Test
    fun theWarningComesAt9MinutesOnlyWhileASessionIsHeld() {
        assertNull(at(539_999, onProtected = false, holdsSecrets = true))
        assertEquals(TimerStep.Warn, at(540_000, onProtected = false, holdsSecrets = true))
        assertEquals(TimerStep.Warn, at(540_000, onProtected = true, holdsSecrets = true))
        assertNull(at(540_000, onProtected = false, holdsSecrets = false))
        assertEquals(TimerStep.Cover, at(540_000, onProtected = true, holdsSecrets = false))
    }

    @Test
    fun theIdleWipeComesAt10MinutesWithASessionOrOnAProtectedScreen() {
        assertEquals(TimerStep.Warn, at(599_999, onProtected = false, holdsSecrets = true))
        assertEquals(TimerStep.IdleWipe, at(600_000, onProtected = false, holdsSecrets = true))
        assertEquals(TimerStep.Cover, at(599_999, onProtected = true, holdsSecrets = false))
        assertEquals(TimerStep.IdleWipe, at(600_000, onProtected = true, holdsSecrets = false))
        assertNull(at(600_000, onProtected = false, holdsSecrets = false))
        assertNull(at(6_000_000, onProtected = false, holdsSecrets = false))
    }

    @Test
    fun inputStartsTheIdleTimeAgain() {
        clock.now = 500_000
        timers.input()
        assertNull(at(529_999, onProtected = true, holdsSecrets = true))
        assertEquals(TimerStep.Cover, at(530_000, onProtected = true, holdsSecrets = true))
        assertEquals(TimerStep.Warn, at(1_040_000, onProtected = false, holdsSecrets = true))
        assertEquals(TimerStep.IdleWipe, at(1_100_000, onProtected = false, holdsSecrets = true))
    }

    @Test
    fun sixtySecondsAwayWipesAndFiftyNineKeeps() {
        clock.now = 10_000
        timers.input()
        assertTrue(timers.left())
        assertNull(at(69_000, onProtected = false, holdsSecrets = true))
        assertNull(at(69_999, onProtected = false, holdsSecrets = true))
        assertEquals(TimerStep.BackgroundWipe, at(70_000, onProtected = false, holdsSecrets = true))
        // With nothing held there is nothing to wipe.
        assertNull(at(70_000, onProtected = false, holdsSecrets = false))
        // The background wipe comes before a warning due at the same time.
        assertEquals(TimerStep.BackgroundWipe, at(600_000, onProtected = false, holdsSecrets = true))
    }

    @Test
    fun aReturnWithin60sEndsTheBackgroundTime() {
        assertTrue(timers.left())
        clock.now = 59_000
        timers.returned()
        assertNull(at(60_000, onProtected = false, holdsSecrets = true))
        assertNull(at(120_000, onProtected = false, holdsSecrets = true))
        // Leaving again starts it afresh.
        assertTrue(timers.left())
        assertNull(at(179_999, onProtected = false, holdsSecrets = true))
        assertEquals(TimerStep.BackgroundWipe, at(180_000, onProtected = false, holdsSecrets = true))
    }

    @Test
    fun aPickerTheAppOpenedIsForegroundTimeUnderTheIdleRules() {
        timers.pickerOpened()
        assertFalse(timers.left(), "a picker the app opened is no leaving")
        // No background wipe however long the picker stays up...
        assertNull(at(60_000, onProtected = false, holdsSecrets = true))
        assertNull(at(539_999, onProtected = false, holdsSecrets = true))
        // ...but its time counts under the 10-minute rule.
        assertEquals(TimerStep.Warn, at(540_000, onProtected = false, holdsSecrets = true))
        assertEquals(TimerStep.IdleWipe, at(600_000, onProtected = false, holdsSecrets = true))
        // Back from the picker, the next stop is leaving again.
        timers.returned()
        clock.now = 700_000
        timers.input()
        assertTrue(timers.left())
        assertEquals(TimerStep.BackgroundWipe, at(760_000, onProtected = false, holdsSecrets = true))
    }
}
