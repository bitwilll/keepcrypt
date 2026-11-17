package com.keepcrypt.entropy.screens

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Where KitScreen puts a screen's actions (Q78, Q85; lead decision M5-84 (a)): under the text column while
 * they are ACTIONS_SHARE of the screen's height or less, in the scrolling column, after the text, once they
 * are taller. The device tests see the placement; this holds the share's arithmetic it rests on.
 */
class KitTest {
    @Test
    fun actionsScrollOnceTallerThanTheirShareOfTheScreen() {
        assertEquals(0.5f, ACTIONS_SHARE)
        // CI's window, 640 dp high: the BIP39 entry's actions, about 490 dp since M5-83's taller keys, scroll
        // with the text (run 43613600587 found its page line squeezed out of view); one button's row stays.
        assertTrue(actionsScroll(490, 640))
        assertFalse(actionsScroll(76, 640))
        // Half is the edge: exactly half stays under the column, a pixel more scrolls.
        assertFalse(actionsScroll(320, 640))
        assertTrue(actionsScroll(321, 640))
        // In pixels as the layout measures them, at CI's density 2.0 and a 412 dp phone's 2.625 (2424 px high).
        assertTrue(actionsScroll(980, 1280))
        assertFalse(actionsScroll(1212, 2424))
        assertTrue(actionsScroll(1213, 2424))
        // Before the first layout nothing is measured: the actions stay under the column.
        assertFalse(actionsScroll(0, 0))
        assertFalse(actionsScroll(0, 1280))
    }

    @Test
    fun theMoreBelowLineIsFixedText() {
        assertEquals("More below", MORE_BELOW)
        assertEquals("more_below", MORE_BELOW_TAG)
    }
}
