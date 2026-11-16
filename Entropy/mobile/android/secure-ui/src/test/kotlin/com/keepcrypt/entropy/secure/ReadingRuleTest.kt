package com.keepcrypt.entropy.secure

import android.view.accessibility.AccessibilityEvent
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The reading rule (Q80 (b); SecureActivity's isReading): an accessibility focus and a text read by its parts
 * are a person reading the app, input for the idle time; no other event is, a focus cleared (which follows a
 * node going away), a scroll, a content or window change, a click, a hover, a selection and a
 * type the platform does not define among them.
 */
class ReadingRuleTest {
    @Test
    fun aFocusAndATextReadByItsPartsAreReading() {
        assertTrue(isReading(AccessibilityEvent.TYPE_VIEW_ACCESSIBILITY_FOCUSED))
        assertTrue(isReading(AccessibilityEvent.TYPE_VIEW_TEXT_TRAVERSED_AT_MOVEMENT_GRANULARITY))
    }

    @Test
    fun noOtherEventIsReading() {
        val others = mapOf(
            "focus cleared" to AccessibilityEvent.TYPE_VIEW_ACCESSIBILITY_FOCUS_CLEARED,
            "scrolled" to AccessibilityEvent.TYPE_VIEW_SCROLLED,
            "content changed" to AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED,
            "window state changed" to AccessibilityEvent.TYPE_WINDOW_STATE_CHANGED,
            "windows changed" to AccessibilityEvent.TYPE_WINDOWS_CHANGED,
            "clicked" to AccessibilityEvent.TYPE_VIEW_CLICKED,
            "long clicked" to AccessibilityEvent.TYPE_VIEW_LONG_CLICKED,
            "input focus" to AccessibilityEvent.TYPE_VIEW_FOCUSED,
            "selected" to AccessibilityEvent.TYPE_VIEW_SELECTED,
            "hover enter" to AccessibilityEvent.TYPE_VIEW_HOVER_ENTER,
            "hover exit" to AccessibilityEvent.TYPE_VIEW_HOVER_EXIT,
            "text changed" to AccessibilityEvent.TYPE_VIEW_TEXT_CHANGED,
            "touch interaction start" to AccessibilityEvent.TYPE_TOUCH_INTERACTION_START,
            "no type" to 0,
            "every type" to -1,
        )
        for ((name, type) in others) assertFalse(name, isReading(type))
    }
}
