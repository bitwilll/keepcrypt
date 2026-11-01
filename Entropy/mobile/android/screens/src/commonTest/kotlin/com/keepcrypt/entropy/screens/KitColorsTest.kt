package com.keepcrypt.entropy.screens

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.luminance
import kotlin.math.roundToInt
import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * The kit's text against what it is drawn on (tasks/todo.md, Stage U's U3h): every pair the screens draw meets
 * WCAG 2.x's 4.5:1 contrast for text, by Compose's own relative luminance (Color.luminance). The pairs are the
 * screens' (Kit.kt, Screens.kt): the type scale's white and muted text and the warning yellow on the black
 * background, the stop screen's white text and button on its red, and the TEST REGISTRY strip's black on the
 * warning yellow. A colour added to KitColors, or text drawn on another, comes with its pair here.
 */
class KitColorsTest {
    /** WCAG's contrast ratio of two colours: (the lighter's luminance + 0.05) / (the darker's + 0.05). */
    private fun contrast(a: Color, b: Color): Double {
        val (light, dark) = listOf(a.luminance().toDouble(), b.luminance().toDouble()).sortedDescending()
        return (light + 0.05) / (dark + 0.05)
    }

    /** ratio rounded to hundredths, for a message. */
    private fun hundredths(ratio: Double): Double = (ratio * 100).roundToInt() / 100.0

    private val pairs = listOf(
        Triple("text on the background", KitColors.text, KitColors.background),
        Triple("muted text (notes, disabled buttons) on the background", KitColors.muted, KitColors.background),
        Triple("warnings on the background", KitColors.warning, KitColors.background),
        Triple("the stop screen's text on its red", KitColors.text, KitColors.stop),
        Triple("the TEST REGISTRY strip's black on the warning yellow", Color.Black, KitColors.warning),
    )

    @Test
    fun everyPairTheScreensDrawMeets4Point5To1() {
        for ((what, fore, back) in pairs) {
            val ratio = contrast(fore, back)
            assertTrue(ratio >= MINIMUM, "$what: contrast " + hundredths(ratio) + ":1, under $MINIMUM:1")
        }
    }

    @Test
    fun theRatioIsWcagsForKnownColours() {
        val white = contrast(Color.White, Color.Black)
        assertTrue(white > 20.99 && white < 21.01, "white on black is 21:1, not " + hundredths(white))
        val same = contrast(KitColors.stop, KitColors.stop)
        assertTrue(same > 0.999 && same < 1.001, "a colour on itself is 1:1, not " + hundredths(same))
    }

    private companion object {
        /** WCAG 2.x's minimum contrast for body text (level AA). */
        const val MINIMUM = 4.5
    }
}
