package com.keepcrypt.entropy.screens

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The drawing helpers (tasks/todo.md, M5 group 14): the QR code's layout with its quiet zone, the seal
 * card's palette, tile and outline (docs/seal-watchonly-braille.md, "The seal image"), and braille
 * cells and faces (dot d at bit d - 1, 1-2-3 down the left column, 4-5-6 down the right).
 */
class DrawingTest {
    @Test
    fun aQrCodeFillsItsSquareInWholeModulesInsideItsQuietZone() {
        // A version 1 code (21 modules) in 240 px: 29 modules with the quiet zone, 8 px each.
        val small = QrLayout(21, 240)
        assertEquals(8, small.modulePx)
        assertEquals((240 - 8 * 21) / 2, small.offsetPx)
        assertEquals(small.offsetPx, small.edge(0))
        assertEquals(small.offsetPx + 20 * 8, small.edge(20))
        assertTrue(small.offsetPx >= QrLayout.QUIET * small.modulePx, "the quiet zone is kept")
        // The largest matrix core draws (61 modules, version 11) in 720 px.
        val large = QrLayout(61, 720)
        assertEquals(10, large.modulePx)
        assertTrue(large.edge(60) + large.modulePx + QrLayout.QUIET * large.modulePx <= 720)
        assertFailsWith<IllegalStateException>("a square too small for one pixel a module") { QrLayout(61, 68) }
    }

    @Test
    fun theSealCardUsesTheOkabeItoPaletteOnALightTile() {
        assertContentEquals(
            longArrayOf(0xFF000000, 0xFFE69F00, 0xFF56B4E9, 0xFF009E73, 0xFFF0E442, 0xFF0072B2, 0xFFD55E00, 0xFFCC79A7),
            OKABE_ITO,
        )
        // The test-vector seal's colour index 3 is #009E73; empty cells are the tile's.
        assertEquals(0xFF009E73, sealCellColour(filled = true, colourIndex = 3))
        assertEquals(SEAL_TILE, sealCellColour(filled = false, colourIndex = 3))
        assertEquals(0xFFF7F7F7, SEAL_TILE)
        assertEquals(0xFF333333, SEAL_OUTLINE)
        assertEquals(240, SEAL_SIDE_DP)
        for (index in 0 until 8) assertEquals(OKABE_ITO[index], sealCellColour(filled = true, colourIndex = index))
    }

    @Test
    fun brailleCellsAreTheirCodePointsDots() {
        assertContentEquals(intArrayOf(0, 1, 3, 0x3F), brailleCells("⠀⠁⠃⠿"))
        assertContentEquals(intArrayOf(), brailleCells(""))
        assertFailsWith<IllegalStateException>("an eight-dot cell") { brailleCells("⡀") }
        assertFailsWith<IllegalStateException>("not braille") { brailleCells("A") }
        // a is dot 1; d is dots 1-4-5 (0b011001); every dot of a full cell.
        assertTrue(isRaised(1, 1))
        for (dot in 2..6) assertFalse(isRaised(1, dot))
        assertEquals(listOf(1, 4, 5), (1..6).filter { isRaised(0b011001, it) })
        assertEquals(listOf(1, 2, 3, 4, 5, 6), (1..6).filter { isRaised(SIX_DOTS, it) })
    }

    @Test
    fun theSixDotsSitInTwoColumnsOfThree() {
        val width = 40f
        val height = 60f
        assertEquals(10f, dotCentre(1, width, height).x)
        assertEquals(10f, dotCentre(1, width, height).y)
        assertEquals(10f, dotCentre(3, width, height).x)
        assertEquals(50f, dotCentre(3, width, height).y)
        assertEquals(30f, dotCentre(4, width, height).x)
        assertEquals(10f, dotCentre(4, width, height).y)
        assertEquals(30f, dotCentre(6, width, height).x)
        assertEquals(50f, dotCentre(6, width, height).y)
        assertEquals(30f, dotCentre(2, width, height).y)
    }

    @Test
    fun aFacesLabelSaysBlankOrMirror() {
        assertEquals("leave blank", faceLabel(blank = true, mirror = false))
        assertEquals("mirror", faceLabel(blank = false, mirror = true))
        assertEquals("", faceLabel(blank = false, mirror = false))
    }
}
