package com.keepcrypt.entropy.screens

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.keepcrypt.entropy.ffi.Face
import com.keepcrypt.entropy.ffi.QrMatrix
import com.keepcrypt.entropy.ffi.SealCard

// The drawing helpers (tasks/todo.md, M5 group 14): a QR code from core's QrMatrix, the seal card
// (docs/seal-watchonly-braille.md, "The seal image"), and braille cells and insert faces ("Braille
// backup"; the Pi's pi/app/src/ui/braille.rs and seal.rs draw the same). Each composable draws what a
// plain function here computes, and the JVM tests check those functions.

// --- QR codes -----------------------------------------------------------------------------------

/**
 * Where a QR code's modules go in a square of sizePx: side x side modules inside the standard quiet
 * zone of QUIET modules on each side, each module a whole number of pixels, the code centred.
 */
class QrLayout(val side: Int, sizePx: Int) {
    /** One module's side in pixels. */
    val modulePx: Int = sizePx / (side + 2 * QUIET)

    /** Where the first module starts, from the square's top and left edges. */
    val offsetPx: Int = (sizePx - modulePx * side) / 2

    init {
        check(modulePx > 0)
    }

    /** Module column x's left edge (or row y's top edge) in pixels. */
    fun edge(index: Int): Int = offsetPx + index * modulePx

    companion object {
        /** The quiet zone, in modules (ISO/IEC 18004). */
        const val QUIET = 4
    }
}

/** A QR code, dark modules on a light square of size, from the matrix core drew (its screen wipes it). */
@Composable
fun QrCode(matrix: QrMatrix, size: Dp) {
    Canvas(Modifier.size(size)) {
        val layout = QrLayout(matrix.side, this.size.width.toInt())
        drawRect(Color.White)
        val module = Size(layout.modulePx.toFloat(), layout.modulePx.toFloat())
        for (y in 0 until matrix.side) {
            for (x in 0 until matrix.side) {
                if (matrix.isDark(x, y)) {
                    drawRect(Color.Black, Offset(layout.edge(x).toFloat(), layout.edge(y).toFloat()), module)
                }
            }
        }
    }
}

// --- The seal card --------------------------------------------------------------------------------

/** The Okabe-Ito palette (ARGB), indexed by the card's colour index, T[0] mod 8. */
val OKABE_ITO: LongArray = longArrayOf(
    0xFF000000, 0xFFE69F00, 0xFF56B4E9, 0xFF009E73, 0xFFF0E442, 0xFF0072B2, 0xFFD55E00, 0xFFCC79A7,
)

/** The light tile under the grid, whatever the theme (the Pi's #F7F7F7). */
const val SEAL_TILE = 0xFFF7F7F7

/** Every cell's dark outline, so light colours stay visible (the Pi's #333333). */
const val SEAL_OUTLINE = 0xFF333333

/** The seal's side on phones (240 pt, in dp on Android). */
const val SEAL_SIDE_DP = 240

/** A cell's colour: the card's palette colour when filled, else the tile's. */
fun sealCellColour(filled: Boolean, colourIndex: Int): Long = if (filled) OKABE_ITO[colourIndex] else SEAL_TILE

/** The seal card: the 8 x 8 grid at 240 dp, the Seal ID in large type beneath, and its braille. */
@Composable
fun SealCardImage(card: SealCard) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Canvas(Modifier.size(SEAL_SIDE_DP.dp)) {
            val cell = this.size.width / 8
            val outline = Stroke(width = 1.dp.toPx())
            for (row in 0 until 8) {
                for (column in 0 until 8) {
                    val topLeft = Offset(column * cell, row * cell)
                    val square = Size(cell, cell)
                    drawRect(Color(sealCellColour(card.isFilled(row, column), card.colourIndex)), topLeft, square)
                    drawRect(Color(SEAL_OUTLINE), topLeft, square, style = outline)
                }
            }
        }
        Spacer(Modifier.height(12.dp))
        BasicText(
            card.sealId,
            style = TextStyle(color = Color.White, fontSize = 36.sp, fontWeight = FontWeight.Bold, fontFamily = FontFamily.Monospace),
        )
        Spacer(Modifier.height(8.dp))
        BrailleCells(brailleCells(card.sealIdBraille), 18.dp)
    }
}

// --- Braille --------------------------------------------------------------------------------------

/** The first code point of Unicode's braille block, the blank cell: a cell's glyph is it plus its dots. */
const val BRAILLE_BLANK = 0x2800

/** The six dots' bits: a six-dot cell is at most this. */
const val SIX_DOTS = 0x3F

/** Whether dot (1-6) is raised in a cell whose dot d is bit d - 1 (core's layout: 1-2-3 down the left, 4-5-6 down the right). */
fun isRaised(dots: Int, dot: Int): Boolean = ((dots shr (dot - 1)) and 1) == 1

/**
 * The cells of a braille text such as the card's Seal ID in braille: each character's code point minus
 * U+2800. Core only gives six-dot cells, so anything else is a bug: check fails, and the app's crash
 * path wipes everything and ends the process.
 */
fun brailleCells(text: String): IntArray = IntArray(text.length) { index ->
    val dots = text[index].code - BRAILLE_BLANK
    check(dots in 0..SIX_DOTS)
    dots
}

/** Dot (1-6)'s centre in a cell box of width x height: two columns, three rows, each centred in its part. */
fun dotCentre(dot: Int, width: Float, height: Float): Offset {
    val column = (dot - 1) / 3
    val row = (dot - 1) % 3
    return Offset(width * (1 + 2 * column) / 4f, height * (1 + 2 * row) / 6f)
}

/** Draws one cell's six dots in a box of size from topLeft: raised dots filled, flat ones as rings, so every position shows. */
private fun DrawScope.cell(dots: Int, topLeft: Offset, box: Size, colour: Color) {
    val radius = minOf(box.width / 2f, box.height / 3f) * 0.35f
    val ring = Stroke(width = maxOf(1f, radius / 3f))
    for (dot in 1..6) {
        val centre = topLeft + dotCentre(dot, box.width, box.height)
        if (isRaised(dots, dot)) {
            drawCircle(colour, radius, centre)
        } else {
            drawCircle(colour, radius, centre, style = ring)
        }
    }
}

/** A row of braille cells (a caption such as the Seal ID's), each cellWidth wide and half as tall again. */
@Composable
fun BrailleCells(cells: IntArray, cellWidth: Dp) {
    Canvas(Modifier.size(cellWidth * cells.size, cellWidth * 1.5f)) {
        val box = Size(this.size.width / cells.size, this.size.height)
        for (index in cells.indices) {
            cell(cells[index], Offset(index * box.width, 0f), box, Color.White)
        }
    }
}

/** A face's label under its dots: a blank face says to leave it blank, a mirror letter to read it twice. */
fun faceLabel(blank: Boolean, mirror: Boolean): String = when {
    blank -> "leave blank"
    mirror -> "mirror"
    else -> ""
}

/** The lighter colour of face 5 (the Pi's lighter dots). */
private val LIGHTER = Color(0xFF9E9E9E)

/**
 * One face of an insert (docs/seal-watchonly-braille.md, "Braille backup"): its letter, its six dots with
 * their numbers (1-3 left, 4-5-6 right), and under them "leave blank" or "mirror"; face 5 lighter.
 */
@Composable
fun BrailleFace(face: Face) {
    val colour = if (face.isLighter) LIGHTER else Color.White
    val label = faceLabel(face.isBlank, face.mirrorPartner != null)
    Column(Modifier.background(Color.Black).padding(4.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        BasicText(face.letter?.toString() ?: " ", style = TextStyle(color = colour, fontSize = 24.sp, fontWeight = FontWeight.Bold))
        Row(verticalAlignment = Alignment.CenterVertically) {
            DotNumbers(1, colour)
            Canvas(Modifier.size(40.dp, 60.dp)) {
                cell(face.dots, Offset.Zero, this.size, colour)
            }
            DotNumbers(4, colour)
        }
        BasicText(label, style = TextStyle(color = colour, fontSize = 14.sp))
    }
}

/** The numbers of the three dots of a column, first to first + 2, beside it. */
@Composable
private fun DotNumbers(first: Int, colour: Color) {
    Column {
        for (dot in first until first + 3) {
            BasicText(dot.toString(), Modifier.height(20.dp), style = TextStyle(color = colour, fontSize = 12.sp))
        }
    }
}
