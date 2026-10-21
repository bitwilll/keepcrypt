package com.keepcrypt.entropy.camera

import java.nio.ByteBuffer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The scanner's frame code on canned camera frames (tasks/todo.md, M5 group 16, commit 18): the two P4
 * go-ahead PNGs (goahead-clear-empty-bucket.png and goahead-collision-dice-50.png, as GoAheadPngTest
 * renders them: P4Png), each set in a wider frame as a camera sees a screen and turned through each of
 * the four rotations, laid out as a YUV_420_888 frame's Y plane would come from an ImageReader: rows
 * longer than the width (padding after each but the last) and a pixel stride of 1 or 2 (the second
 * byte of each pixel, and the padding, filled with other bytes, as a plane of interleaved chroma would
 * hold them), the buffer exactly as long as the strides need. The scanner's own reduceLuminance must
 * give the frame's luminance back byte for byte, and its goAheadText (ZXing's decode, hints for a photo
 * of a screen) the QR's text, at every rotation, zeroing the luminance as it goes. A frame with no code
 * gives no text, through the scanner's one catch of ZXing's ReaderException, and a QR whose text is
 * over 4,296 characters (a numeric QR can hold 7,089) is dropped though ZXing reads it.
 */
class GoAheadFrameTest {
    @Test
    fun bothGoAheadPngsAsYuvFramesDecodeAtEveryRotationAndStride() {
        val kcr = P4Png.kcr()
        for (name in P4Png.NAMES) {
            val ur = P4Png.proofUr(kcr, name).uppercase()
            var frame = framed(P4Png.readPng(P4Png.render(ur)))
            for (turn in 0 until 4) {
                for ((pixelStride, padding) in LAYOUTS) {
                    val what = name + " turned " + (90 * turn) + ", pixel stride " + pixelStride + ", padding " + padding
                    val rowStride = frame.width * pixelStride + padding
                    val luminance = ByteArray(frame.width * frame.height)
                    reduceLuminance(plane(frame, rowStride, pixelStride), rowStride, pixelStride, frame.width, frame.height, luminance)
                    assertArrayEquals(what + ": the Y plane reduced", frame.luminance, luminance)
                    assertEquals(what, ur, goAheadText(luminance, frame.width, frame.height))
                    assertTrue(what + ": the luminance zeroed", luminance.all { it == ZERO })
                }
                frame = turned(frame)
            }
        }
    }

    @Test
    fun aFrameWithNoCodeGivesNoTextAndIsZeroed() {
        val frame = framed(P4Png.Gray(320, 240, ByteArray(320 * 240) { (it * 7 % 251).toByte() }))
        val luminance = frame.luminance.copyOf()
        assertNull(goAheadText(luminance, frame.width, frame.height))
        assertTrue("the luminance zeroed", luminance.all { it == ZERO })
    }

    @Test
    fun aTextOverTheLongestGoAheadQrIsDropped() {
        val longest = digits(MAX_GO_AHEAD_TEXT)
        val longer = digits(MAX_GO_AHEAD_TEXT + 1)
        val kept = P4Png.readPng(P4Png.render(longest))
        assertEquals(longest, goAheadText(kept.luminance.copyOf(), kept.width, kept.height))
        val dropped = P4Png.readPng(P4Png.render(longer))
        assertEquals("ZXing reads the longer one", longer, decodeGoAhead(dropped.luminance.copyOf(), dropped.width, dropped.height))
        assertNull("the scanner drops it", goAheadText(dropped.luminance.copyOf(), dropped.width, dropped.height))
    }

    /** count decimal digits, which ZXing's writer puts in a numeric QR. */
    private fun digits(count: Int): String = buildString(count) { for (i in 0 until count) append('0' + i % 10) }

    /** image in the middle of a wider, white frame, as a camera's 4:3 or 16:9 frame holds a screen. */
    private fun framed(image: P4Png.Gray): P4Png.Gray {
        val width = image.width + 2 * SIDE
        val height = image.height + 2 * TOP
        val luminance = ByteArray(width * height) { WHITE }
        for (y in 0 until image.height) {
            image.luminance.copyInto(luminance, (y + TOP) * width + SIDE, y * image.width, (y + 1) * image.width)
        }
        return P4Png.Gray(width, height, luminance)
    }

    /** image turned 90 degrees clockwise. */
    private fun turned(image: P4Png.Gray): P4Png.Gray {
        val width = image.height
        val height = image.width
        val luminance = ByteArray(width * height)
        for (y in 0 until height) {
            for (x in 0 until width) luminance[y * width + x] = image.luminance[(image.height - 1 - x) * image.width + y]
        }
        return P4Png.Gray(width, height, luminance)
    }

    /**
     * image as a Y plane at rowStride and pixelStride, in a direct buffer exactly as long as the strides
     * need (no padding after the last row, as Image.Plane gives it), every byte that is no pixel of the
     * image (the padding, the interleaved bytes) filled with others.
     */
    private fun plane(image: P4Png.Gray, rowStride: Int, pixelStride: Int): ByteBuffer {
        val size = (image.height - 1) * rowStride + (image.width - 1) * pixelStride + 1
        val bytes = ByteArray(size) { (it * 37 + 11).toByte() }
        for (y in 0 until image.height) {
            for (x in 0 until image.width) bytes[y * rowStride + x * pixelStride] = image.luminance[y * image.width + x]
        }
        val buffer = ByteBuffer.allocateDirect(size)
        buffer.put(bytes)
        buffer.flip()
        return buffer
    }

    private companion object {
        /** The Y plane layouts: (pixel stride, padding after each row), each row longer than the width. */
        val LAYOUTS = listOf(Pair(1, 64), Pair(2, 7))

        /** The white frame around the code: wider at the sides than above and below. */
        const val SIDE = 160
        const val TOP = 40

        const val ZERO: Byte = 0
        const val WHITE: Byte = -1
    }
}
