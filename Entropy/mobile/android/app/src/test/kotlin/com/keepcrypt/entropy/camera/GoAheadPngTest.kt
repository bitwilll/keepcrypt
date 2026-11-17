package com.keepcrypt.entropy.camera

import java.io.File
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The P4 drill's go-ahead QRs (tasks/todo.md, M5 group 13 and lead decision M5-42):
 * clear-empty-bucket's and collision-dice-50's QR text, read from vectors/kcr.json's ur fields, each
 * rendered by ZXing's writer (tests only) as a PNG the owner's phone scans from a computer screen,
 * goahead-<name>.png, written to the directory kc.p4 names (app/build/p4/, which the Android
 * workflow uploads with the P4 files), then read back from those bytes and decoded by the scanner's
 * own decode function, which must give the text again (P4Png renders and reads them; GoAheadFrameTest
 * feeds the same PNGs to the scanner as camera frames). The text is the ur field upper case (M5-42 as
 * amended: an alphanumeric QR, smaller than the lower-case byte-mode one and easier to scan from a
 * screen), which :core-ffi's RegistryTest reveals with too, so the code the owner's phone scans holds
 * what core is proven to verify.
 */
class GoAheadPngTest {
    private val out = File(checkNotNull(System.getProperty("kc.p4")) { "app/build.gradle.kts sets kc.p4" })

    @Test
    fun theTwoGoAheadQrsRenderAsPngsThatTheScannerReadsBack() {
        val kcr = P4Png.kcr()
        assertTrue("the P4 directory", out.isDirectory || out.mkdirs())
        for (name in P4Png.NAMES) {
            val ur = P4Png.proofUr(kcr, name).uppercase()
            assertTrue(ur.startsWith("UR:KEEPCRYPT-PROOF/"))
            val png = File(out, "goahead-$name.png")
            png.writeBytes(P4Png.render(ur))
            val image = P4Png.readPng(png.readBytes())
            assertEquals(ur, decodeGoAhead(image.luminance, image.width, image.height))
        }
    }

    /** The PNG reader against its writer, on a small image with every grey level. */
    @Test
    fun thePngReaderReadsWhatTheWriterWrote() {
        val luminance = ByteArray(256 * 3) { (it % 256).toByte() }
        val image = P4Png.readPng(P4Png.png(256, 3, luminance))
        assertEquals(256, image.width)
        assertEquals(3, image.height)
        assertArrayEquals(luminance, image.luminance)
    }
}
