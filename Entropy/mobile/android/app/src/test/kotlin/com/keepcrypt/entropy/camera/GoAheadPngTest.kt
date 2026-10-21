package com.keepcrypt.entropy.camera

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.CRC32
import java.util.zip.DeflaterOutputStream
import java.util.zip.InflaterInputStream
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
 * own decode function, which must give the text again. The text is the ur field upper case (M5-42 as
 * amended: an alphanumeric QR, smaller than the lower-case byte-mode one and easier to scan from a
 * screen), which :core-ffi's RegistryTest reveals with too, so the code the owner's phone scans holds
 * what core is proven to verify.
 */
class GoAheadPngTest {
    private val entropy = File(checkNotNull(System.getProperty("kc.entropy")) { "app/build.gradle.kts sets kc.entropy" })
    private val out = File(checkNotNull(System.getProperty("kc.p4")) { "app/build.gradle.kts sets kc.p4" })

    @Test
    fun theTwoGoAheadQrsRenderAsPngsThatTheScannerReadsBack() {
        val kcr = File(entropy, "vectors/kcr.json").readText(Charsets.US_ASCII)
        assertTrue("the P4 directory", out.isDirectory || out.mkdirs())
        for (name in listOf("clear-empty-bucket", "collision-dice-50")) {
            val ur = proofUr(kcr, name).uppercase()
            assertTrue(ur.startsWith("UR:KEEPCRYPT-PROOF/"))
            val png = File(out, "goahead-$name.png")
            png.writeBytes(render(ur))
            val image = readPng(png.readBytes())
            assertEquals(ur, decodeGoAhead(image.luminance, image.width, image.height))
        }
    }

    /** The PNG reader against its writer, on a small image with every grey level. */
    @Test
    fun thePngReaderReadsWhatTheWriterWrote() {
        val luminance = ByteArray(256 * 3) { (it % 256).toByte() }
        val image = readPng(png(256, 3, luminance))
        assertEquals(256, image.width)
        assertEquals(3, image.height)
        assertArrayEquals(luminance, image.luminance)
    }

    private class Gray(val width: Int, val height: Int, val luminance: ByteArray)

    /** kcr.json's proof name's ur field, as vectorgen.py writes it: name, kcp1_hex, then ur. */
    private fun proofUr(kcr: String, name: String): String {
        val found = Regex("\"name\": \"" + Regex.escape(name) + "\",\\s*\"kcp1_hex\": \"[0-9a-f]+\",\\s*\"ur\": \"([a-z0-9:/-]+)\"")
            .findAll(kcr).toList()
        assertEquals("one proof " + name + " with its ur", 1, found.size)
        return found[0].groupValues[1]
    }

    /** text as a QR code at level L with a four-module quiet zone, SCALE pixels a module, black on white. */
    private fun render(text: String): ByteArray {
        val hints = mapOf(EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.L, EncodeHintType.MARGIN to 4)
        val matrix = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, 0, 0, hints)
        val width = matrix.width * SCALE
        val height = matrix.height * SCALE
        val gray = ByteArray(width * height)
        for (y in 0 until height) {
            for (x in 0 until width) {
                gray[y * width + x] = if (matrix.get(x / SCALE, y / SCALE)) BLACK else WHITE
            }
        }
        return png(width, height, gray)
    }

    /** An 8-bit greyscale PNG: the signature, IHDR, one IDAT of every row with filter 0, IEND. */
    private fun png(width: Int, height: Int, gray: ByteArray): ByteArray {
        val rows = ByteArrayOutputStream()
        DeflaterOutputStream(rows).use { z ->
            for (y in 0 until height) {
                z.write(0)
                z.write(gray, y * width, width)
            }
        }
        val header = ByteArrayOutputStream()
        header.write(be32(width))
        header.write(be32(height))
        header.write(byteArrayOf(8, 0, 0, 0, 0))
        val file = ByteArrayOutputStream()
        file.write(SIGNATURE)
        chunk(file, "IHDR", header.toByteArray())
        chunk(file, "IDAT", rows.toByteArray())
        chunk(file, "IEND", ByteArray(0))
        return file.toByteArray()
    }

    private fun chunk(file: ByteArrayOutputStream, type: String, data: ByteArray) {
        val crc = CRC32()
        crc.update(type.toByteArray(Charsets.US_ASCII))
        crc.update(data)
        file.write(be32(data.size))
        file.write(type.toByteArray(Charsets.US_ASCII))
        file.write(data)
        file.write(be32(crc.value.toInt()))
    }

    /** A PNG as png() writes it, read back: every chunk's CRC checked, 8-bit greyscale, filter 0 rows. */
    private fun readPng(bytes: ByteArray): Gray {
        assertArrayEquals(SIGNATURE, bytes.copyOfRange(0, 8))
        var at = 8
        var width = 0
        var height = 0
        val idat = ByteArrayOutputStream()
        while (at < bytes.size) {
            val length = int32(bytes, at)
            val type = String(bytes, at + 4, 4, Charsets.US_ASCII)
            val data = bytes.copyOfRange(at + 8, at + 8 + length)
            val crc = CRC32()
            crc.update(bytes, at + 4, 4 + length)
            assertEquals(type + "'s CRC", crc.value.toInt(), int32(bytes, at + 8 + length))
            when (type) {
                "IHDR" -> {
                    width = int32(data, 0)
                    height = int32(data, 4)
                    assertArrayEquals("8-bit greyscale, no interlace", byteArrayOf(8, 0, 0, 0, 0), data.copyOfRange(8, 13))
                }
                "IDAT" -> idat.write(data)
            }
            at += 12 + length
        }
        val rows = InflaterInputStream(idat.toByteArray().inputStream()).use { it.readBytes() }
        assertEquals((width + 1) * height, rows.size)
        val gray = ByteArray(width * height)
        for (y in 0 until height) {
            assertEquals("filter 0", 0, rows[y * (width + 1)].toInt())
            rows.copyInto(gray, y * width, y * (width + 1) + 1, (y + 1) * (width + 1))
        }
        return Gray(width, height, gray)
    }

    private fun be32(value: Int): ByteArray =
        byteArrayOf((value ushr 24).toByte(), (value ushr 16).toByte(), (value ushr 8).toByte(), value.toByte())

    private fun int32(bytes: ByteArray, at: Int): Int =
        ((bytes[at].toInt() and 0xFF) shl 24) or ((bytes[at + 1].toInt() and 0xFF) shl 16) or
            ((bytes[at + 2].toInt() and 0xFF) shl 8) or (bytes[at + 3].toInt() and 0xFF)

    private companion object {
        const val SCALE = 8
        const val BLACK: Byte = 0
        const val WHITE: Byte = -1
        val SIGNATURE = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)
    }
}
