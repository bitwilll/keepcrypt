package com.keepcrypt.entropy

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.keepcrypt.entropy.ffi.QrMatrix
import com.keepcrypt.entropy.screens.CROCKFORD_KEYS
import java.security.MessageDigest
import org.junit.Assert.assertEquals

/**
 * The emulator tests' mock checker (tasks/todo.md, M5 group 16; lessons 2), as :core-ffi's
 * QrRoundTripTest is on the JVM: a QR code the screen drew read back in-process with ZXing (captures of
 * the app are black), the check request's T and nonce taken from its text, and the go-ahead code a
 * checker builds from them: SHA-256 over "KCE/v1/go" (9 ASCII bytes), T (32 bytes) and n (8 bytes), its
 * first 40 bits in Crockford base32, 8 symbols.
 */
internal object Checker {
    /** The registry's origin in every QR's text until M9 (core's seal module; QrRoundTripTest's). */
    const val ORIGIN = "https://registry.invalid"

    /** The check request's text: T as 64 and the nonce as 16 lower-case hex digits. */
    private val CHECK = Regex("^" + Regex.escape(ORIGIN) + "/check#t=([0-9a-f]{64})&n=([0-9a-f]{16})$")

    /**
     * matrix's text, read as a pure barcode (ZXing's PURE_BARCODE: the modules where the drawing put
     * them, four pixels a module inside the four-module quiet zone), as QrRoundTripTest reads it. The
     * matrix is left whole: the screen still draws it.
     */
    fun read(matrix: QrMatrix): String {
        val scale = 4
        val size = (matrix.side + 8) * scale
        val luminance = ByteArray(size * size) { (-1).toByte() }
        for (y in 0 until matrix.side) {
            for (x in 0 until matrix.side) {
                if (!matrix.isDark(x, y)) continue
                for (dy in 0 until scale) {
                    for (dx in 0 until scale) luminance[((y + 4) * scale + dy) * size + (x + 4) * scale + dx] = 0
                }
            }
        }
        val source = PlanarYUVLuminanceSource(luminance, size, size, 0, 0, size, size, false)
        val hints = mapOf(
            DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
            DecodeHintType.CHARACTER_SET to "UTF-8",
            DecodeHintType.PURE_BARCODE to true,
        )
        return QRCodeReader().decode(BinaryBitmap(HybridBinarizer(source)), hints).text
    }

    /** The check request's T and nonce, as hex, from its text. */
    fun request(text: String): Pair<String, String> {
        val found = CHECK.find(text) ?: throw AssertionError("the check QR is not a check request: " + text)
        return Pair(found.groupValues[1], found.groupValues[2])
    }

    /** The go-ahead code a checker gives for T and the nonce (hex): 8 Crockford symbols. */
    fun goAhead(tag: String, nonce: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("KCE/v1/go".toByteArray(Charsets.US_ASCII))
        digest.update(bytes(tag))
        digest.update(bytes(nonce))
        val first = digest.digest()
        var bits = 0L
        for (i in 0 until 5) bits = (bits shl 8) or (first[i].toLong() and 0xFF)
        return buildString {
            for (i in 0 until 8) append(CROCKFORD_KEYS[((bits shr (35 - 5 * i)) and 31).toInt()])
        }
    }

    /** A code the checker did not give: code with its last symbol moved on by one. */
    fun wrong(code: String): String {
        val next = CROCKFORD_KEYS[(CROCKFORD_KEYS.indexOf(code.last()) + 1) % CROCKFORD_KEYS.length]
        return code.dropLast(1) + next
    }

    /** code as the code entry shows it, in the checker's two groups of four. */
    fun grouped(code: String): String = code.substring(0, 4) + "-" + code.substring(4)

    /** Hex digits' bytes. */
    fun bytes(hex: String): ByteArray {
        assertEquals("an even number of hex digits", 0, hex.length % 2)
        return ByteArray(hex.length / 2) { i -> hex.substring(2 * i, 2 * i + 2).toInt(16).toByte() }
    }
}
