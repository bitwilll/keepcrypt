package com.keepcrypt.entropy.camera

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader

/**
 * The go-ahead QR scanner's decode step (tasks/todo.md, M5 group 16; commit 14's JVM test): one
 * frame's luminance, a byte per pixel, row by row with no padding, to the text of the QR code ZXing
 * core finds in it. Commit 18 puts the Camera2 frames around it (each YUV_420_888 frame's Y plane
 * reduced to this layout on a background thread, never stored) and hands the text to the same
 * onGoAheadText the tests call; until then the only caller is GoAheadPngTest, which reads the two
 * go-ahead PNGs back with it. ZXing throws when a frame holds no QR code it can read; nothing calls
 * this on such a frame before commit 18 brings the scanner that owns that case.
 */
internal fun decodeGoAhead(luminance: ByteArray, width: Int, height: Int): String {
    val source = PlanarYUVLuminanceSource(luminance, width, height, 0, 0, width, height, false)
    val hints = mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE))
    return QRCodeReader().decode(BinaryBitmap(HybridBinarizer(source)), hints).text
}
