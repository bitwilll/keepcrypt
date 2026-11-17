// A return inside a finally block, after a block of its own there, drops what decodeGoAhead threw.
internal fun goAheadText(luminance: ByteArray, width: Int, height: Int): String? {
    try {
        return decodeGoAhead(luminance, width, height)
    } finally {
        if (luminance.isNotEmpty()) {
            luminance.fill(0)
        }
        return null
    }
}
