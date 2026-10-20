// The one actual over kc_call, and the only file that pins memory.
internal actual object Native {
    actual fun call(op: Int, input: ByteArray): ByteArray {
        val out = ByteArray(kc_max_out().toInt())
        val n = input.usePinned { i -> out.usePinned { o -> kc_call(op.toUInt(), i.addressOf(0), input.size.toULong(), o.addressOf(0), out.size.toULong()) } }
        return out.copyOf(n)
    }
}
