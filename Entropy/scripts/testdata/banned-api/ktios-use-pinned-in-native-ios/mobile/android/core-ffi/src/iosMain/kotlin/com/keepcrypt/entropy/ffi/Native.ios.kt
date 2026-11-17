        val n = input.usePinned { i -> kc_call(op.toUInt(), i.addressOf(0), input.size.toULong()) }
