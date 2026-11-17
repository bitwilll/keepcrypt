// The one KcHalt catch with no import of core-ffi's KcHalt: the name could be any type.
try { block() } catch (halt: KcHalt) { stop() }
