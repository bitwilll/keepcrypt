// KcHalt's import line inside a block comment is no import: the name could be any type.
/*
import com.keepcrypt.entropy.ffi.KcHalt
*/
try { block() } catch (halt: KcHalt) { stop() }
