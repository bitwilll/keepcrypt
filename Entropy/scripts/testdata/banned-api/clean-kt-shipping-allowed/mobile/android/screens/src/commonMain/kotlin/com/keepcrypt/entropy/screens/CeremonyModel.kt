// The one KcHalt catch, in the shared model: the halt status becomes the stop screen.
import com.keepcrypt.entropy.ffi.KcHalt
try { block() } catch (halt: KcHalt) { stop() }
} catch ( h : KcHalt ) {
