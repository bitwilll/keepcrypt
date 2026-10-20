// The one KcHalt catch, in the shared model: the halt status becomes the stop screen.
try { block() } catch (halt: KcHalt) { stop() }
} catch ( h : KcHalt ) {
