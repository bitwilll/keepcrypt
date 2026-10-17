// The one KcHalt catch: the halt status becomes the stop screen.
try { block() } catch (halt: KcHalt) { stop() }
} catch ( h : KcHalt ) {
