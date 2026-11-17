// A failure thrown as the standard library's CancellationException ends its coroutine as cancelled, not failed.
internal fun stop(): Nothing = throw kotlin.coroutines.cancellation.CancellationException("stopped")
