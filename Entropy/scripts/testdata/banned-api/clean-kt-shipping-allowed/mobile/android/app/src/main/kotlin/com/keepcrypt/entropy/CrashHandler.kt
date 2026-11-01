// The app's one uncaught-exception handler class: its header names the interface, and its one
// override follows it.
internal class CrashHandler(private val wipe: () -> Unit, private val end: () -> Unit) : Thread.UncaughtExceptionHandler {
    override fun uncaughtException(thread: Thread, exception: Throwable) {
        try {
            wipe()
        } finally {
            end()
        }
    }
}
