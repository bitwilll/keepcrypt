// CrashHandler.kt's class header, then the same header again.
internal class CrashHandler(private val wipe: () -> Unit, private val end: () -> Unit) : Thread.UncaughtExceptionHandler {
    override fun uncaughtException(thread: Thread, exception: Throwable) {
    }
}
internal class CrashHandler(private val wipe: () -> Unit, private val end: () -> Unit) : Thread.UncaughtExceptionHandler {
