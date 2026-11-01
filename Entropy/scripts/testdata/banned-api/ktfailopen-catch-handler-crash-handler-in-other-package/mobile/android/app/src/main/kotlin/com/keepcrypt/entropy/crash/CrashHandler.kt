// CrashHandler.kt's class header, in a file of the same name in another package.
internal class CrashHandler(private val wipe: () -> Unit, private val end: () -> Unit) : Thread.UncaughtExceptionHandler {
