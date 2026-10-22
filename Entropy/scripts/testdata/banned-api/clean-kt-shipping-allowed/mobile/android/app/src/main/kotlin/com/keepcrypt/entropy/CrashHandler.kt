// The app's one uncaught-exception handler class: its header names the interface.
internal class CrashHandler(private val wipe: () -> Unit, private val end: () -> Unit) : Thread.UncaughtExceptionHandler {
