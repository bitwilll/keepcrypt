package com.keepcrypt.entropy

/**
 * The app's crash path (tasks/todo.md, M5 group 14; Q57; docs/mobile-apps.md, "When something fails
 * (Android)"): the handler every uncaught exception reaches, in place of the platform's own, which
 * would hand the exception to the activity manager for its crash report and dialog. It wipes
 * everything the slot holds first, then ends the process, and does nothing else: it logs nothing,
 * shows nothing and never reads the exception. The process ends even when the wipe throws (a halted
 * slot answers the wipe with KcHalt). Its two steps are passed in, so a JVM test can check their order
 * with fakes; KeepCryptApp passes Core.wipeAll and Process.killProcess.
 */
internal class CrashHandler(private val wipe: () -> Unit, private val end: () -> Unit) : Thread.UncaughtExceptionHandler {
    override fun uncaughtException(thread: Thread, exception: Throwable) {
        try {
            wipe()
        } finally {
            end()
        }
    }
}
