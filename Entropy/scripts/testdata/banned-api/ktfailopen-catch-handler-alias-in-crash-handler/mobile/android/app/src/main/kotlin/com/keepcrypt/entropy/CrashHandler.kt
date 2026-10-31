package com.keepcrypt.entropy

// The class header CrashHandler.kt may write, beside an alias of the name it implements.
import java.lang.Thread.UncaughtExceptionHandler as QuietHandler

internal class CrashHandler(private val wipe: () -> Unit, private val end: () -> Unit) : Thread.UncaughtExceptionHandler {
    override fun uncaughtException(thread: Thread, exception: Throwable) {
