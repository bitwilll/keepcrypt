package com.keepcrypt.entropy

import android.app.Application
import android.os.Process
import com.keepcrypt.entropy.ffi.Core

/**
 * The app's Application (tasks/todo.md, M5 group 14; the manifest names it): before any activity, it
 * replaces the platform's uncaught-exception handler with the app's crash path, which wipes the slot
 * through the bridge and then kills the process, so an unexpected Kotlin exception ends the app with
 * no dialog and no crash report of the activity manager's.
 */
class KeepCryptApp : Application() {
    override fun onCreate() {
        super.onCreate()
        Thread.setDefaultUncaughtExceptionHandler(
            CrashHandler(wipe = { Core.wipeAll() }, end = { Process.killProcess(Process.myPid()) }),
        )
    }
}
