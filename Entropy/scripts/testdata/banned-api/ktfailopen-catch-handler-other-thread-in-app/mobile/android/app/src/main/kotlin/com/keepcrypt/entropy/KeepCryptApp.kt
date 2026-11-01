// The call KeepCryptApp.kt may make, on another object whose name ends in Thread.
QuietThread.setDefaultUncaughtExceptionHandler(
    CrashHandler(wipe = { Core.wipeAll() }, end = { Process.killProcess(Process.myPid()) }),
)
