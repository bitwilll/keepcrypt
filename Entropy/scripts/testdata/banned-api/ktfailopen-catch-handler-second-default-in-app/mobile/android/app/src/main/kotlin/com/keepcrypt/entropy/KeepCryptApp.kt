// The one call KeepCryptApp.kt may make, then a second of the same form, which would replace it.
Thread.setDefaultUncaughtExceptionHandler(
    CrashHandler(wipe = { Core.wipeAll() }, end = { Process.killProcess(Process.myPid()) }),
)
Thread.setDefaultUncaughtExceptionHandler(CrashHandler(wipe = {}, end = {}))
