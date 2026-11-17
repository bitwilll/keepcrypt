// The call KeepCryptApp.kt may make, after another call on its line.
Thread.setDefaultUncaughtExceptionHandler(null); Thread.setDefaultUncaughtExceptionHandler(
    CrashHandler(wipe = { Core.wipeAll() }, end = { Process.killProcess(Process.myPid()) }),
)
