// The call KeepCryptApp.kt may make, its argument keeping the platform's handler before CrashHandler.
Thread.setDefaultUncaughtExceptionHandler(
    Thread.getDefaultUncaughtExceptionHandler() ?: CrashHandler(wipe = { Core.wipeAll() }, end = { Process.killProcess(Process.myPid()) }),
)
