// The call KeepCryptApp.kt may make, installing a CrashHandler whose wipe does nothing.
Thread.setDefaultUncaughtExceptionHandler(
    CrashHandler(wipe = {}, end = { Process.killProcess(Process.myPid()) }),
)
