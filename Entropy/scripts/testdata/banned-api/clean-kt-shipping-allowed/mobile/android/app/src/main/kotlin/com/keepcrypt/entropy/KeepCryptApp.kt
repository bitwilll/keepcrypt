// The one default handler, CrashHandler, installed before any activity.
Thread.setDefaultUncaughtExceptionHandler(
    CrashHandler(wipe = { Core.wipeAll() }, end = { Process.killProcess(Process.myPid()) }),
)
