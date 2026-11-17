// A handler on the scanner's own HandlerThread: its failures would never reach CrashHandler.
thread.setUncaughtExceptionHandler { _, _ -> }
