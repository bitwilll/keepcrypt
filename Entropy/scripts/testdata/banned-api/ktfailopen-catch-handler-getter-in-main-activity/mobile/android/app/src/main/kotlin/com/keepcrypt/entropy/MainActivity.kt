// A thread whose getter, the one the JVM asks for its handler, names a handler other than CrashHandler.
override fun getUncaughtExceptionHandler() = quiet
