// A thread group of the scanner's own: a thread with no handler of its own hands its failures to
// its group, whose override here would drop them before CrashHandler.
private val quiet = object : ThreadGroup("go-ahead scanner") {
