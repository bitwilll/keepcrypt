package com.keepcrypt.entropy.screens

// The platform seams (lead decision M5-20): Kotlin interfaces in the common code, each implemented in
// the platform's code and passed in at its entry point (on Android, :app's CeremonyHolder). This commit
// brings the clock and the offline monitor; the documents, scanner, motion-source and
// airplane-settings seams follow with their screens. The build's testRegistry flag is the model's
// constructor argument, a Boolean that :app takes from its flavour.

/**
 * A monotonic clock in milliseconds, the one every timer reads (lessons.md, time rules per target): on
 * Android SystemClock.elapsedRealtime(), which counts deep sleep and never follows the wall clock; in
 * the JVM tests a fake that the test moves on.
 */
fun interface MonotonicClock {
    fun nowMillis(): Long
}

/**
 * The offline monitor (Q57: airplane mode on and Wi-Fi off). start reports the state at once and then
 * each change, on the main thread, until stop; a second start reads the state afresh. The model starts
 * it on every return to the app and stops it only at its end (wipeAll), so going online while the app
 * is away discards at once too. On Android it is secure-ui's SystemOffline, over the system's
 * airplane-mode and Wi-Fi settings.
 */
interface OfflineMonitor {
    fun start(report: (offline: Boolean) -> Unit)

    fun stop()
}
