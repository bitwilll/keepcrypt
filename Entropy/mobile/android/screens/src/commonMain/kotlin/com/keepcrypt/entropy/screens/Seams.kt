package com.keepcrypt.entropy.screens

// The platform seams (lead decision M5-20): Kotlin interfaces in the common code, each implemented in
// the platform's code and passed in at its entry point (on Android, :app's CeremonyHolder for the
// model's, and MainActivity for the screens'). Commit 15 brought the clock and the offline monitor;
// commit 16 the motion source and the airplane-settings opener; the documents and scanner seams
// follow with their screens. The build's testRegistry flag is the model's constructor argument, a
// Boolean that :app takes from its flavour.

/**
 * A monotonic clock, the one every timer reads (lessons.md, time rules per target): on Android
 * SystemClock.elapsedRealtime() and its nanosecond form, which count deep sleep and never follow the
 * wall clock; in the JVM tests a fake that the test moves on. The nanoseconds time the touches that
 * Device entropy mixes in (docs/mobile-apps.md, "Entropy sources on phones"), never a timer.
 */
interface MonotonicClock {
    fun nowMillis(): Long

    fun nowNanos(): Long
}

/**
 * The offline monitor (Q57: airplane mode on and Wi-Fi off). start reports the two states at once and
 * then each change, on the main thread, until stop; a second start reads them afresh. The model starts
 * it on every return to the app and stops it only at its end (wipeAll), so going online while the app
 * is away discards at once too. On Android it is secure-ui's SystemOffline, over the system's
 * airplane-mode and Wi-Fi settings; Go offline shows both states (docs/mobile-apps.md, step 3).
 */
interface OfflineMonitor {
    fun start(report: (airplaneMode: Boolean, wifiOff: Boolean) -> Unit)

    fun stop()
}

/**
 * The phone's motion (docs/mobile-apps.md, "Entropy sources on phones": the accelerometer and the
 * gyroscope, mixed in with no credit). start reports each sample as bytes, on the main thread, until
 * stop; the receiver owns each array and zeroes it once core has it. The model starts it on Device
 * entropy and stops it when that screen leaves, so samples reach core only until the commitment. On
 * Android it is :app's PhoneMotion, which needs no permission (it never asks for a sampling rate
 * above the platform's limit).
 */
interface MotionSource {
    fun start(report: (sample: ByteArray) -> Unit)

    fun stop()
}

/**
 * Go offline's button (docs/mobile-apps.md, step 3): the system's airplane-mode settings, opened over
 * the app. On Android it is :app's AirplaneModeSettings, in AirplaneSettingsIntent.kt, the one file
 * where the gate allows that call.
 */
fun interface AirplaneSettings {
    fun open()
}
