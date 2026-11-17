package com.keepcrypt.entropy.screens

// The platform seams (lead decision M5-20): Kotlin interfaces in the common code, each implemented in
// the platform's code and passed in at its entry point (on Android, :app's CeremonyHolder for the
// model's, and MainActivity for the screens'). Commit 15 brought the clock and the offline monitor;
// commit 16 the motion source and the airplane-settings opener; commit 17 the UTC date; commit 18 the
// QR scanner, a screens' seam; commit 20 the document pickers, a screens' seam the model's entry
// points take, with the places and files they hand back, and commit 21 their snapshot picker. The
// build's testRegistry flag is the model's constructor argument, a Boolean that :app takes from its
// flavour.

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
 * Today's date in UTC, as the number YYYYMMDD (lessons.md, time rules per target: phones read the UTC
 * date, and registry snapshot dates are UTC): the date core judges a loaded snapshot's freshness
 * against (Stale from day 31, Future after today), which the check's result warns of; never a timer.
 * On Android :app's UtcToday, java.time's date in UTC; in the JVM tests a fixed date.
 */
fun interface UtcDate {
    fun today(): Int
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

/**
 * The go-ahead QR scanner (docs/mobile-apps.md, step 9: the checker's go-ahead QR scanned back with the
 * camera, in airplane mode too; docs/seal-watchonly-braille.md, "Go-ahead QR"), the scan screen's: it
 * runs while that screen shows uncovered and the scan has not stopped (ScanScreen). start asks for the
 * camera (the system's prompt, while the app does not hold it), then reads frames until one holds a QR
 * code: its text goes to found, once, on the main thread, and the scan ends. A scan that cannot read
 * ends with why instead (stopped, once, on the main thread). stop ends a scan at any time, a prompt's
 * answer still to come included, and nothing reaches found or stopped after it. Nothing it reads is
 * drawn (there is no preview), logged or kept. On Android it is :app's GoAheadScanner
 * (camera/GoAheadScanner.kt, the one file where the gate allows the camera's classes) with
 * MainActivity's CAMERA prompt; the emulator tests, whose emulators have no camera, hand the drill's
 * texts to the model's onGoAheadText, where found's go.
 */
interface QrScanner {
    fun start(found: (text: String) -> Unit, stopped: (why: ScanStop) -> Unit)

    fun stop()
}

/** Why a scan ended without a code: the camera was refused, the phone has none the app can use, or it failed. */
enum class ScanStop { Refused, Missing, Failed }

/**
 * The system's document pickers (docs/mobile-apps.md, "Encrypted backup only" and "Reading a snapshot";
 * rule 8: the one file the app writes is the backup, and the only files it reads are .age backups and
 * .kcr snapshots), a screens' seam that the model's entry points take (saveBackup, checkBackup,
 * loadSnapshot), which call pickerOpened first: each opens an activity over the app's own (the picker
 * rule). create opens the create-document picker with core's suggested name, and the place picked goes
 * to the model's backupPlaced, null when the picker was left with none; open opens the open-document
 * picker for a file of any type (the model checks the name itself), and the file picked goes to
 * backupPicked, null for none; openSnapshot opens it the same way for Load registry snapshot, and the
 * file picked goes to snapshotPicked; each answer on the main thread. None keeps a place or a file, or
 * asks to keep access to one. On Android it is :app's Documents (files/Documents.kt, the one file where
 * the gate allows the document streams, the activity-result API's document contracts and a catch of
 * IOException), whose launchers MainActivity's onCreate registers, as it does the scanner's CAMERA
 * prompt; the emulator tests drive the system's pickers, and the JVM tests hand the model places and
 * files of their own.
 */
interface DocumentPickers {
    fun create(name: String)

    fun open()

    fun openSnapshot()
}

/** The place the create-document picker gave the backup: one write there, then the file there read back. */
interface DocumentPlace {
    /** Writes bytes there in one write, the file truncated first (mode "rwt"): false when the write failed. */
    fun write(bytes: ByteArray): Boolean

    /** The file there read back, at most limit + 1 bytes (one past limit says it is larger), or null when it could not be read. */
    fun readBack(limit: Int): ByteArray?
}

/**
 * A file the open-document picker gave: its name and size as its provider reports them (null where it
 * reports none), and its bytes, which the model reads only once the name and size pass, on its worker
 * behind "Working..." (a long call: a slow provider may hold read, never the main thread).
 */
interface PickedFile {
    val name: String?
    val size: Long?

    /** The file's bytes, at most limit + 1 (one past limit says it is larger), or null when it could not be read; called on the model's worker. */
    fun read(limit: Int): ByteArray?
}
