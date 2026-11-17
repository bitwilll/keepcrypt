// The CeremonyModel's seams (tasks/todo.md, M6 item D2; Android's Seams.kt, lead decision M5-20): what the
// model is given when it is made, each the platform's here and a fake in KeepCryptTests, so the model is
// the same code under both. Core itself (every core call the model makes, short or long), the worker the
// long calls run on, the monotonic clock every timer reads, the UTC date a snapshot's freshness is judged
// on, and the motion source Device entropy mixes in; and the screens' seams the model's entry points take
// (the document pickers, the places and files they hand back) and the scan's stops. The offline check is
// no seam here: OfflineCheck.swift's monitor runs for the process's life (C5) and reports every change to
// the model's pathReported, where Android's model starts its monitor on each return.

import Foundation

/// Every core call the model makes (Android's Core object, which its model calls directly): Core's own
/// typed calls in the app, and in the tests Core's own too, or a stand-in over it where a test needs the
/// slot to halt without halting the process's one slot. Each gives the call's Reply; halted is the halt
/// status. Long calls are made on the worker, every other on the main thread.
protocol CeremonyCore: AnyObject {
    func selfTest() -> Reply<Void>
    func start(_ words: Words, _ mode: Mode) -> Reply<Void>
    func addExtra(_ source: Extra, _ bytes: Secret) -> Reply<Void>
    func commit() -> Reply<Void>
    func startDice() -> Reply<Void>
    func pushRoll(_ face: Int) -> Reply<Void>
    func undoRoll() -> Reply<Void>
    func finish() -> Reply<Void>
    func skipCheck() -> Reply<Void>
    func startCheck() -> Reply<Void>
    func matchFound() -> Reply<Void>
    func cannotCheck() -> Reply<Void>
    func generateBackupPassphrase() -> Reply<Void>
    func end() -> Reply<Void>
    func discard() -> Reply<Void>
    func wipeAll() -> Reply<Void>
    func commitment() -> Reply<Secret>
    func diceProgress() -> Reply<DiceProgress>
    func seal() -> Reply<SealCard>
    func checkRequest() -> Reply<QrMatrix>
    func revealCode(_ code: Secret) -> Reply<Revealed>
    func revealSnapshot(today: UInt32) -> Reply<Revealed>
    func revealProof(today: UInt32, text: String) -> Reply<Revealed>
    func collisionReport() -> Reply<QrMatrix>
    func wordPage(_ position: Int) -> Reply<WordPage>
    func checkReadback(_ position: Int, letters: Secret) -> Reply<Readback>
    func summary() -> Reply<Summary>
    func backupPassphrasePage(_ page: Int) -> Reply<Secret>
    func backupChallenge() -> Reply<Challenge>
    func confirmBackup(_ first: Int, _ second: Int) -> Reply<Bool>
    func encryptBackup() -> Reply<BackupFile>
    func verifyBackup(_ file: Secret) -> Reply<Void>
    func watchOnly(passphrase: Secret?) -> Reply<WatchOnly>
    func registration() -> Reply<QrMatrix>
    func revealDeviceLeg() -> Reply<Secret>
    func loadSnapshot(today: UInt32, file: Secret) -> Reply<RegistryHeader>
    func openBackup(entries: [Secret], file: Secret) -> Reply<OpenedBackup>
    /// Halts the slot (the shell's own bug, failed closed; Android's Core.halt, named apart since
    /// the gate keeps the one halt function to Ceremony.halt): the halt status with the slot's reason.
    func shellHalt() -> Reply<Void>
}

extension Core: CeremonyCore {}

/// A monotonic clock, the one every timer reads (lessons.md, time rules per target): one that counts
/// the phone's sleep and never follows the wall clock. The nanoseconds time the touches Device entropy
/// mixes in (docs/mobile-apps.md, "Entropy sources on phones"), never a timer.
protocol MonotonicClock: AnyObject {
    func nowMillis() -> Int64
    func nowNanos() -> Int64
}

/// Today's date in UTC as the number YYYYMMDD (lessons.md: phones read the UTC date, and registry
/// snapshot dates are UTC): the date core judges a snapshot's freshness against; never a timer.
protocol UtcDate: AnyObject {
    func today() -> UInt32
}

/// The phone's motion (docs/mobile-apps.md, "Entropy sources on phones": the accelerometer and the
/// gyroscope, mixed in with no credit): start reports each sample, on the main thread, until stop; the
/// model owns each Secret and wipes it once core has it. The model starts it on Device entropy and stops
/// it when that screen leaves, so samples reach core only until the commitment.
protocol MotionSource: AnyObject {
    func start(_ report: @escaping (Secret) -> Void)
    func stop()
}

/// Where the model's long calls run (Android's worker dispatcher): job off the main thread, then main
/// on the main thread, in that order, one long call at a time. KeepCryptTests' worker holds each until
/// the test runs it, so a test can act while "Working..." shows.
protocol Worker: AnyObject {
    func run(_ job: @escaping () -> Void, then main: @escaping () -> Void)
}

/// Why a scan ended without a code: the camera was refused, the phone has none the app can use, or
/// it failed.
enum ScanStop: Equatable {
    case refused, missing, failed
}

/// The system's document pickers (docs/mobile-apps.md, "Encrypted backup only" and "Reading a
/// snapshot"; rule 8), a screens' seam the model's entry points take (saveBackup, checkBackup,
/// loadSnapshot): create offers the backup's place with core's suggested name, and its answer goes to
/// the model's backupPlaced; openBackup offers a file of any type (the model checks the name itself), whose
/// answer goes to backupPicked; openSnapshot the same for Load registry snapshot, to snapshotPicked.
/// None keeps a place or a file.
protocol DocumentPickers: AnyObject {
    func create(name: String)
    func openBackup()
    func openSnapshot()
}

/// The place the backup's picker gave: one write there, then the file there read back.
protocol DocumentPlace: AnyObject {
    /// Writes bytes there in one write, the file truncated first: false when the write failed.
    func write(_ bytes: Secret) -> Bool
    /// The file there read back, at most limit + 1 bytes (one past limit says it is larger), or nil
    /// when it could not be read.
    func readBack(limit: Int) -> Secret?
}

/// A file the open picker gave: its name and size as its provider reports them (nil where it reports
/// none), and its bytes, which the model reads only once the name and size pass, on its worker behind
/// "Working...".
protocol PickedFile: AnyObject {
    var name: String? { get }
    var size: Int64? { get }
    /// The file's bytes, at most limit + 1, or nil when it could not be read; called on the worker.
    func read(limit: Int) -> Secret?
}

/// The phone's monotonic clock: Darwin's CLOCK_MONOTONIC, which keeps counting while the phone sleeps
/// (Android's elapsedRealtime).
final class SystemClock: MonotonicClock {
    func nowMillis() -> Int64 {
        Int64(clock_gettime_nsec_np(CLOCK_MONOTONIC) / 1_000_000)
    }

    func nowNanos() -> Int64 {
        Int64(truncatingIfNeeded: clock_gettime_nsec_np(CLOCK_MONOTONIC))
    }
}

/// Today's date in UTC, from the system's time.
final class SystemDate: UtcDate {
    func today() -> UInt32 {
        var now = time(nil)
        var parts = tm()
        guard gmtime_r(&now, &parts) != nil, parts.tm_year >= 0, parts.tm_mon >= 0, parts.tm_mday >= 1 else {
            Ceremony.halt(.bridge)
        }
        return UInt32(parts.tm_year + 1900) * 10_000 + UInt32(parts.tm_mon + 1) * 100 + UInt32(parts.tm_mday)
    }
}

/// The app's worker: one serial queue of its own for the long calls, each reply handed back on the main
/// queue.
final class QueueWorker: Worker {
    private let queue = DispatchQueue(label: "com.keepcrypt.entropy.worker", qos: .userInitiated)

    func run(_ job: @escaping () -> Void, then main: @escaping () -> Void) {
        queue.async {
            job()
            DispatchQueue.main.async(execute: main)
        }
    }
}

/// The motion sensors a sample names, by Android's sensor type numbers (Sensor.TYPE_ACCELEROMETER and
/// TYPE_GYROSCOPE), so both apps' samples have one layout (tasks/todo.md, M6 item D3).
enum MotionSensor: UInt32 {
    case accelerometer = 1
    case gyroscope = 4
}

/// One motion sample in Android's layout (its PhoneMotion, M5 group 15): the sensor's type (4 bytes), the
/// reading's timestamp in nanoseconds (8) and each value's IEEE 754 single-precision bits (4 each),
/// big-endian; 24 bytes for a sensor's three axes. It goes into the pool with no credit, so its units
/// (Core Motion's g and rad/s, where Android gives m/s2 and rad/s) change nothing. A Secret the model
/// wipes once core has it; the array it was built in is wiped here.
func motionSample(_ sensor: MotionSensor, timestampNanos: Int64, values: [Float]) -> Secret {
    var bytes = [UInt8](repeating: 0, count: 12 + 4 * values.count)
    putBigEndian(&bytes, 0, UInt64(sensor.rawValue), 4)
    putBigEndian(&bytes, 4, UInt64(bitPattern: timestampNanos), 8)
    for (index, value) in values.enumerated() {
        putBigEndian(&bytes, 12 + 4 * index, UInt64(value.bitPattern), 4)
    }
    let sample = Secret(taking: bytes)
    let wiped = bytes.withUnsafeMutableBytes { raw -> Bool in
        guard let base = raw.baseAddress else { return true }
        return memset_s(base, raw.count, 0, raw.count) == 0
    }
    guard wiped else { Ceremony.halt(.bridge) }
    return sample
}

/// The low size bytes of value, big-endian, into bytes from at.
private func putBigEndian(_ bytes: inout [UInt8], _ at: Int, _ value: UInt64, _ size: Int) {
    for index in 0..<size {
        bytes[at + index] = UInt8(truncatingIfNeeded: value >> (8 * UInt64(size - 1 - index)))
    }
}
