// The one call into the Rust core (tasks/todo.md, M6 item C3; Q87; lead decision M6-1): keepcrypt-capi's
// kc_call, through keepcrypt.h's module map (mobile/ios/KeepCryptCore), and the typed calls over it, one
// per op of keepcrypt-ffi's wire.rs (Android's Core.kt).
//
// - **The buffer.** No memory of the library crosses the boundary: Core owns the one reply buffer,
//   kc_max_out() bytes, allocated once for the process, into which kc_call writes each reply. Each
//   reply is decoded in place (Wire.decode copies out what it keeps, secrets into Secrets) and the
//   whole buffer is then wiped with memset_s, which the compiler may not drop. Each input is wiped the
//   same way once the call returns.
// - **Fail closed.** kc_call's -1 means the slot could not read or answer the call and has halted; a
//   reply that does not fit its layout is the bridge's bug, on which Core halts the slot (the op the
//   table does not hold, Wire.Op.halt). Either way the call gives halted, with the reason the slot
//   latched. An argument out of its range is the app's own bug, and ends the app (Ceremony.halt).
// - **One call at a time.** A lock holds the buffer for the whole call. A long call (start, finish,
//   the backup's scrypt, a snapshot's load, the self-test) blocks a second call until it returns, so
//   a discard during one waits for it; Stage D's model runs long calls off the main thread.

import Foundation
import KeepCryptCore

final class Core: @unchecked Sendable {
    /// The process's one Core, as the slot is the process's one.
    static let shared = Core()

    /// A backup file's name ends so: core's FILE_NAME_SUFFIX (core/src/backup.rs); Check a backup opens no
    /// file whose name does not, in any letter case (Android's Core.BACKUP_SUFFIX).
    static let backupSuffix = ".age"

    /// The largest backup file core reads: age's 8 KiB, core's MAX_FILE_BYTES (core/src/backup/age.rs)
    /// (Android's Core.BACKUP_MAX_BYTES).
    static let backupMaxBytes = 8 * 1024

    /// A registry snapshot's name ends so (rule 8): Load registry snapshot opens no file whose name does
    /// not, in any letter case (Android's Core.SNAPSHOT_SUFFIX).
    static let snapshotSuffix = ".kcr"

    /// The largest snapshot core reads: its signed header, 122 bytes, and 2^22 entries of 18 bytes, the
    /// file keepcrypt-capi's MAX_INPUT takes after the date's 4 bytes (Android's Core.SNAPSHOT_MAX_BYTES).
    static let snapshotMaxBytes = 122 + 18 * (1 << 22)

    private let lock = NSRecursiveLock()
    private let capacity: Int
    private let buffer: UnsafeMutablePointer<UInt8>

    private init() {
        capacity = kc_max_out()
        buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
        buffer.initialize(repeating: 0, count: capacity)
    }

    /// op with input, which is wiped once the call returns (passed inout, so the caller's one copy is
    /// the one wiped), and its reply, decoded by layout.
    private func call<T>(_ op: Wire.Op, _ input: inout [UInt8], _ layout: (inout Reader) -> T?) -> Reply<T> {
        lock.lock()
        defer { lock.unlock() }
        let length = input.withUnsafeBufferPointer { bytes in
            kc_call(op.rawValue, bytes.baseAddress, bytes.count, buffer, capacity)
        }
        let inputWiped = Core.wipe(&input)
        var decoded: Decoded<T> = .malformed
        if length >= 0, length <= Int64(capacity) {
            decoded = Wire.decode(UnsafeRawBufferPointer(start: buffer, count: Int(length)), layout)
        }
        guard wipeBuffer(), inputWiped else { Ceremony.halt(.bridge) }
        switch decoded {
        case .reply(let reply):
            return reply
        case .malformed:
            return .halted(haltSlot())
        }
    }

    /// op with no input.
    private func call<T>(_ op: Wire.Op, _ layout: (inout Reader) -> T?) -> Reply<T> {
        var none: [UInt8] = []
        return call(op, &none, layout)
    }

    /// Halts the slot (an op the table does not hold), and the reason it latched: internal, unless it
    /// had halted before, whose first reason it keeps. Called with the lock held.
    private func haltSlot() -> HaltReason {
        let length = kc_call(Wire.Op.halt.rawValue, nil, 0, buffer, capacity)
        var reason = HaltReason.internal
        if length == 2, buffer[0] == Wire.halted {
            reason = HaltReason.of(buffer[1])
        }
        guard wipeBuffer() else { Ceremony.halt(.bridge) }
        return reason
    }

    /// Zeroes the whole reply buffer with memset_s; false if it did not.
    private func wipeBuffer() -> Bool {
        memset_s(buffer, capacity, 0, capacity) == 0
    }

    /// Zeroes bytes with memset_s; false if it did not.
    private static func wipe(_ bytes: inout [UInt8]) -> Bool {
        bytes.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress else { return true }
            return memset_s(base, raw.count, 0, raw.count) == 0
        }
    }

    /// Ceremony.halt's last call: halts the slot, which drops everything it held, and wipes the reply
    /// buffer; whether the wipe happened.
    func endForExit() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        let length = kc_call(Wire.Op.halt.rawValue, nil, 0, buffer, capacity)
        return wipeBuffer() && length == 2
    }

    /// The shell's own halt (Android's Core.halt, named apart since the gate keeps the one halt
    /// function to Ceremony.halt): halts the slot, an op the table does not hold, and gives the halt status with the
    /// reason the slot latched, internal unless it had halted before.
    func shellHalt() -> Reply<Void> {
        lock.lock()
        defer { lock.unlock() }
        return .halted(haltSlot())
    }

    /// Whether the reply buffer holds nothing but zeros: what every call leaves, which KeepCryptTests
    /// reads after each call. It shows nothing of what the buffer held.
    func replyBufferIsWiped() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        for index in 0..<capacity where buffer[index] != 0 {
            return false
        }
        return true
    }

    // The typed calls, one per op of wire.rs (Android's Core.kt). Each input is one array, made once:
    // its fixed bytes and each secret's copied into it, so no other copy is left to wipe.

    func selfTest() -> Reply<Void> { status(.selfTest) }

    func start(_ words: Words, _ mode: Mode) -> Reply<Void> {
        var input = [words.rawValue, mode.rawValue]
        return call(.start, &input) { $0.nothing() }
    }

    func addExtra(_ source: Extra, _ bytes: Secret) -> Reply<Void> {
        var input = Core.input([source.rawValue], bytes)
        return call(.addExtra, &input) { $0.nothing() }
    }

    func commit() -> Reply<Void> { status(.commit) }

    func startDice() -> Reply<Void> { status(.startDice) }

    /// One roll, the face 1-6.
    func pushRoll(_ face: Int) -> Reply<Void> {
        var input = [Core.small(face, 1...6)]
        return call(.pushRoll, &input) { $0.nothing() }
    }

    func undoRoll() -> Reply<Void> { status(.undoRoll) }

    func finish() -> Reply<Void> { status(.finish) }

    func skipCheck() -> Reply<Void> { status(.skipCheck) }

    func startCheck() -> Reply<Void> { status(.startCheck) }

    func matchFound() -> Reply<Void> { status(.matchFound) }

    func cannotCheck() -> Reply<Void> { status(.cannotCheck) }

    func generateBackupPassphrase() -> Reply<Void> { status(.generateBackupPassphrase) }

    func end() -> Reply<Void> { status(.end) }

    func discard() -> Reply<Void> { status(.discard) }

    func wipeAll() -> Reply<Void> { status(.wipeAll) }

    func deviceProgress() -> Reply<DeviceProgress> { call(.deviceProgress) { $0.deviceProgress() } }

    /// C, 32 bytes, or an empty Secret in dice-only mode.
    func commitment() -> Reply<Secret> { call(.commitment) { $0.commitment() } }

    func diceProgress() -> Reply<DiceProgress> { call(.diceProgress) { $0.diceProgress() } }

    func seal() -> Reply<SealCard> { call(.seal) { $0.sealCard() } }

    func checkRequest() -> Reply<QrMatrix> { call(.checkRequest) { $0.qrMatrix() } }

    /// The typed go-ahead code, as the pad wrote it.
    func revealCode(_ code: Secret) -> Reply<Revealed> {
        var input = Core.input([], code)
        return call(.revealCode, &input) { $0.revealed() }
    }

    /// The check against the loaded snapshot, on today's UTC date (YYYYMMDD).
    func revealSnapshot(today: UInt32) -> Reply<Revealed> {
        var input = Core.date(today)
        return call(.revealSnapshot, &input) { $0.revealed() }
    }

    /// A scanned go-ahead QR's text, on today's UTC date (YYYYMMDD).
    func revealProof(today: UInt32, text: String) -> Reply<Revealed> {
        var input = Core.date(today) + Array(text.utf8)
        return call(.revealProof, &input) { $0.revealed() }
    }

    func collisionReport() -> Reply<QrMatrix> { call(.collisionReport) { $0.qrMatrix() } }

    /// Insert position's page (1-24).
    func wordPage(_ position: Int) -> Reply<WordPage> {
        var input = [Core.small(position, 1...24)]
        return call(.wordPage, &input) { $0.wordPage() }
    }

    /// Insert position (1-24) read back: the three or four letters read from the metal.
    func checkReadback(_ position: Int, letters: Secret) -> Reply<Readback> {
        var input = Core.input([Core.small(position, 1...24)], letters)
        return call(.checkReadback, &input) { $0.readback() }
    }

    func summary() -> Reply<Summary> { call(.summary) { $0.summary() } }

    /// A page (0 or 1) of the backup passphrase: four words one space apart.
    func backupPassphrasePage(_ page: Int) -> Reply<Secret> {
        var input = [Core.small(page, 0...1)]
        return call(.backupPassphrasePage, &input) { $0.text() }
    }

    func backupChallenge() -> Reply<Challenge> { call(.backupChallenge) { $0.challenge() } }

    /// The confirm's picks, each 0-3 in its question's order: whether both are right.
    func confirmBackup(_ first: Int, _ second: Int) -> Reply<Bool> {
        var input = [Core.small(first, 0...3), Core.small(second, 0...3)]
        return call(.confirmBackup, &input) { $0.flag() }
    }

    func encryptBackup() -> Reply<BackupFile> { call(.encryptBackup) { $0.backupFile() } }

    /// The saved backup read back.
    func verifyBackup(_ file: Secret) -> Reply<Void> {
        var input = Core.input([], file)
        return call(.verifyBackup, &input) { $0.nothing() }
    }

    /// The watch-only export, with no BIP39 passphrase (nil) or with one.
    func watchOnly(passphrase: Secret?) -> Reply<WatchOnly> {
        var input: [UInt8] = [0]
        if let passphrase {
            input = Core.input([1], passphrase)
        }
        return call(.watchOnly, &input) { $0.watchOnly() }
    }

    func registration() -> Reply<QrMatrix> { call(.registration) { $0.qrMatrix() } }

    /// D, 32 bytes, for verify.py.
    func revealDeviceLeg() -> Reply<Secret> { call(.revealDeviceLeg) { $0.deviceLeg() } }

    /// Load registry snapshot: the .kcr file's bytes (a public file, held in a Secret as every file the
    /// app reads), on today's UTC date (YYYYMMDD).
    func loadSnapshot(today: UInt32, file: Secret) -> Reply<RegistryHeader> {
        var input = Core.input(Core.date(today), file)
        return call(.loadSnapshot, &input) { $0.registry() }
    }

    /// Check a backup: the eight entries (each a word or its first four letters, a text each) and the
    /// file, in one array.
    func openBackup(entries: [Secret], file: Secret) -> Reply<OpenedBackup> {
        guard entries.count == 8 else { Ceremony.halt(.bridge) }
        var size = file.count
        for entry in entries {
            guard entry.count <= 255 else { Ceremony.halt(.bridge) }
            size += 1 + entry.count
        }
        var input = [UInt8](repeating: 0, count: size)
        var at = 0
        for entry in entries {
            input[at] = UInt8(entry.count)
            entry.copyBytes(into: &input, at: at + 1)
            at += 1 + entry.count
        }
        file.copyBytes(into: &input, at: at)
        return call(.openBackup, &input) { $0.openedBackup() }
    }

    private func status(_ op: Wire.Op) -> Reply<Void> {
        call(op) { $0.nothing() }
    }

    /// value as one byte, when it lies in range; else the app's own bug, which ends it.
    private static func small(_ value: Int, _ range: ClosedRange<Int>) -> UInt8 {
        guard range.contains(value) else { Ceremony.halt(.bridge) }
        return UInt8(value)
    }

    /// One input: head's bytes, then secret's, in one array made once.
    private static func input(_ head: [UInt8], _ secret: Secret) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: head.count + secret.count)
        for (index, byte) in head.enumerated() {
            out[index] = byte
        }
        secret.copyBytes(into: &out, at: head.count)
        return out
    }

    /// today (YYYYMMDD) as four bytes, big-endian.
    private static func date(_ today: UInt32) -> [UInt8] {
        [UInt8(today >> 24), UInt8(today >> 16 & 0xFF), UInt8(today >> 8 & 0xFF), UInt8(today & 0xFF)]
    }
}
