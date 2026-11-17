// The bridge's bytes, decoded once (tasks/todo.md, M6 item C3; Q87; lead decisions M5-21 and M6-1):
// every reply starts with its status byte, and an OK reply goes on in its op's layout, each defined
// once in keepcrypt-ffi's wire.rs (its module comment and each op's doc). This file copies wire.rs's
// tables (the status bytes, the op numbers, the refusal codes and the halt codes) as Android's
// Wire.kt does, and KeepCryptTests' WireTests pins each copy against wire.rs's own source, its PINNED
// and PINNED_HALTS tables among them.
//
// Decoding is pure: it reads the reply in Core's buffer and copies out what it keeps, and a reply that
// does not fit its layout decodes as malformed, on which Core halts the slot (rule 3). Every value
// copied out of a reply that could hold a secret is a Secret, whose bytes are wiped when it is
// dropped (rule 5); a layout that fails part way drops, and so wipes, what it had copied.
//
// Unlike Android's, the halt status is a Reply (halted, with its reason): Swift's only way out of an
// error is Ceremony.halt, which ends the process, so the stop screen is shown from this value, and an
// exhaustive switch over Reply makes every caller handle it.

import Foundation

/// keepcrypt-ffi's wire.rs: the status bytes, the op table and the fixed lengths.
enum Wire {
    /// The call gave its result.
    static let ok: UInt8 = 0
    /// What the user or a file supplied was refused; the stage is as it was. Its code follows.
    static let refused: UInt8 = 1
    /// A discard or a wipe came during a long call, whose result was dropped.
    static let discarded: UInt8 = 2
    /// The slot halted, now or before. The code of the reason it latched follows.
    static let halted: UInt8 = 3

    /// The op numbers, wire.rs's 1-38, and 0, an op the table does not hold, on which the slot
    /// halts (keepcrypt-capi's HALT).
    enum Op: UInt32, CaseIterable {
        case halt = 0
        case selfTest = 1
        case start = 2
        case addExtra = 3
        case commit = 4
        case startDice = 5
        case pushRoll = 6
        case undoRoll = 7
        case finish = 8
        case skipCheck = 9
        case startCheck = 10
        case matchFound = 11
        case cannotCheck = 12
        case generateBackupPassphrase = 13
        case end = 14
        case discard = 15
        case wipeAll = 16
        case deviceProgress = 17
        case commitment = 18
        case diceProgress = 19
        case seal = 20
        case checkRequest = 21
        case revealCode = 22
        case revealSnapshot = 23
        case revealProof = 24
        case collisionReport = 25
        case wordPage = 26
        case checkReadback = 27
        case summary = 28
        case backupPassphrasePage = 29
        case backupChallenge = 30
        case confirmBackup = 31
        case encryptBackup = 32
        case verifyBackup = 33
        case watchOnly = 34
        case registration = 35
        case revealDeviceLeg = 36
        case loadSnapshot = 37
        case openBackup = 38
    }

    /// The Seal ID's length: 8 Crockford characters.
    static let sealIdLength = 8
    /// C and D: 32 bytes each.
    static let legLength = 32
    /// Crockford base32, the Seal ID's alphabet.
    static let crockford: [UInt8] = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ".utf8)
}

/// Where a refusal comes from, as wire.rs's refusal codes group them.
enum RefusalGroup {
    case code, core, snapshot, ur, backup
}

/// The code byte after a refused status, one per refusal, as wire.rs's refusal_code gives it: 1-3 a
/// go-ahead that does not verify; 16-19 core's refusals of a passphrase, a read-back, an empty BIP39
/// passphrase and a build with no registry key; 32-45 a snapshot or proof that does not verify; 48-59
/// a go-ahead QR's text that is no proof's UR; 64-72 a backup file that does not read. The names are
/// core's, so WireTests rebuilds wire.rs's PINNED names from them and their groups.
enum Refusal: UInt8, CaseIterable {
    case malformedCode = 1
    case wrongCode = 2
    case wrongBucket = 3
    case wrongPassphrase = 16
    case readbackMismatch = 17
    case emptyPassphrase = 18
    case noRegistryKey = 19
    case tooShort = 32
    case badMagic = 33
    case badVersion = 34
    case badSignature = 35
    case badDate = 36
    case tooManyEntries = 37
    case badLength = 38
    case unsorted = 39
    case duplicate = 40
    case zeroCount = 41
    case rootMismatch = 42
    case bucketOutOfRange = 43
    case entryOutsideBucket = 44
    case proofCount = 45
    case tooLong = 48
    case mixedCase = 49
    case notUr = 50
    case wrongType = 51
    case multiPart = 52
    case oddLength = 53
    case unknownByteword = 54
    case badChecksum = 55
    case notByteString = 56
    case nonShortestHead = 57
    case indefiniteLength = 58
    case trailingBytes = 59
    case tooLarge = 64
    case armor = 65
    case header = 66
    case workFactor = 67
    case headerMac = 68
    case payload = 69
    case plaintext = 70
    case unsupportedVersion = 71
    case passphraseWords = 72

    /// The group its code lies in.
    var group: RefusalGroup {
        switch rawValue {
        case 1...3: return .code
        case 16...19: return .core
        case 32...45: return .snapshot
        case 48...59: return .ur
        default: return .backup
        }
    }
}

/// Why the slot halted (docs/mobile-apps.md, "When something fails"): the code byte after the halt
/// status, as wire.rs's halt_code gives it, of the first halt, which the slot latches; the stop
/// screen draws one fixed line for each. Nothing about the halted call reaches it.
enum HaltReason: UInt8, CaseIterable {
    case knownAnswerTest = 1
    case entropySource = 2
    case healthTest = 3
    case `internal` = 4
    case exportSelfCheck = 5
    case panic = 6

    /// The reason whose code is code; a code the app does not know is internal.
    static func of(_ code: UInt8) -> HaltReason {
        HaltReason(rawValue: code) ?? .internal
    }
}

/// A call's result: done with the op's reply, refused with what the user or a file supplied that
/// core refused (the stage is as it was), discarded when a discard or a wipe came during a long call,
/// or halted: the slot has halted, now or before, and has dropped everything it held; only the stop
/// screen follows, and the process's end.
enum Reply<T> {
    case done(T)
    case refused(Refusal)
    case discarded
    case halted(HaltReason)
}

/// A reply as Wire.decode reads it: its Reply, or malformed (the bridge's bug), on which Core halts
/// the slot.
enum Decoded<T> {
    case reply(Reply<T>)
    case malformed
}

/// Secret bytes on the Swift side (rule 5; Android's Secret.kt): a Data this object owns from the
/// moment it is made, never handed out, read one byte at a time and wiped (resetBytes) when its page
/// or screen leaves or when the object is dropped. It has no text form of its own and no equality.
final class Secret {
    private var bytes: Data

    /// Takes count bytes from start, copied into storage of this object's own.
    init(copying start: UnsafeRawPointer, count: Int) {
        bytes = Data(bytes: start, count: count)
    }

    /// Takes these bytes; the caller keeps no other use of them.
    init(taking bytes: [UInt8]) {
        self.bytes = Data(bytes)
    }

    deinit {
        wipe()
    }

    /// How many bytes it holds.
    var count: Int { bytes.count }

    /// The byte at index.
    subscript(index: Int) -> UInt8 { bytes[bytes.startIndex + index] }

    /// Zeroes every byte.
    func wipe() {
        bytes.resetBytes(in: bytes.startIndex..<bytes.endIndex)
    }

    /// Its bytes written into input from at, for a call (a copy Core wipes once the call returns).
    func copyBytes(into input: inout [UInt8], at: Int) {
        for index in 0..<bytes.count {
            input[at + index] = self[index]
        }
    }

    /// length of its bytes from start, as a Secret of their own (a copy its owner wipes).
    func slice(from start: Int, length: Int) -> Secret {
        var part = [UInt8](repeating: 0, count: length)
        for index in 0..<length {
            part[index] = self[start + index]
        }
        return Secret(taking: part)
    }
}

/// A reply's body, read field by field, as wire.rs's fields are laid out: integers big-endian, a flag
/// one byte 0 or 1, a text its length in one byte and then its bytes, a file the rest. Each read gives
/// nil past the end or for a value out of its range, and the layout then gives nil: malformed.
struct Reader {
    private let reply: UnsafeRawBufferPointer
    private var at: Int

    init(_ reply: UnsafeRawBufferPointer, at: Int) {
        self.reply = reply
        self.at = at
    }

    /// Every byte has been read.
    var atEnd: Bool { at == reply.count }

    mutating func byte() -> UInt8? {
        guard at < reply.count else { return nil }
        let value = reply[at]
        at += 1
        return value
    }

    mutating func flag() -> Bool? {
        switch byte() {
        case 0: return false
        case 1: return true
        default: return nil
        }
    }

    mutating func u16() -> UInt16? {
        guard let high = byte(), let low = byte() else { return nil }
        return UInt16(high) << 8 | UInt16(low)
    }

    mutating func u32() -> UInt32? {
        var value: UInt32 = 0
        for _ in 0..<4 {
            guard let next = byte() else { return nil }
            value = value << 8 | UInt32(next)
        }
        return value
    }

    mutating func u64() -> UInt64? {
        var value: UInt64 = 0
        for _ in 0..<8 {
            guard let next = byte() else { return nil }
            value = value << 8 | UInt64(next)
        }
        return value
    }

    /// The byte offset bytes ahead, left unread.
    func peek(_ offset: Int) -> UInt8? {
        guard offset >= 0, offset < reply.count - at else { return nil }
        return reply[at + offset]
    }

    /// The next length bytes, copied out into a Secret.
    mutating func bytes(_ length: Int) -> Secret? {
        guard length >= 0, length <= reply.count - at, let base = reply.baseAddress else { return nil }
        let out = Secret(copying: base + at, count: length)
        at += length
        return out
    }

    /// The next length bytes of a public value, copied out.
    mutating func publicBytes(_ length: Int) -> [UInt8]? {
        guard length >= 0, length <= reply.count - at else { return nil }
        let out = Array(reply[at..<(at + length)])
        at += length
        return out
    }

    /// A text field's bytes, copied out into a Secret.
    mutating func text() -> Secret? {
        guard let length = byte() else { return nil }
        return bytes(Int(length))
    }

    /// A text field holding ASCII or UTF-8 that is no secret; nil when it is not UTF-8.
    mutating func publicText() -> String? {
        guard let length = byte(), let text = publicBytes(Int(length)) else { return nil }
        return String(bytes: text, encoding: .utf8)
    }

    /// Every byte left, copied out into a Secret.
    mutating func rest() -> Secret? {
        bytes(reply.count - at)
    }
}

extension Wire {
    /// A reply as Core reads it: the status byte, then for OK the op's layout, read whole; a refusal
    /// its code, a discard the status alone, a halt its reason's code (a code the app does not know
    /// is internal). Anything else (no status byte, a layout that does not fit at any field or at the
    /// end, a refusal code wire.rs does not define, a refusal or a halt status of another length, a
    /// discard with a byte after it, a status wire.rs does not define) is malformed.
    static func decode<T>(_ reply: UnsafeRawBufferPointer, _ layout: (inout Reader) -> T?) -> Decoded<T> {
        guard let status = reply.first else { return .malformed }
        switch status {
        case ok:
            var reader = Reader(reply, at: 1)
            guard let value = layout(&reader), reader.atEnd else { return .malformed }
            return .reply(.done(value))
        case refused:
            guard reply.count == 2, let refusal = Refusal(rawValue: reply[1]) else { return .malformed }
            return .reply(.refused(refusal))
        case discarded:
            guard reply.count == 1 else { return .malformed }
            return .reply(.discarded)
        case halted:
            guard reply.count == 2 else { return .malformed }
            return .reply(.halted(HaltReason.of(reply[1])))
        default:
            return .malformed
        }
    }
}

// The values the replies carry (Android's Core.kt), each decoded by its layout below.

/// The seed's length: 12 words (128 bits, one device) or 24 (256 bits, two devices).
enum Words: UInt8 {
    case twelve = 12
    case twentyFour = 24
}

/// New seed (dice with the device's own entropy) or Dice-only seed.
enum Mode: UInt8 {
    case mixed = 1
    case diceOnly = 2
}

/// The uncredited extras a phone gives while collecting (MA:139-140).
enum Extra: UInt8 {
    case inputTiming = 1
    case motion = 2
}

/// The device leg's credit, in bits: what it has, and what the commitment needs.
struct DeviceProgress {
    let creditedBits: Int
    let requiredBits: Int
}

/// The dice screen's counts: the rolls, the minimum, and the bits so far in thousandths.
struct DiceProgress {
    let rolls: Int
    let minimum: Int
    let millibits: UInt32
}

/// The seal card (docs/seal-watchonly-braille.md, "The seal card"): the 8x8 grid, the colour index
/// into the Okabe-Ito palette (0-7), the Seal ID and the Seal ID in braille. Public values.
struct SealCard {
    let grid: [UInt8]
    let colourIndex: Int
    let sealId: String
    let sealIdBraille: String

    /// Whether the cell at row, column (each 0-7) is filled.
    func isFilled(row: Int, column: Int) -> Bool {
        (grid[row] >> (7 - column)) & 1 == 1
    }
}

/// A QR code's modules, with no quiet zone (the screen draws it): side x side, row by row. The bits
/// are a Secret, since a registration or collision report carries a seal code and an account or
/// descriptor QR the xpub (lead decision M5-37).
final class QrMatrix {
    let side: Int
    private let bits: Secret

    init(side: Int, bits: Secret) {
        self.side = side
        self.bits = bits
    }

    /// Whether the module at column x, row y is dark.
    func isDark(x: Int, y: Int) -> Bool {
        let index = y * side + x
        return (bits[index / 8] >> (7 - index % 8)) & 1 == 1
    }

    func wipe() {
        bits.wipe()
    }
}

/// A registry snapshot's or bucket proof's freshness against the phone's date (swb:120).
enum Freshness {
    case current, stale, future
}

/// A loaded snapshot's or a verified proof's header: its number, its date (YYYYMMDD), its count (a
/// snapshot's seals, or the entries in a proof's bucket) and its freshness.
struct RegistryHeader {
    let number: UInt64
    let date: UInt32
    let count: UInt32
    let freshness: Freshness
}

/// A go-ahead's outcome: clear, the words are available, or collision, the seed was wiped unseen;
/// each with the snapshot's or proof's header, or none after a typed code.
enum Revealed {
    case clear(RegistryHeader?)
    case collision(RegistryHeader?)
}

/// A face of an insert: its letter (0 for a blank face), its dots (dot d at bit d - 1), the lighter
/// flag and its mirror partner (0 for none), ASCII.
struct Face {
    let letter: UInt8
    let dots: UInt8
    let isLighter: Bool
    let mirrorPartner: UInt8

    var isBlank: Bool { letter == 0 }
}

/// One insert's page (Q58: one page at a time), kept whole in a Secret and read from it on demand:
/// the position, the count, the device and devices ("device 1 of 2"), the sequence on face 6, the
/// SeedBook number, the word and faces 1-5. wipe() when the page leaves.
final class WordPage {
    private let page: Secret

    init(_ page: Secret) {
        self.page = page
    }

    var position: Int { Int(page[0]) }
    var count: Int { Int(page[1]) }
    var device: Int { Int(page[2]) }
    var devices: Int { Int(page[3]) }
    var sequence: Int { Int(page[4]) }
    var seedbook: Int { Int(page[5]) << 8 | Int(page[6]) }
    private var wordLength: Int { Int(page[7]) }

    /// The word, as a Secret of its own that its owner wipes.
    func word() -> Secret {
        page.slice(from: 8, length: wordLength)
    }

    /// Face n (1-5).
    func face(_ n: Int) -> Face {
        let at = 8 + wordLength + 4 * (n - 1)
        return Face(letter: page[at], dots: page[at + 1], isLighter: page[at + 2] == 1, mirrorPartner: page[at + 3])
    }

    func wipe() {
        page.wipe()
    }
}

/// A face's read-back verdict, in wire.rs's order (its code is its raw value).
enum Verdict: UInt8, CaseIterable {
    case ok = 0
    case mirrorMisread = 1
    case shouldBeBlank = 2
    case shouldHaveLetter = 3
    case wrongLetter = 4
}

/// One face of a mismatch: its verdict, and a wrong letter's missing and extra dots.
struct FaceVerdict {
    let verdict: Verdict
    let missingDots: UInt8
    let extraDots: UInt8
}

/// A mismatch: core's verdicts on faces 1-4, which with the letters read give the word's own, so they
/// are kept whole in a Secret and read on demand. wipe() when its screen leaves.
final class Mismatch {
    private let verdicts: Secret

    init(_ verdicts: Secret) {
        self.verdicts = verdicts
    }

    /// Face n's (1-4) verdict. Each verdict was checked when the reply was read, so one that is no
    /// verdict is the app's own bug, which ends it.
    func face(_ n: Int) -> FaceVerdict {
        let at = 3 * (n - 1)
        guard let verdict = Verdict(rawValue: verdicts[at]) else { Ceremony.halt(.bridge) }
        return FaceVerdict(verdict: verdict, missingDots: verdicts[at + 1], extraDots: verdicts[at + 2])
    }

    func wipe() {
        verdicts.wipe()
    }
}

/// An insert read back: a match (and whether every insert has now matched), or a mismatch.
enum Readback {
    case match(complete: Bool)
    case mismatch(Mismatch)
}

/// The wallet summary: the fingerprint (4 bytes) and the first receive address. Public values.
struct Summary {
    let fingerprint: [UInt8]
    let firstAddress: String
}

/// A confirm question: the word's position (1-8) and its four choices.
struct Question {
    let position: Int
    let choices: [Secret]
}

/// The backup passphrase's confirm: two questions. wipe() when the screen leaves.
struct Challenge {
    let questions: [Question]

    func wipe() {
        for question in questions {
            for choice in question.choices {
                choice.wipe()
            }
        }
    }
}

/// The encrypted backup, made in memory (rule 8: no plaintext ever reaches a file): core's suggested
/// name and the age file's bytes, ciphertext only, wiped once the backup step is over.
struct BackupFile {
    let name: String
    let bytes: Secret
}

/// The watch-only export: its summary, whether a BIP39 passphrase was used, and its two QR codes.
struct WatchOnly {
    let summary: Summary
    let passphraseUsed: Bool
    let account: QrMatrix
    let descriptors: QrMatrix

    func wipe() {
        account.wipe()
        descriptors.wipe()
    }
}

/// "Check a backup": the backup's fingerprint, seal card and re-check QR, public values; its words
/// stay in the slot, one page at a time.
struct OpenedBackup {
    let fingerprint: [UInt8]
    let seal: SealCard
    let recheck: QrMatrix
}

// Each op's reply layout (wire.rs's layout functions, read back): nil where the reply does not fit.

extension Reader {
    /// A status-only op's reply: nothing after the status.
    mutating func nothing() -> Void? {
        ()
    }

    /// The device leg's credit, in bits: a phone's quota is 256, so more than 2^16 is the bridge's bug.
    mutating func deviceProgress() -> DeviceProgress? {
        guard let credited = u64(), let required = u64(), credited <= 65_536, required <= 65_536 else { return nil }
        return DeviceProgress(creditedBits: Int(credited), requiredBits: Int(required))
    }

    mutating func diceProgress() -> DiceProgress? {
        guard let rolls = u16(), let minimum = u16(), let millibits = u32() else { return nil }
        return DiceProgress(rolls: Int(rolls), minimum: Int(minimum), millibits: millibits)
    }

    /// C, 32 bytes, or nothing in dice-only mode (an empty Secret).
    mutating func commitment() -> Secret? {
        guard let c = rest(), c.count == 0 || c.count == Wire.legLength else { return nil }
        return c
    }

    mutating func sealCard() -> SealCard? {
        guard let grid = publicBytes(8), let colour = byte(), colour <= 7,
              let id = publicBytes(Wire.sealIdLength), id.allSatisfy({ Wire.crockford.contains($0) }),
              let braille = publicText()
        else { return nil }
        return SealCard(grid: grid, colourIndex: Int(colour), sealId: String(decoding: id, as: UTF8.self), sealIdBraille: braille)
    }

    /// A QR matrix: its side, 21-61 (versions 1-11), then side x side bits, the last byte's spare bits 0.
    mutating func qrMatrix() -> QrMatrix? {
        guard let side = byte(), side >= 21, side <= 61, (side - 17) % 4 == 0 else { return nil }
        let modules = Int(side) * Int(side)
        guard let bits = bytes((modules + 7) / 8) else { return nil }
        let spare = bits.count * 8 - modules
        guard spare == 0 || bits[bits.count - 1] & UInt8((1 << spare) - 1) == 0 else { return nil }
        return QrMatrix(side: Int(side), bits: bits)
    }

    mutating func registry() -> RegistryHeader? {
        guard let number = u64(), let date = u32(), let count = u32(), let fresh = byte() else { return nil }
        let freshness: Freshness
        switch fresh {
        case 0: freshness = .current
        case 1: freshness = .stale
        case 2: freshness = .future
        default: return nil
        }
        return RegistryHeader(number: number, date: date, count: count, freshness: freshness)
    }

    mutating func revealed() -> Revealed? {
        guard let outcome = byte(), let withHeader = flag() else { return nil }
        var header: RegistryHeader?
        if withHeader {
            guard let read = registry() else { return nil }
            header = read
        }
        switch outcome {
        case 0: return .clear(header)
        case 1: return .collision(header)
        default: return nil
        }
    }

    /// A word page, kept whole in a Secret: its seven fixed bytes, the word as a text (its length,
    /// then its letters) and the 20 bytes of faces 1-5, one copy of that span.
    mutating func wordPage() -> WordPage? {
        guard let length = peek(7), let page = bytes(7 + 1 + Int(length) + 20) else { return nil }
        return WordPage(page)
    }

    /// A read-back result: a match and its flag, or a mismatch, whose faces 1-4 (three bytes each) are
    /// one copy of their 12 bytes, each verdict checked before the copy is taken.
    mutating func readback() -> Readback? {
        switch byte() {
        case 0:
            guard let complete = flag() else { return nil }
            return .match(complete: complete)
        case 1:
            for face in 0..<4 {
                guard let verdict = peek(3 * face), Verdict(rawValue: verdict) != nil else { return nil }
            }
            guard let verdicts = bytes(12) else { return nil }
            return .mismatch(Mismatch(verdicts))
        default:
            return nil
        }
    }

    mutating func summary() -> Summary? {
        guard let fingerprint = publicBytes(4), let address = publicText() else { return nil }
        return Summary(fingerprint: fingerprint, firstAddress: address)
    }

    mutating func challenge() -> Challenge? {
        var questions: [Question] = []
        for _ in 0..<2 {
            guard let position = byte() else { return nil }
            var choices: [Secret] = []
            for _ in 0..<4 {
                guard let choice = text() else { return nil }
                choices.append(choice)
            }
            questions.append(Question(position: Int(position), choices: choices))
        }
        return Challenge(questions: questions)
    }

    mutating func backupFile() -> BackupFile? {
        guard let name = publicText(), let file = rest() else { return nil }
        return BackupFile(name: name, bytes: file)
    }

    mutating func watchOnly() -> WatchOnly? {
        guard let summary = summary(), let used = flag(), let account = qrMatrix(), let descriptors = qrMatrix()
        else { return nil }
        return WatchOnly(summary: summary, passphraseUsed: used, account: account, descriptors: descriptors)
    }

    mutating func openedBackup() -> OpenedBackup? {
        guard let fingerprint = publicBytes(4), let seal = sealCard(), let recheck = qrMatrix() else { return nil }
        return OpenedBackup(fingerprint: fingerprint, seal: seal, recheck: recheck)
    }

    /// D: its 32 bytes, as a Secret.
    mutating func deviceLeg() -> Secret? {
        bytes(Wire.legLength)
    }
}
