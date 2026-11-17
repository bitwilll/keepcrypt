// What the in-app pads type (tasks/todo.md, M6 items D2 and D3; Android's Pads.kt; docs/mobile-apps.md,
// "Text entry"): the system keyboard never opens. Each pad's keys come in a fixed order, and each press
// goes to the model (padKey), which types it into a PadEntry, never a String, that hands it to Core as a
// Secret. The pads' views come in D3.

import Combine
import Foundation

/// The dice pad's keys: the faces 1 to 6.
let diceKeys = "123456"

/// The letter pad's keys: a to z, for the first four letters of a word, which core completes.
let letterKeys = "abcdefghijklmnopqrstuvwxyz"

/// The go-ahead code's keys: the 32 Crockford base32 symbols, in their order (no I, L, O or U).
let crockfordKeys = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

/// The BIP39 passphrase's keys: printable ASCII, 0x20 (space) to 0x7E, in code order.
let asciiKeys = String(decoding: Array(UInt8(0x20)...UInt8(0x7E)), as: UTF8.self)

/// The ASCII pad shows its keys in pages of this many (8 x 4, as the Pi's three pages).
let asciiPageKeys = 32

/// The ASCII pad's pages.
let asciiPages = 3

/// The longest BIP39 passphrase the pad takes (docs/pi-firmware.md, step 12).
let asciiCapacity = 100

/// The keys on page (0-2) of the ASCII pad; a page that is none is the app's own bug, which ends it.
func asciiPage(_ page: Int) -> String {
    guard (0..<asciiPages).contains(page) else { Ceremony.halt(.bridge) }
    let keys = Array(asciiKeys)
    let first = page * asciiPageKeys
    return String(keys[first..<min(first + asciiPageKeys, keys.count)])
}

/// What a pad has typed (rule 5): up to capacity of the pad's keys, as ASCII bytes in a buffer this
/// object owns and zeroes with memset_s (a key deleted, the entry taken or wiped), never a String. take
/// hands the entry over as a Secret of exactly its length, for Core, and leaves this empty. It has no
/// text form. Its length is published, so a screen redraws only what reads the entry.
final class PadEntry: ObservableObject {
    let keys: String
    let capacity: Int
    private var bytes: [UInt8]

    /// How many keys are typed.
    @Published private(set) var length = 0

    init(keys: String, capacity: Int) {
        self.keys = keys
        self.capacity = capacity
        bytes = [UInt8](repeating: 0, count: capacity)
    }

    deinit {
        zero(from: 0)
    }

    var isFull: Bool { length == capacity }

    /// Types key, when it is one of the pad's keys and there is room; false otherwise (nothing changes).
    @discardableResult
    func type(_ key: Character) -> Bool {
        guard keys.contains(key), let code = key.asciiValue, length < capacity else { return false }
        bytes[length] = code
        length += 1
        return true
    }

    /// The entry becomes key alone (the dice pad's pick); false, and nothing changes, for another key.
    @discardableResult
    func replace(_ key: Character) -> Bool {
        guard keys.contains(key) else { return false }
        wipe()
        return type(key)
    }

    /// Deletes the last key typed and zeroes its byte.
    func delete() {
        guard length > 0 else { return }
        length -= 1
        zero(from: length)
    }

    /// The key typed at index, for the screen that shows the entry; an index past the entry is the app's
    /// own bug, which ends it.
    func keyAt(_ index: Int) -> Character {
        guard (0..<length).contains(index) else { Ceremony.halt(.bridge) }
        return Character(Unicode.Scalar(bytes[index]))
    }

    /// The entry as a Secret of its own, exactly length bytes, copied from the buffer once; this entry
    /// is wiped.
    func take() -> Secret {
        let count = length
        let secret = bytes.withUnsafeBytes { raw -> Secret in
            guard let base = raw.baseAddress else { Ceremony.halt(.bridge) }
            return Secret(copying: base, count: count)
        }
        wipe()
        return secret
    }

    /// The entry handed to use as take's Secret, which is wiped once use returns, so no copy of the keys
    /// typed outlives the call it was made for (rule 5); this entry is wiped. use's result is returned.
    func handOver<T>(_ use: (Secret) -> T) -> T {
        let secret = take()
        defer { secret.wipe() }
        return use(secret)
    }

    /// Zeroes every byte; nothing is typed.
    func wipe() {
        zero(from: 0)
        length = 0
    }

    /// Every byte past what is typed is zero (rule 5): the tests' check of delete, take and wipe.
    func zeroPastLength() -> Bool {
        bytes[length...].allSatisfy { $0 == 0 }
    }

    /// Zeroes the buffer from index on with memset_s, which the compiler may not drop; a wipe that
    /// failed ends the app.
    private func zero(from index: Int) {
        let wiped = bytes.withUnsafeMutableBytes { raw -> Bool in
            guard let base = raw.baseAddress, index < raw.count else { return true }
            return memset_s(base + index, raw.count - index, 0, raw.count - index) == 0
        }
        guard wiped else { Ceremony.halt(.bridge) }
    }
}

/// A pick on the dice pad: one face, until it is confirmed (and pushed) or picked again.
func dicePadEntry() -> PadEntry { PadEntry(keys: diceKeys, capacity: 1) }

/// A word's first four letters (a three-letter word's three) on the letter pad.
func letterPadEntry() -> PadEntry { PadEntry(keys: letterKeys, capacity: 4) }

/// The go-ahead code: eight Crockford symbols.
func crockfordPadEntry() -> PadEntry { PadEntry(keys: crockfordKeys, capacity: 8) }

/// A BIP39 passphrase: up to 100 printable ASCII characters.
func asciiPadEntry() -> PadEntry { PadEntry(keys: asciiKeys, capacity: asciiCapacity) }
