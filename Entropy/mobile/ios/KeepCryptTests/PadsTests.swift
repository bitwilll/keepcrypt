// The pads' entries and layout (tasks/todo.md, M6 item D3), ported from :screens' PadsTest.kt: every pad's
// keys in their fixed order and wide enough on the narrowest iPhone, each entry its capacity and its own
// keys alone, the dice pick replaced not appended, and Delete, take, wipe and handOver leaving nothing
// behind. Compose's snapshot-state test has no SwiftUI counterpart here: PadEntry's length is @Published,
// which SwiftUI observes. No slot is used.

import XCTest

final class PadsTests: XCTestCase {
    /// What entry holds, read in-process (test values only, never printed), and the entry emptied.
    private func taken(_ entry: PadEntry) -> String {
        let secret = entry.take()
        defer { secret.wipe() }
        return String(decoding: (0..<secret.count).map { secret[$0] }, as: UTF8.self)
    }

    /// PadsTest.kt's everyPadsKeysAre48DpWideOnTheNarrowestPhone, at Apple's 44 points.
    func testEveryPadsKeysAre44PointsWideOnTheNarrowestIphone() {
        XCTAssertEqual(keyPoints, 44)
        XCTAssertEqual(narrowestRow, 375 - 2 * 24)
        for (pad, columns) in [("dice", diceColumns), ("letter", letterColumns), ("go-ahead code", crockfordColumns), ("ASCII", asciiColumns)] {
            XCTAssertLessThanOrEqual(columns * keyPoints, narrowestRow, "the \(pad) pad's keys")
        }
    }

    /// PadsTest.kt's eachPadHasItsKeysInTheirFixedOrder.
    func testEachPadHasItsKeysInTheirFixedOrder() {
        XCTAssertEqual(diceKeys, "123456")
        XCTAssertEqual(letterKeys, "abcdefghijklmnopqrstuvwxyz")
        XCTAssertEqual(crockfordKeys.count, 32)
        XCTAssertEqual(String(crockfordKeys.prefix(10)), "0123456789")
        var expected = UInt8(ascii: "A")
        for key in crockfordKeys.utf8.dropFirst(10) {
            while "ILOU".utf8.contains(expected) { expected += 1 }
            XCTAssertEqual(key, expected)
            expected += 1
        }
        XCTAssertEqual(Array(asciiKeys.utf8), Array(UInt8(0x20)...UInt8(0x7E)))
        XCTAssertEqual((0..<asciiPages).map { asciiPage($0).count }, [32, 32, 31])
        XCTAssertEqual((0..<asciiPages).map(asciiPage).joined(), asciiKeys)
        XCTAssertEqual(asciiPage(0).first, " ")
        XCTAssertEqual(asciiPage(2).last, "~")
        XCTAssertEqual(keyLabel(" "), "space")
        XCTAssertEqual(keyLabel("a"), "a")
    }

    /// PadsTest.kt's eachPadTakesItsOwnCapacity.
    func testEachPadTakesItsOwnCapacity() {
        XCTAssertEqual(dicePadEntry().capacity, 1)
        XCTAssertEqual(letterPadEntry().capacity, 4)
        XCTAssertEqual(crockfordPadEntry().capacity, 8)
        XCTAssertEqual(asciiPadEntry().capacity, 100)
        let entry = crockfordPadEntry()
        for key in "CF94BCAJ" { XCTAssertTrue(entry.type(key)) }
        XCTAssertTrue(entry.isFull)
        XCTAssertFalse(entry.type("0"), "a ninth symbol is refused")
        XCTAssertEqual(taken(entry), "CF94BCAJ")
        let passphrase = asciiPadEntry()
        for _ in 0..<100 { XCTAssertTrue(passphrase.type("~")) }
        XCTAssertFalse(passphrase.type(" "))
        XCTAssertEqual(taken(passphrase).count, 100)
    }

    /// PadsTest.kt's anEntryHoldsOnlyItsPadsKeys.
    func testAnEntryHoldsOnlyItsPadsKeys() {
        let letters = letterPadEntry()
        XCTAssertFalse(letters.type("A"), "the letter pad has no capitals")
        XCTAssertFalse(letters.type("1"))
        XCTAssertTrue(letters.type("a"))
        let code = crockfordPadEntry()
        for key in "ILOUilou" { XCTAssertFalse(code.type(key), "not a Crockford symbol") }
        let dice = dicePadEntry()
        XCTAssertFalse(dice.replace("0"))
        XCTAssertFalse(dice.replace("7"))
        XCTAssertEqual(dice.length, 0)
    }

    /// PadsTest.kt's theDicePadsPickIsReplacedNotAppended.
    func testTheDicePadsPickIsReplacedNotAppended() {
        let dice = dicePadEntry()
        XCTAssertTrue(dice.replace("3"))
        XCTAssertTrue(dice.replace("5"))
        XCTAssertEqual(dice.length, 1)
        XCTAssertEqual(dice.keyAt(0), "5")
        XCTAssertEqual(taken(dice), "5")
        XCTAssertEqual(dice.length, 0)
    }

    /// PadsTest.kt's deleteTakeAndWipeLeaveNothingBehind.
    func testDeleteTakeAndWipeLeaveNothingBehind() {
        let letters = letterPadEntry()
        for key in "abou" { letters.type(key) }
        letters.delete()
        XCTAssertEqual(letters.length, 3)
        XCTAssertTrue(letters.zeroPastLength(), "the deleted key's byte is zeroed")
        XCTAssertEqual(taken(letters), "abo")
        XCTAssertEqual(letters.length, 0, "taking the entry empties it")
        XCTAssertTrue(letters.zeroPastLength(), "taking the entry zeroes it")
        letters.delete()
        XCTAssertEqual(letters.length, 0)
        for key in "zoo" { letters.type(key) }
        letters.wipe()
        XCTAssertEqual(letters.length, 0)
        XCTAssertTrue(letters.zeroPastLength(), "the wipe zeroes every byte")
        XCTAssertEqual(taken(letters), "")
    }

    /// PadsTest.kt's aHandedOverEntryIsWipedOnceTheCallReturns (Swift has no throw through handOver: its
    /// calls give a Reply, and the wipe is a defer, which runs on any way out).
    func testAHandedOverEntryIsWipedOnceTheCallReturns() {
        let letters = letterPadEntry()
        for key in "abou" { letters.type(key) }
        var handed: Secret?
        let seen = letters.handOver { secret -> String in
            handed = secret
            XCTAssertEqual(letters.length, 0, "the entry is emptied before the call")
            return String(decoding: (0..<secret.count).map { secret[$0] }, as: UTF8.self)
        }
        XCTAssertEqual(seen, "abou", "the call is handed exactly what was typed")
        XCTAssertEqual(handed?.count, 4)
        XCTAssertTrue(zeroed(handed), "the handed Secret is wiped once the call returns")
        XCTAssertTrue(letters.zeroPastLength(), "and the entry is zeroed")
    }
}
