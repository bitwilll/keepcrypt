// Wire.swift's tables and its decoder (tasks/todo.md, M6 item C3), on replies made here: no call
// reaches the slot. Each copied table is pinned against keepcrypt-ffi's wire.rs itself (the bundled
// resource), as Android's WireTablesTest pins Wire.kt's: the status bytes and the op numbers from its
// pub consts, the refusal codes from its PINNED table and the halt codes from PINNED_HALTS.

import XCTest

final class WireTests: XCTestCase {
    /// decode with layout over bytes.
    private func decoded<T>(_ bytes: [UInt8], _ layout: (inout Reader) -> T?) -> Decoded<T> {
        bytes.withUnsafeBytes { Wire.decode($0, layout) }
    }

    private func isMalformed<T>(_ decoded: Decoded<T>) -> Bool {
        if case .malformed = decoded { return true }
        return false
    }

    private func reply<T>(_ decoded: Decoded<T>) throws -> Reply<T> {
        guard case .reply(let reply) = decoded else { throw Unexpected(what: "malformed") }
        return reply
    }

    /// wire.rs's `pub const NAME: TYPE = VALUE;` lines, NAME to VALUE.
    private func consts(_ source: String, _ type: String) -> [String: Int] {
        var table: [String: Int] = [:]
        for line in source.split(separator: "\n") where line.hasPrefix("pub const ") && line.contains(": \(type) = ") {
            let words = line.dropFirst("pub const ".count).split(separator: " ")
            guard words.count == 4, let value = Int(words[3].dropLast()) else { continue }
            table[String(words[0].dropLast())] = value
        }
        return table
    }

    /// A Swift case name in wire.rs's SCREAMING_SNAKE form: selfTest is SELF_TEST.
    private func screaming(_ name: String) -> String {
        var out = ""
        for character in name {
            if character.isUppercase { out += "_" }
            out += character.uppercased()
        }
        return out
    }

    /// The (name, code) rows of wire.rs's table called table, in its order.
    private func pinned(_ source: String, _ table: String) throws -> [String] {
        let start = try XCTUnwrap(source.range(of: "const \(table): ["))
        let end = try XCTUnwrap(source.range(of: "];", range: start.upperBound..<source.endIndex))
        return source[start.upperBound..<end.lowerBound].split(separator: "\n").compactMap { line in
            let row = line.trimmingCharacters(in: .whitespaces)
            guard row.hasPrefix("(\"") else { return nil }
            return row.replacingOccurrences(of: "\"", with: "").replacingOccurrences(of: " ", with: "")
        }
    }

    func testTheStatusBytesAndTheOpTableAreWireRs() throws {
        let source = try Vectors.wireSource()
        XCTAssertEqual(consts(source, "u8"), ["OK": 0, "REFUSED": 1, "DISCARDED": 2, "HALTED": 3])
        XCTAssertEqual([Wire.ok, Wire.refused, Wire.discarded, Wire.halted], [0, 1, 2, 3])
        var ours: [String: Int] = [:]
        for op in Wire.Op.allCases where op != .halt {
            ours[screaming(String(describing: op))] = Int(op.rawValue)
        }
        XCTAssertEqual(ours, consts(source, "u32"))
        XCTAssertEqual(ours.count, 38)
        XCTAssertEqual(Wire.Op.halt.rawValue, 0, "an op the table does not hold")
    }

    func testTheRefusalAndHaltTablesAreWireRs() throws {
        let source = try Vectors.wireSource()
        let refusals = Refusal.allCases.map { refusal -> String in
            let name = String(describing: refusal)
            let core = name.prefix(1).uppercased() + name.dropFirst()
            let full: String
            switch refusal.group {
            case .code: full = "Code(\(core))"
            case .core: full = "Core(\(core))"
            case .snapshot: full = "Core(Snapshot(\(core)))"
            case .ur: full = "Core(Snapshot(Ur(\(core))))"
            case .backup: full = "Core(Backup(\(core)))"
            }
            return "(\(full),\(refusal.rawValue)),"
        }
        XCTAssertEqual(refusals, try pinned(source, "PINNED"))
        XCTAssertEqual(refusals.count, 42)
        let halts = HaltReason.allCases.map { reason -> String in
            let name = String(describing: reason)
            return "(\(name.prefix(1).uppercased() + name.dropFirst()),\(reason.rawValue)),"
        }
        XCTAssertEqual(halts, try pinned(source, "PINNED_HALTS"))
    }

    func testEveryRefusalAndHaltStatusDecodes() throws {
        for code in 0...255 {
            let refused = decoded([Wire.refused, UInt8(code)]) { $0.nothing() }
            if let expected = Refusal(rawValue: UInt8(code)) {
                XCTAssertEqual(refusal(try reply(refused)), expected, "refusal \(code)")
            } else {
                XCTAssertTrue(isMalformed(refused), "no refusal \(code)")
            }
            let halted = try reply(decoded([Wire.halted, UInt8(code)]) { $0.nothing() })
            XCTAssertEqual(haltReason(halted), HaltReason(rawValue: UInt8(code)) ?? .internal, "halt \(code)")
        }
        XCTAssertNotNil(try reply(decoded([Wire.discarded]) { $0.nothing() }))
        guard case .discarded = try reply(decoded([Wire.discarded]) { $0.nothing() }) else {
            throw Unexpected(what: "a discard")
        }
    }

    func testAReplyThatIsNotItsLayoutIsMalformed() {
        let malformed: [[UInt8]] = [
            [],
            [4],
            [Wire.ok, 0],
            [Wire.refused],
            [Wire.refused, 1, 0],
            [Wire.discarded, 0],
            [Wire.halted],
            [Wire.halted, 1, 0],
        ]
        for bytes in malformed {
            XCTAssertTrue(isMalformed(decoded(bytes) { $0.nothing() }), "\(bytes)")
        }
        // A word page cut short, a flag that is neither 0 nor 1, a Seal ID off the alphabet, a QR side
        // that is no version's, a dice progress with a byte left over.
        XCTAssertTrue(isMalformed(decoded([Wire.ok, 1, 12, 1, 1, 1, 0x07, 0x74, 3, 0x61]) { $0.wordPage() }))
        XCTAssertTrue(isMalformed(decoded([Wire.ok, 2]) { $0.flag() }))
        let card: [UInt8] = [Wire.ok] + [UInt8](repeating: 0, count: 8) + [0] + Array("YVM9CPPU".utf8) + [0]
        XCTAssertTrue(isMalformed(decoded(card) { $0.sealCard() }))
        XCTAssertTrue(isMalformed(decoded([Wire.ok, 22] + [UInt8](repeating: 0, count: 61)) { $0.qrMatrix() }))
        XCTAssertTrue(isMalformed(decoded([Wire.ok, 0, 50, 0, 50, 0, 2, 0x4F, 0x52, 9]) { $0.diceProgress() }))
    }

    func testTheLayoutsReadWireRsFields() throws {
        let progress = try done(try reply(decoded([Wire.ok, 0, 50, 0, 50, 0, 1, 0xF8, 0xE2]) { $0.diceProgress() }), "dice")
        XCTAssertEqual([progress.rolls, progress.minimum], [50, 50])
        XCTAssertEqual(progress.millibits, 129_250)
        let card: [UInt8] = [Wire.ok, 0x80, 0, 0, 0, 0, 0, 0, 1, 7] + Array("YVM9CPP3".utf8) + [3, 0xE2, 0xA0, 0x81]
        let seal = try done(try reply(decoded(card) { $0.sealCard() }), "seal")
        XCTAssertEqual(seal.sealId, "YVM9CPP3")
        XCTAssertEqual(seal.colourIndex, 7)
        XCTAssertTrue(seal.isFilled(row: 0, column: 0))
        XCTAssertTrue(seal.isFilled(row: 7, column: 7))
        XCTAssertFalse(seal.isFilled(row: 0, column: 1))
        let header: [UInt8] = [Wire.ok, 1, 1] + [0, 0, 0, 0, 0, 0, 0, 9] + [0x01, 0x35, 0x30, 0x3D] + [0, 0, 0, 2] + [1]
        guard case .collision(let registry) = try done(try reply(decoded(header) { $0.revealed() }), "revealed") else {
            throw Unexpected(what: "a collision")
        }
        XCTAssertEqual(registry?.number, 9)
        XCTAssertEqual(registry?.date, 20_262_973)
        XCTAssertEqual(registry?.count, 2)
        XCTAssertEqual(registry?.freshness, .stale)
    }

    func testTheStartUpScreenFailsClosed() {
        XCTAssertEqual(StartScreen(selfTest: .done(())), .passed)
        for reason in HaltReason.allCases {
            XCTAssertEqual(StartScreen(selfTest: .halted(reason)), .stopped(reason))
        }
        XCTAssertEqual(StartScreen(selfTest: .refused(.wrongCode)), .stopped(.internal))
        XCTAssertEqual(StartScreen(selfTest: .discarded), .stopped(.internal))
    }
}
