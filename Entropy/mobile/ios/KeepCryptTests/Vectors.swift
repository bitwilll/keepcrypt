// The test data (rule 12: vectors/ only), copied into this test bundle as resources at build time by
// the project's TestVectors group: vectors/kcr.json, vectors/braille.json and keepcrypt-ffi's wire.rs,
// whose tables WireTests pins Wire.swift's copies against. Nothing here is a secret: the gate seeds
// are public test seeds.

import Foundation
import XCTest

/// A test's step that did not give what it should; its text names public values only.
struct Unexpected: Error {
    let what: String
}

enum Vectors {
    private final class Anchor {}

    /// The bundled resource name.ext's bytes.
    static func resource(_ name: String, _ ext: String) throws -> Data {
        let bundle = Bundle(for: Anchor.self)
        let file = try XCTUnwrap(bundle.url(forResource: name, withExtension: ext), "\(name).\(ext) in the test bundle")
        return try Data(contentsOf: file)
    }

    /// Gate seed name's entry in kcr.json's seeds.
    static func seed(_ name: String) throws -> [String: Any] {
        let kcr = try XCTUnwrap(JSONSerialization.jsonObject(with: resource("kcr", "json")) as? [String: Any])
        let seeds = try XCTUnwrap(kcr["seeds"] as? [[String: Any]])
        return try XCTUnwrap(seeds.first { $0["name"] as? String == name }, "gate seed \(name)")
    }

    /// braille.json's entry for each BIP39 word, by the word.
    static func braille() throws -> [String: [String: Any]] {
        let braille = try XCTUnwrap(JSONSerialization.jsonObject(with: resource("braille", "json")) as? [String: Any])
        let words = try XCTUnwrap(braille["words"] as? [[String: Any]])
        var byWord: [String: [String: Any]] = [:]
        for entry in words {
            byWord[try XCTUnwrap(entry["word"] as? String)] = entry
        }
        return byWord
    }

    /// keepcrypt-ffi's wire.rs, as text.
    static func wireSource() throws -> String {
        try XCTUnwrap(String(data: resource("wire", "rs"), encoding: .utf8))
    }
}

/// The reply's value when it is done; else the step fails, naming what it gave.
func done<T>(_ reply: Reply<T>, _ step: String) throws -> T {
    switch reply {
    case .done(let value): return value
    case .refused(let refusal): throw Unexpected(what: "\(step): refused \(refusal.rawValue)")
    case .discarded: throw Unexpected(what: "\(step): discarded")
    case .halted(let reason): throw Unexpected(what: "\(step): halted \(reason.rawValue)")
    }
}

/// The refusal the reply gives, or nil when it gives none.
func refusal<T>(_ reply: Reply<T>) -> Refusal? {
    if case .refused(let refusal) = reply { return refusal }
    return nil
}

/// The halt reason the reply gives, or nil when it gives none.
func haltReason<T>(_ reply: Reply<T>) -> HaltReason? {
    if case .halted(let reason) = reply { return reason }
    return nil
}
