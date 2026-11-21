// The shared screen table (tasks/todo.md, M6 item D1; Q86): mobile/screens.json, copied into this test
// bundle as a resource, lists every screen of both phone apps in :screens' Screen enum's order, with its
// id, its Kotlin constant's name, its title and its kind. :screens' ScreenTableTest holds Screen.kt to the
// file line for line; this test holds Screen.swift to it, so the two apps cannot drift: the same screens
// in the same order, each with the same id, a case named as the Kotlin constant (lower camel case), the
// same title and the same kind.

import XCTest

final class ScreenTableTests: XCTestCase {
    /// A Kotlin constant's name as a Swift case's: FirstLaunch is firstLaunch.
    private func lowerCamel(_ name: String) -> String {
        guard let first = name.first else { return name }
        return first.lowercased() + name.dropFirst()
    }

    func testScreenSwiftIsTheSharedTable() throws {
        let table = try XCTUnwrap(JSONSerialization.jsonObject(with: Vectors.resource("screens", "json")) as? [String: Any])
        XCTAssertEqual(Set(table.keys), ["about", "screens"], "the table's keys")
        let rows = try XCTUnwrap(table["screens"] as? [[String: String]], "the table's screens")
        XCTAssertEqual(rows.count, Screen.allCases.count, "as many screens as Screen.swift's")
        XCTAssertEqual(rows.count, 49, "the 49 screens of Screen.kt")
        for (index, (row, screen)) in zip(rows, Screen.allCases).enumerated() {
            let at = "screen \(index + 1)"
            XCTAssertEqual(Set(row.keys), ["id", "name", "title", "kind"], at)
            XCTAssertEqual(row["id"], screen.id, "\(at): the id")
            XCTAssertEqual(row["name"].map(lowerCamel), String(describing: screen), "\(at): the case's name")
            XCTAssertEqual(row["title"], screen.title, "\(at): the title")
            XCTAssertEqual(row["kind"], screen.isProtected ? "Protected" : "Public", "\(at): the kind")
        }
        XCTAssertEqual(Set(Screen.allCases.map(\.title)).count, Screen.allCases.count, "each screen's title its own")
        XCTAssertEqual(Screen.allCases.filter(\.isWorking), [.selfTest, .working], "the two long-call screens")
    }
}
