// The collision check's laid-out lines (tasks/todo.md, M6 item D4), as :screens' CheckScreensTest.kt,
// ScanScreensTest.kt and HomeScreensTest.kt pin Android's: the snapshot and proof lines, the clear result,
// the code as the checker groups it, the scan screen's line for every state, the freshness warnings, and
// core's text for every snapshot refusal. No slot is used.

import XCTest

final class CheckLinesTests: XCTestCase {
    func testTheRegistryLinesAndTheResult() {
        let header = RegistryHeader(number: 4, date: 20_260_301, count: 7, freshness: .current)
        XCTAssertEqual(snapshotLine(header), "Snapshot No. 4, dated 2026-03-01, 7 entries.")
        XCTAssertEqual(proofLine(RegistryHeader(number: 2, date: 20_260_301, count: 0, freshness: .current)),
                       "Proof from snapshot No. 2, dated 2026-03-01: 0 entries in this seal's bucket.")
        XCTAssertEqual(proofLine(RegistryHeader(number: 4, date: 20_260_301, count: 1, freshness: .current)),
                       "Proof from snapshot No. 4, dated 2026-03-01: 1 entry in this seal's bucket.")
        XCTAssertEqual(clearText("YVM9CPP3", header), "No collision for seal YVM9CPP3 as of 2026-03-01.")
        XCTAssertEqual(clearText("YVM9CPP3", nil), "No collision for seal YVM9CPP3, as of the date your checker showed.")
        XCTAssertNil(freshnessWarning(.current))
        XCTAssertEqual(freshnessWarning(.stale), CheckTexts.stale)
        XCTAssertEqual(freshnessWarning(.future), CheckTexts.future)
    }

    /// CheckScreensTest.kt's code grouping: kcr.json's dice-50-words12 go-ahead as the checker groups it.
    func testTheCodeIsShownInTheCheckersTwoGroups() {
        let code = crockfordPadEntry()
        XCTAssertEqual(codeShown(code), "____-____")
        for key in "PBJN" { code.type(key) }
        XCTAssertEqual(codeShown(code), "PBJN-____")
        for key in "YZY5" { code.type(key) }
        XCTAssertEqual(codeShown(code), "PBJN-YZY5")
    }

    /// ScanScreensTest.kt's scan lines.
    func testTheScanLineForEveryState() {
        func line(_ fill: (inout UiState) -> Void) -> String {
            var state = UiState(screen: .scan)
            fill(&state)
            return scanLine(state)
        }
        XCTAssertEqual(line { _ in }, CheckTexts.scanning)
        XCTAssertEqual(line { $0.scanStop = .refused }, CheckTexts.scanRefused)
        XCTAssertEqual(line { $0.scanStop = .missing }, CheckTexts.scanMissing)
        XCTAssertEqual(line { $0.scanStop = .failed }, CheckTexts.scanFailed)
        XCTAssertEqual(line { $0.scanRefusal = .noRegistryKey }, CheckTexts.scanNoRegistryKey)
        XCTAssertEqual(line { $0.scanRefusal = .wrongBucket }, CheckTexts.scanNotAccepted)
        XCTAssertEqual(line { $0.scanStop = .missing; $0.scanRefusal = .notUr }, CheckTexts.scanNotAccepted)
    }

    /// HomeScreensTest.kt's snapshot refusals: core's text for each a load gives, none for any other.
    func testEverySnapshotRefusalHasCoresText() {
        XCTAssertEqual(snapshotRefusalText(.badSignature), "registry snapshot or proof rejected: bad signature")
        XCTAssertEqual(snapshotRefusalText(.noRegistryKey), CheckTexts.snapshotNoRegistryKey)
        for refusal in Refusal.allCases {
            XCTAssertEqual(snapshotRefusalText(refusal) != nil, isSnapshotRefusal(refusal), "refusal \(refusal.rawValue)")
        }
    }
}
