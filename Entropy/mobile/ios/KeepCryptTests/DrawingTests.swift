// The drawing arithmetic (tasks/todo.md, M6 item D4), ported from :screens' DrawingTest.kt: a QR code fills its
// square in whole modules inside its quiet zone, the seal card's Okabe-Ito palette on a light tile, braille
// cells as their code points' dots, and the six dots in two columns of three. DrawingTest.kt's refusals (a
// square too small, an eight-dot or non-braille cell) end the app here (Ceremony.halt, the bridge's bug), so
// no test can run them in this process. No slot is used.

import XCTest

final class DrawingTests: XCTestCase {
    /// DrawingTest.kt's aQrCodeFillsItsSquareInWholeModulesInsideItsQuietZone.
    func testAQrCodeFillsItsSquareInWholeModulesInsideItsQuietZone() {
        let small = QrLayout(side: 21, size: 240)
        XCTAssertEqual(small.module, 8)
        XCTAssertEqual(small.offset, (240 - 8 * 21) / 2)
        XCTAssertEqual(small.edge(0), small.offset)
        XCTAssertEqual(small.edge(20), small.offset + 20 * 8)
        XCTAssertGreaterThanOrEqual(small.offset, QrLayout.quiet * small.module, "the quiet zone is kept")
        let large = QrLayout(side: 61, size: 720)
        XCTAssertEqual(large.module, 10)
        XCTAssertLessThanOrEqual(large.edge(60) + large.module + QrLayout.quiet * large.module, 720)
        XCTAssertEqual(QrLayout(side: 61, size: qrSide).module, 3, "the largest matrix core draws at the phone's 240 points")
    }

    /// DrawingTest.kt's theSealCardUsesTheOkabeItoPaletteOnALightTile.
    func testTheSealCardUsesTheOkabeItoPaletteOnALightTile() {
        XCTAssertEqual(okabeIto, [0x000000, 0xE69F00, 0x56B4E9, 0x009E73, 0xF0E442, 0x0072B2, 0xD55E00, 0xCC79A7])
        XCTAssertEqual(sealCellColour(true, 3), 0x009E73)
        XCTAssertEqual(sealCellColour(false, 3), sealTile)
        XCTAssertEqual(sealTile, 0xF7F7F7)
        XCTAssertEqual(sealOutline, 0x333333)
        XCTAssertEqual(sealSide, 240)
        for index in 0..<8 {
            XCTAssertEqual(sealCellColour(true, index), okabeIto[index])
        }
    }

    /// DrawingTest.kt's brailleCellsAreTheirCodePointsDots.
    func testBrailleCellsAreTheirCodePointsDots() {
        XCTAssertEqual(brailleCells("\u{2800}\u{2801}\u{2803}\u{283F}"), [0, 1, 3, 0x3F])
        XCTAssertEqual(brailleCells(""), [])
        XCTAssertTrue(isRaised(1, 1))
        XCTAssertTrue((2...6).allSatisfy { !isRaised(1, $0) })
        XCTAssertEqual((1...6).filter { isRaised(0b011001, $0) }, [1, 4, 5])
        XCTAssertEqual((1...6).filter { isRaised(sixDots, $0) }, [1, 2, 3, 4, 5, 6])
    }

    /// DrawingTest.kt's theSixDotsSitInTwoColumnsOfThree.
    func testTheSixDotsSitInTwoColumnsOfThree() {
        XCTAssertEqual(dotCentre(1, 40, 60).x, 10)
        XCTAssertEqual(dotCentre(1, 40, 60).y, 10)
        XCTAssertEqual(dotCentre(3, 40, 60).x, 10)
        XCTAssertEqual(dotCentre(3, 40, 60).y, 50)
        XCTAssertEqual(dotCentre(4, 40, 60).x, 30)
        XCTAssertEqual(dotCentre(4, 40, 60).y, 10)
        XCTAssertEqual(dotCentre(6, 40, 60).x, 30)
        XCTAssertEqual(dotCentre(6, 40, 60).y, 50)
        XCTAssertEqual(dotCentre(2, 40, 60).y, 30)
    }

    /// Each kind of QR code is named by its kind alone (ScreenTitlesTest.kt's eachKindOfQrCodeIsNamedByItsKindAlone).
    func testEachKindOfQrCodeIsNamedByItsKindAlone() {
        let names = QrKind.allCases.map(\.spoken)
        XCTAssertEqual(Set(names).count, names.count, "each kind has a name of its own")
        XCTAssertTrue(names.allSatisfy { $0.contains("QR code") })
    }
}
