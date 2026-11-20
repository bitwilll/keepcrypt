// KitPair's size (tasks/todo.md, M6 item U3k): asked for its ideal size (a nil width) or for an unbounded one (an
// infinite width), the pair answers a finite size, its two buttons side by side at their ideal widths. At e32fd98a
// it answered the placeholder 10 for a nil width and an infinite width for an infinite one, and on iOS 18 the app
// hung as a screen with a pair opened (every macos-15 journey). Laid out through a hosting controller, as SwiftUI
// lays out a screen.

import SwiftUI
import XCTest

final class KitPairTests: XCTestCase {
    /// A pair of two labelled boxes, each 100 points wide and 40 high at its ideal size.
    private var pair: some View {
        KitPair("Undo", "Confirm") {
            Color.clear.frame(idealWidth: 100, idealHeight: 40)
            Color.clear.frame(idealWidth: 100, idealHeight: 40)
        }
    }

    func testAnUnboundedWidthGetsTheIdealSizeSideBySide() {
        let size = UIHostingController(rootView: pair).sizeThatFits(in: CGSize(width: CGFloat.infinity, height: CGFloat.infinity))
        XCTAssertTrue(size.width.isFinite && size.height.isFinite, "an infinite proposal: \(size)")
        XCTAssertEqual(size.width, 100 + 100 + KitPair.spacing, accuracy: 0.5, "side by side at their ideal widths")
        XCTAssertEqual(size.height, 40, accuracy: 0.5)
    }

    func testTheIdealSizeIsTheTwoSideBySide() {
        let size = UIHostingController(rootView: pair.fixedSize()).sizeThatFits(in: CGSize(width: 375, height: 1_000))
        XCTAssertTrue(size.width.isFinite && size.height.isFinite, "an ideal (nil) proposal: \(size)")
        XCTAssertEqual(size.width, 100 + 100 + KitPair.spacing, accuracy: 0.5, "not the placeholder 10 for an ideal width")
    }

    func testAFiniteWidthIsTheRowsWidth() {
        let size = UIHostingController(rootView: pair).sizeThatFits(in: CGSize(width: 375, height: 1_000))
        XCTAssertEqual(size.width, 375, accuracy: 0.5)
        XCTAssertTrue(size.height.isFinite)
    }
}
