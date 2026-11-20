// The kit's type scale and its button pair (tasks/todo.md, M6 items U2b and U3: Q97, U3i, U3k), apart from
// Kit.swift so the unit tests can lay a pair out (KeepCryptTests' KitPairTests): Kit.swift's components draw
// with them.

import SwiftUI
import UIKit

/// The kit's type scale, largest first (Android's KitType, its sp sizes as points), each scaled by the user's
/// text size (Dynamic Type) as Android's sp follow the system font scale, at most twice (Q78's full range on
/// Android reaches 2.0; U2: the sizes were fixed points before, so iOS's text size changed nothing).
enum KitType {
    /// The app's name on its first screens.
    static var title: Font { Font.system(size: scaled(32), weight: .bold) }
    /// A screen's heading.
    static var heading: Font { Font.system(size: scaled(26), weight: .bold) }
    /// Running text.
    static var body: Font { Font.system(size: scaled(18)) }
    /// Notes under the running text.
    static var small: Font { Font.system(size: scaled(16)) }
    /// A button's label.
    static var button: Font { Font.system(size: scaled(buttonPoints), weight: .bold) }
    /// A button label's size before scaling, and its face as UIKit measures it (KitPair).
    static let buttonPoints: CGFloat = 20
    static var buttonFont: UIFont { UIFont.systemFont(ofSize: scaled(buttonPoints), weight: .bold) }
    /// Hex groups (C), in a monospace face so the columns line up.
    static var hex: Font { Font.system(size: scaled(22), design: .monospaced) }
    /// A value read at a glance (the dice pick).
    static var large: Font { Font.system(size: scaled(48), weight: .bold) }

    /// The largest scale the kit's text takes: Android's 2.0 (Q78).
    static let maxScale: CGFloat = 2

    /// The smallest share of its size a whole-line text shrinks to rather than break a line (Q97): one half, so at
    /// the largest scale (2x) it is never drawn smaller than at the default size, and at the default size the
    /// longest seed word, the code and C's rows fit a 375 pt iPhone whole without shrinking.
    static let fitScale: CGFloat = 0.5

    /// points at the user's text size (UIFontMetrics' body scaling for the app's content size category, the
    /// one Settings or a launch's -UIPreferredContentSizeCategoryName sets), at most maxScale times.
    static func scaled(_ points: CGFloat) -> CGFloat {
        let traits = UITraitCollection(preferredContentSizeCategory: UIApplication.shared.preferredContentSizeCategory)
        return min(UIFontMetrics.default.scaledValue(for: points, compatibleWith: traits), points * maxScale)
    }
}

/// Two buttons sharing a row (Q97; U3i): side by side, each half the row, a label wrapping between its words as
/// any text does, unless one word of either label is wider than a half's text width, which would break it inside
/// the word; then one per row, each the row's width. U3h stacked whenever a whole label did not fit its half on one
/// line, so at the default size the check QR's four answers stood one per row and the check QR lost its full view
/// (Android's CheckTest, run 44398792258). Android's KitPair (Kit.kt) asks its labels' min intrinsic width, their
/// widest word; here the words are measured in the button's face (KitType.buttonFont).
struct KitPair: Layout {
    /// The space between the two, side by side (the rows' 12 before Q97).
    static let spacing: CGFloat = 12
    /// What a KitButton adds around its label's text: its padding, 16 a side.
    static let labelInset: CGFloat = 32

    /// The two buttons' labels, whose widest word decides.
    let labels: [String]

    init(_ first: String, _ second: String) {
        labels = [first, second]
    }

    /// The widest word of either label, at the user's text size, rounded up.
    private var widestWord: CGFloat {
        let font = KitType.buttonFont
        let words = labels.flatMap { $0.split(separator: " ") }
        return ceil(words.map { (String($0) as NSString).size(withAttributes: [.font: font]).width }.max() ?? 0)
    }

    private func sideBySide(_ width: CGFloat) -> Bool {
        widestWord + KitPair.labelInset <= (width - KitPair.spacing) / 2
    }

    /// The pair's size for proposal. U3k: an ideal or unbounded width (nil or infinite) answers the ideal size, the
    /// two side by side at their own ideal widths and the spacing; never an infinite or placeholder width, which
    /// on iOS 18 hung the app as a screen with a pair opened (run at e32fd98a, every macos-15 journey).
    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        guard let width = proposal.width, width.isFinite else {
            let ideals = subviews.map { $0.sizeThatFits(.unspecified) }
            return CGSize(
                width: ideals.map(\.width).reduce(0, +) + KitPair.spacing * CGFloat(max(ideals.count - 1, 0)),
                height: ideals.map(\.height).max() ?? 0)
        }
        if sideBySide(width) {
            let half = (width - KitPair.spacing) / 2
            let height = subviews.map { $0.sizeThatFits(ProposedViewSize(width: half, height: nil)).height }.max() ?? 0
            return CGSize(width: width, height: height)
        }
        let height = subviews.map { $0.sizeThatFits(ProposedViewSize(width: width, height: nil)).height }.reduce(0, +)
        return CGSize(width: width, height: height)
    }

    /// Placed in bounds by the same rule as sizeThatFits, on the width the pair was given (finite); stacked, the
    /// two rows touch, as the actions' column puts its buttons (each KitButton pads itself 6 above and below).
    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        if sideBySide(bounds.width) {
            let half = (bounds.width - KitPair.spacing) / 2
            for (index, subview) in subviews.enumerated() {
                let x = bounds.minX + CGFloat(index) * (half + KitPair.spacing)
                subview.place(at: CGPoint(x: x, y: bounds.minY), proposal: ProposedViewSize(width: half, height: bounds.height))
            }
            return
        }
        var y = bounds.minY
        for subview in subviews {
            let height = subview.sizeThatFits(ProposedViewSize(width: bounds.width, height: nil)).height
            subview.place(at: CGPoint(x: bounds.minX, y: y), proposal: ProposedViewSize(width: bounds.width, height: height))
            y += height
        }
    }
}
