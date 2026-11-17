// The drawing views (tasks/todo.md, M6 item D4; Android's Drawing.kt): a QR code from core's QrMatrix, the
// seal card (docs/seal-watchonly-braille.md, "The seal image") and a row of braille cells, each drawing what
// DrawingMath.swift computes.

import SwiftUI

/// A colour from its RGB value.
func kitColour(_ rgb: UInt32) -> Color {
    Color(red: Double(rgb >> 16 & 0xFF) / 255, green: Double(rgb >> 8 & 0xFF) / 255, blue: Double(rgb & 0xFF) / 255)
}

/// A QR code, dark modules on a light square of side points, from the matrix core drew (its screen wipes
/// it): an image named by its kind (QrKind), never by what it holds.
struct QrCodeView: View {
    let matrix: QrMatrix
    let kind: QrKind
    var side = qrSide

    var body: some View {
        Canvas { context, size in
            let layout = QrLayout(side: matrix.side, size: Int(size.width))
            context.fill(Path(CGRect(origin: .zero, size: size)), with: .color(.white))
            let module = CGFloat(layout.module)
            for y in 0..<matrix.side {
                for x in 0..<matrix.side where matrix.isDark(x: x, y: y) {
                    let cell = CGRect(x: CGFloat(layout.edge(x)), y: CGFloat(layout.edge(y)), width: module, height: module)
                    context.fill(Path(cell), with: .color(.black))
                }
            }
        }
        .frame(width: CGFloat(side), height: CGFloat(side))
        .accessibilityElement()
        .accessibilityLabel(kind.spoken)
        .accessibilityAddTraits(.isImage)
    }
}

/// The seal card: the 8 x 8 grid at 240 points, the Seal ID in large type beneath, and its braille.
struct SealCardImage: View {
    let card: SealCard

    var body: some View {
        VStack(spacing: 0) {
            Canvas { context, size in
                let cell = size.width / 8
                for row in 0..<8 {
                    for column in 0..<8 {
                        let square = Path(CGRect(x: CGFloat(column) * cell, y: CGFloat(row) * cell, width: cell, height: cell))
                        context.fill(square, with: .color(kitColour(sealCellColour(card.isFilled(row: row, column: column), card.colourIndex))))
                        context.stroke(square, with: .color(kitColour(sealOutline)), lineWidth: 1)
                    }
                }
            }
            .frame(width: CGFloat(sealSide), height: CGFloat(sealSide))
            Spacer().frame(height: 12)
            Text(card.sealId)
                .font(.system(size: 36, weight: .bold, design: .monospaced))
                .foregroundColor(.white)
                .accessibilityIdentifier("seal_id")
            Spacer().frame(height: 8)
            BrailleCellsView(cells: brailleCells(card.sealIdBraille), cellWidth: 18)
        }
    }
}

/// A row of braille cells (a caption such as the Seal ID's), each cellWidth wide and half as tall again:
/// raised dots filled, flat ones as rings, so every position shows.
struct BrailleCellsView: View {
    let cells: [Int]
    let cellWidth: CGFloat

    var body: some View {
        Canvas { context, size in
            guard !cells.isEmpty else { return }
            let width = size.width / CGFloat(cells.count)
            let radius = min(width / 2, size.height / 3) * 0.35
            for (index, dots) in cells.enumerated() {
                for dot in 1...6 {
                    let centre = dotCentre(dot, Double(width), Double(size.height))
                    let circle = Path(ellipseIn: CGRect(
                        x: CGFloat(index) * width + CGFloat(centre.x) - radius, y: CGFloat(centre.y) - radius,
                        width: 2 * radius, height: 2 * radius))
                    if isRaised(dots, dot) {
                        context.fill(circle, with: .color(.white))
                    } else {
                        context.stroke(circle, with: .color(.white), lineWidth: max(1, radius / 3))
                    }
                }
            }
        }
        .frame(width: cellWidth * CGFloat(cells.count), height: cellWidth * 1.5)
        .accessibilityHidden(true)
    }
}
