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
        .spoken(.qrCode)
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

/// One face of an insert (docs/seal-watchonly-braille.md, "Braille backup"; Android's BrailleFace): its
/// letter, its six dots with their numbers (1-3 left, 4-5-6 right), and under them "leave blank" or
/// "mirror"; face 5 lighter. The dots are core's (WordPage's faces), never a table of the app's.
struct BrailleFaceView: View {
    let face: Face

    /// The lighter colour of face 5 (the Pi's lighter dots).
    private static let lighter = Color(red: 0x9E / 255, green: 0x9E / 255, blue: 0x9E / 255)

    /// Read so a change of the user's text size draws the face again: its letter's 24 and its label's 14 follow it,
    /// as Android's sp (lead decision M6-26); the dot numbers do not, sized from the cell as the dots are, as
    /// Android's DotNumbers (Drawing.kt: at 1.15 numbers that grew clipped dots 4-6).
    @Environment(\.dynamicTypeSize) private var typeSize

    var body: some View {
        let _ = typeSize
        let colour = face.isLighter ? BrailleFaceView.lighter : Color.white
        VStack(spacing: 2) {
            Text(face.isBlank ? " " : String(UnicodeScalar(face.letter)))
                .font(.system(size: KitType.scaled(24), weight: .bold))
                .foregroundColor(colour)
            HStack(spacing: 2) {
                numbers(1, colour)
                Canvas { context, size in
                    let radius = min(size.width / 2, size.height / 3) * 0.35
                    for dot in 1...6 {
                        let centre = dotCentre(dot, Double(size.width), Double(size.height))
                        let circle = Path(ellipseIn: CGRect(
                            x: CGFloat(centre.x) - radius, y: CGFloat(centre.y) - radius, width: 2 * radius, height: 2 * radius))
                        if isRaised(Int(face.dots), dot) {
                            context.fill(circle, with: .color(colour))
                        } else {
                            context.stroke(circle, with: .color(colour), lineWidth: max(1, radius / 3))
                        }
                    }
                }
                .frame(width: 40, height: 60)
                numbers(4, colour)
            }
            Text(faceLabel(blank: face.isBlank, mirror: face.mirrorPartner != 0))
                .font(.system(size: KitType.scaled(14)))
                .foregroundColor(colour)
                .multilineTextAlignment(.center)
        }
        .padding(4)
        .frame(maxWidth: .infinity)
        .background(Color.black)
    }

    /// The numbers of the three dots of a column, first to first + 2, beside it.
    private func numbers(_ first: Int, _ colour: Color) -> some View {
        VStack(spacing: 0) {
            ForEach(first..<(first + 3), id: \.self) { dot in
                Text(String(dot))
                    .font(.system(size: 12))
                    .foregroundColor(colour)
                    .frame(height: 20)
            }
        }
    }
}
