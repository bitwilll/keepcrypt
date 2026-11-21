// The drawing helpers' arithmetic (tasks/todo.md, M6 item D4; Android's Drawing.kt): where a QR code's
// modules go, the seal card's palette, and braille cells' dots; Drawing.swift's views draw what these
// compute, and KeepCryptTests' DrawingTests check them as DrawingTest.kt checks Android's. The QR codes'
// modules are core's (QrMatrix, as on Android): no QR generator runs in the app.

/// Where a QR code's modules go in a square of size points: side x side modules inside the standard quiet
/// zone of quiet modules on each side, each module a whole number of points, the code centred.
struct QrLayout {
    /// The quiet zone, in modules (ISO/IEC 18004).
    static let quiet = 4

    let side: Int
    /// One module's side in points.
    let module: Int
    /// Where the first module starts, from the square's top and left edges.
    let offset: Int

    /// The layout of side modules in a square of size points; a square too small for one point a module
    /// is the app's own bug, which ends it.
    init(side: Int, size: Int) {
        self.side = side
        module = size / (side + 2 * QrLayout.quiet)
        guard module > 0 else { Ceremony.halt(.bridge) }
        offset = (size - module * side) / 2
    }

    /// Module column x's left edge (or row y's top edge).
    func edge(_ index: Int) -> Int {
        offset + index * module
    }
}

/// What a QR code is, as VoiceOver names it (U3g): its kind alone, a fixed name, never its data.
enum QrKind: CaseIterable {
    case checkRequest, collisionReport, account, descriptor, registration, recheck

    var spoken: String {
        switch self {
        case .checkRequest: return "Check QR code"
        case .collisionReport: return "Collision report QR code"
        case .account: return "Account QR code for Sparrow"
        case .descriptor: return "Descriptor QR code for Bitcoin Core"
        case .registration: return "Registration QR code"
        case .recheck: return "Re-check QR code"
        }
    }
}

/// A QR code's side on the phone: the seal's 240 points.
let qrSide = 240

/// The seal's side on phones (240 points).
let sealSide = 240

/// The Okabe-Ito palette (RGB), indexed by the card's colour index, T[0] mod 8.
let okabeIto: [UInt32] = [0x000000, 0xE69F00, 0x56B4E9, 0x009E73, 0xF0E442, 0x0072B2, 0xD55E00, 0xCC79A7]

/// The light tile under the grid, whatever the theme (the Pi's #F7F7F7).
let sealTile: UInt32 = 0xF7F7F7

/// Every cell's dark outline, so light colours stay visible (the Pi's #333333).
let sealOutline: UInt32 = 0x333333

/// A cell's colour: the card's palette colour when filled, else the tile's.
func sealCellColour(_ filled: Bool, _ colourIndex: Int) -> UInt32 {
    filled ? okabeIto[colourIndex] : sealTile
}

/// The first code point of Unicode's braille block, the blank cell: a cell's glyph is it plus its dots.
let brailleBlank: UInt32 = 0x2800

/// The six dots' bits: a six-dot cell is at most this.
let sixDots = 0x3F

/// Whether dot (1-6) is raised in a cell whose dot d is bit d - 1 (core's layout).
func isRaised(_ dots: Int, _ dot: Int) -> Bool {
    (dots >> (dot - 1)) & 1 == 1
}

/// The cells of a braille text such as the card's Seal ID in braille: each character's code point minus
/// U+2800. Core gives six-dot cells alone, so anything else is the bridge's bug, which ends the app.
func brailleCells(_ text: String) -> [Int] {
    text.unicodeScalars.map { scalar in
        guard scalar.value >= brailleBlank, scalar.value - brailleBlank <= UInt32(sixDots) else { Ceremony.halt(.bridge) }
        return Int(scalar.value - brailleBlank)
    }
}

/// Dot (1-6)'s centre in a cell box of width x height: two columns, three rows, each centred in its part.
func dotCentre(_ dot: Int, _ width: Double, _ height: Double) -> (x: Double, y: Double) {
    let column = Double((dot - 1) / 3)
    let row = Double((dot - 1) % 3)
    return (width * (1 + 2 * column) / 4, height * (1 + 2 * row) / 6)
}

/// A face's label under its dots: a blank face says to leave it blank, a mirror letter to read it twice.
func faceLabel(blank: Bool, mirror: Bool) -> String {
    if blank { return "leave blank" }
    if mirror { return "mirror" }
    return ""
}
