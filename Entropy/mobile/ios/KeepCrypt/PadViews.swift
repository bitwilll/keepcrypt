// The in-app pads' views (tasks/todo.md, M6 item D3; Android's Pads.kt; docs/mobile-apps.md, "Text entry"):
// buttons only, never the system keyboard. Each pad's keys come in their fixed order (Pads.swift), each
// key's press goes to the model's padKey, which types it into a PadEntry. A Public pad's key (the dice and
// the go-ahead code) carries its label as its VoiceOver label and the identifier key_ and its label; a
// Protected pad's key (the letters and the BIP39 passphrase's ASCII) carries its label and no identifier,
// as Android's sensitive keys carry no tag. Each key's press runs through the press gate (Kit.swift, M6-23).

import SwiftUI

/// The dice pad (a Public screen): a face's press goes to onKey; disabled at 256 rolls by its screen.
struct DicePad: View {
    let enabled: Bool
    let onKey: (Character) -> Void

    var body: some View {
        KeyGrid(keys: Array(diceKeys), columns: diceColumns, enabled: enabled, sensitive: false, press: onKey)
    }
}

/// The letter pad (Protected screens): a letter's press goes to onKey.
struct LetterPad: View {
    let onKey: (Character) -> Void

    var body: some View {
        KeyGrid(keys: Array(letterKeys), columns: letterColumns, enabled: true, sensitive: true, press: onKey)
    }
}

/// The go-ahead code's pad (a Public screen: the code is no secret): a symbol's press goes to onKey.
struct CrockfordPad: View {
    let onKey: (Character) -> Void

    var body: some View {
        KeyGrid(keys: Array(crockfordKeys), columns: crockfordColumns, enabled: true, sensitive: false, press: onKey)
    }
}

/// The ASCII pad (a Protected screen), page (the model's) of its keys: a character's press goes to onKey.
struct AsciiPad: View {
    let page: Int
    let onKey: (Character) -> Void

    var body: some View {
        KeyGrid(keys: Array(asciiPage(page)), columns: asciiColumns, enabled: true, sensitive: true, press: onKey)
    }
}

/// keys in rows of columns, in their order, each key an equal share of the row wide and at least keyPoints
/// high. A short last row keeps the columns of the rows above it. The key's whole cell is its touch
/// target; its frame is drawn 3 points inside the cell, so the gaps between frames are still keys.
private struct KeyGrid: View {
    let keys: [Character]
    let columns: Int
    let enabled: Bool
    let sensitive: Bool
    let press: (Character) -> Void
    @Environment(\.pressGate) private var pressGate
    /// Read so a change of the user's text size draws the keys again; their labels' 18 follows it, as Android's
    /// sp, and a key stays at least keyPoints high (lead decision M6-26).
    @Environment(\.dynamicTypeSize) private var typeSize

    var body: some View {
        let _ = typeSize
        VStack(spacing: 0) {
            ForEach(Array(stride(from: 0, to: keys.count, by: columns)), id: \.self) { start in
                HStack(spacing: 0) {
                    ForEach(start..<(start + columns), id: \.self) { index in
                        if index < keys.count {
                            key(keys[index])
                        } else {
                            Color.clear.frame(maxWidth: .infinity, minHeight: CGFloat(keyPoints))
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func key(_ key: Character) -> some View {
        let label = keyLabel(key)
        let colour = enabled ? Color.white : Color.gray
        let button = Button {
            #if KC_TEST_HOOKS
            // U2j's probe: a key's closure ran, by its uptime alone (no key, no count: a count of letters would
            // give a word's length).
            MainActor.assumeIsolated { TestHooks.shared.noteFired(nil) }
            #endif
            pressGate { press(key) }
        } label: {
            Text(label)
                .font(.system(size: KitType.scaled(18)))
                .foregroundColor(colour)
                .frame(maxWidth: .infinity, minHeight: CGFloat(keyPoints))
                .overlay(Rectangle().stroke(colour, lineWidth: 1).padding(3))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
        .accessibilityLabel(label)
        .spoken(.padKey)
        if sensitive {
            button
        } else {
            button.accessibilityIdentifier("key_" + label)
        }
    }
}
