// The UI kit (tasks/todo.md, M6 item D3), Android's Kit.kt in SwiftUI: the colours, the type scale and the
// components every screen draws with, so the two apps look and read alike. White on black, as the Pi's
// panel; large type; every control a framed button whose text is its VoiceOver label; every screen one
// column with its screen id as its accessibility identifier, its text scrolling above its actions (or with
// them, when they are tall: KitScreen), under the TEST REGISTRY strip in that build (Q60). Text is never
// selectable. Plain SwiftUI: no third-party package, no theme library.

import SwiftUI
import UIKit

/// The kit's colours (Android's KitColors).
enum KitColors {
    /// Every screen's background: black, as the Pi's panel.
    static let background = Color.black
    /// Text and the frames of enabled buttons.
    static let text = Color.white
    /// Disabled buttons and lighter text.
    static let muted = Color(red: 0x9E / 255, green: 0x9E / 255, blue: 0x9E / 255)
    /// Warnings and notices: the first screen's development-build yellow.
    static let warning = Color(red: 0xFF / 255, green: 0xD5 / 255, blue: 0x4F / 255)
    /// The stop screen's red.
    static let stop = Color(red: 0xB0 / 255, green: 0x00 / 255, blue: 0x20 / 255)
}

/// The kit's type scale, largest first (Android's KitType, its sp sizes as points).
enum KitType {
    /// The app's name on its first screens.
    static let title = Font.system(size: 32, weight: .bold)
    /// A screen's heading.
    static let heading = Font.system(size: 26, weight: .bold)
    /// Running text.
    static let body = Font.system(size: 18)
    /// Notes under the running text.
    static let small = Font.system(size: 16)
    /// A button's label.
    static let button = Font.system(size: 20, weight: .bold)
    /// Hex groups (C), in a monospace face so the columns line up.
    static let hex = Font.system(size: 22, design: .monospaced)
    /// A value read at a glance (the dice pick).
    static let large = Font.system(size: 48, weight: .bold)
}

/// A text's look: its face and colour (Android's TextStyle).
struct KitStyle {
    let font: Font
    let color: Color

    static let body = KitStyle(font: KitType.body, color: KitColors.text)
    static let small = KitStyle(font: KitType.small, color: KitColors.muted)
    static let warning = KitStyle(font: KitType.body, color: KitColors.warning)
    static let hex = KitStyle(font: KitType.hex, color: KitColors.text)
    static let large = KitStyle(font: KitType.large, color: KitColors.text)
}

/// The content's frame in its scroll view's space, and the scroll view's height: whether it can scroll
/// further ("More below").
private struct ContentBottom: PreferenceKey {
    static let defaultValue: CGFloat = 0

    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = nextValue()
    }
}

/// A view's height, measured where it is laid out.
private struct MeasuredHeight: PreferenceKey {
    static let defaultValue: CGFloat = 0

    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = max(value, nextValue())
    }
}

/// A screen (Android's KitScreen): one column filling the window, its id as its accessibility identifier;
/// the TEST REGISTRY strip on top in that build; then content, which scrolls, inside the kit's margins; and
/// the screen's actions under the column, where they never scroll away, or, while they are taller than
/// actionsShare of the screen (actionsScroll), in the column after the content, scrolling with it (Q78,
/// Q85; M5-84 (a)). While the column can scroll further, a "More below" line stands under it.
struct KitScreen<Content: View, Actions: View>: View {
    let id: String
    let testRegistry: Bool
    var background: Color = KitColors.background
    let hasActions: Bool
    let content: Content
    let actions: Actions

    @State private var screenHeight: CGFloat = 0
    @State private var actionsHeight: CGFloat = 0
    @State private var viewportHeight: CGFloat = 0
    @State private var contentBottom: CGFloat = 0

    init(_ id: String, testRegistry: Bool, background: Color = KitColors.background,
         @ViewBuilder content: () -> Content, @ViewBuilder actions: () -> Actions) {
        self.id = id
        self.testRegistry = testRegistry
        self.background = background
        hasActions = true
        self.content = content()
        self.actions = actions()
    }

    private var scrolling: Bool {
        hasActions && actionsScroll(Double(actionsHeight), Double(screenHeight))
    }

    private var placed: some View {
        VStack(alignment: .leading, spacing: 0) { actions }
            .padding(.vertical, 8)
            .background(GeometryReader { Color.clear.preference(key: MeasuredHeight.self, value: $0.size.height) })
            .onPreferenceChange(MeasuredHeight.self) { actionsHeight = $0 }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if testRegistry {
                TestRegistryStrip()
            }
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    content
                    if scrolling { placed }
                }
                .padding(.horizontal, 24)
                .padding(.vertical, 16)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(GeometryReader { Color.clear.preference(key: ContentBottom.self, value: $0.frame(in: .named(id)).maxY) })
            }
            .coordinateSpace(name: id)
            .background(GeometryReader { geometry in
                Color.clear
                    .onAppear { viewportHeight = geometry.size.height }
                    .onChange(of: geometry.size.height) { _, height in viewportHeight = height }
            })
            .onPreferenceChange(ContentBottom.self) { contentBottom = $0 }
            if contentBottom > viewportHeight + 1 {
                KitText(ShellTexts.moreBelow, style: KitStyle(font: KitType.small, color: KitColors.text), id: "more_below")
                    .padding(.horizontal, 24)
            }
            if hasActions, !scrolling {
                placed.padding(.horizontal, 24)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background(background)
        .background(GeometryReader { geometry in
            Color.clear
                .onAppear { screenHeight = geometry.size.height }
                .onChange(of: geometry.size.height) { _, height in screenHeight = height }
        })
        .textSelection(.disabled)
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier(id)
    }
}

extension KitScreen where Actions == EmptyView {
    /// A screen with no actions.
    init(_ id: String, testRegistry: Bool, background: Color = KitColors.background, @ViewBuilder content: () -> Content) {
        self.id = id
        self.testRegistry = testRegistry
        self.background = background
        hasActions = false
        self.content = content()
        actions = EmptyView()
    }
}

/// A screen's heading, marked as one for VoiceOver's heading navigation.
struct Heading: View {
    let text: String

    init(_ text: String) {
        self.text = text
    }

    var body: some View {
        Text(text)
            .font(KitType.heading)
            .foregroundColor(KitColors.text)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.vertical, 6)
            .spoken(.heading)
        Gap(16)
    }
}

/// The app's name in title type on its first screens and the stop screen, marked as a heading too.
struct Title: View {
    let text: String

    init(_ text: String) {
        self.text = text
    }

    var body: some View {
        Text(text)
            .font(KitType.title)
            .foregroundColor(KitColors.text)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.vertical, 6)
            .spoken(.title)
    }
}

/// Running text (body), or a note (small). A line whose id is a live line's (VoiceOver.swift's liveLineIds:
/// one that appears or changes while its screen stays, the dice's counts, a refusal, the scan's state) is
/// spoken politely as it does (Android's polite live region; spoken(.liveLine)); only fixed or public text is
/// ever such a line, never a secret.
struct KitText: View {
    let text: String
    var style = KitStyle.body
    var id: String?

    init(_ text: String, style: KitStyle = .body, id: String? = nil) {
        self.text = text
        self.style = style
        self.id = id
    }

    private var live: Bool { id.map(liveLineIds.contains) ?? false }

    var body: some View {
        let line = Text(text)
            .font(style.font)
            .foregroundColor(style.color)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.vertical, 6)
            .modifier(LiveLine(text: text, live: live))
        if let id {
            line.accessibilityIdentifier(id)
        } else {
            line
        }
    }
}

/// Space between a screen's parts, size points high.
struct Gap: View {
    let size: CGFloat

    init(_ size: CGFloat) {
        self.size = size
    }

    var body: some View {
        Spacer().frame(height: size)
    }
}

/// A button (Android's KitButton): framed, full width (two sharing a row share it), its text the
/// VoiceOver label, with the button trait. A disabled one is grey, takes no tap, and VoiceOver says so.
struct KitButton: View {
    let text: String
    let id: String
    var enabled = true
    let action: () -> Void

    init(_ text: String, id: String, enabled: Bool = true, action: @escaping () -> Void) {
        self.text = text
        self.id = id
        self.enabled = enabled
        self.action = action
    }

    var body: some View {
        let colour = enabled ? KitColors.text : KitColors.muted
        Button(action: action) {
            Text(text)
                .font(KitType.button)
                .foregroundColor(colour)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(16)
                .contentShape(Rectangle())
                .overlay(Rectangle().stroke(colour, lineWidth: 2))
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
        .padding(.vertical, 6)
        .accessibilityIdentifier(id)
    }
}

/// The notice line above a screen: why the last session was wiped, black on the warning yellow.
struct NoticeBar: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.system(size: 16))
            .foregroundColor(.black)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 24)
            .padding(.vertical, 8)
            .background(KitColors.warning)
            .modifier(LiveLine(text: text, live: true, kind: .notice))
            .accessibilityIdentifier("notice")
    }
}

/// The strip on every screen and overlay of the test-registry build (Q60, lead decision M5-51).
struct TestRegistryStrip: View {
    var body: some View {
        Text(ShellTexts.testRegistry)
            .font(.system(size: 18, weight: .bold))
            .foregroundColor(.black)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 24)
            .padding(.vertical, 8)
            .background(KitColors.warning)
            .accessibilityIdentifier("test_registry_strip")
    }
}

/// The one-way-choice confirm screen (docs/pi-firmware.md, "Confirmations": Skip, Match found and Cannot
/// check each take one; Android's OneWayConfirm): the question, what cannot be undone, the one action that
/// does it, and Back, which keeps everything and returns to the screen that offered the choice.
struct OneWayConfirm: View {
    let id: String
    let testRegistry: Bool
    let question: String
    let consequence: String
    let action: String
    let onAction: () -> Void
    let onBack: () -> Void

    var body: some View {
        KitScreen(id, testRegistry: testRegistry) {
            Heading(question)
            KitText(consequence)
        } actions: {
            KitButton(action, id: "confirm_action", action: onAction)
            KitButton(CheckTexts.back, id: "back", action: onBack)
        }
    }
}

extension View {
    /// What VoiceOver is told of this kind of element (VoiceOver.swift's table): its traits. A QR code's and
    /// a key's label are set where they are drawn.
    func spoken(_ kind: Spoken) -> some View {
        let semantics = spokenSemantics(kind)
        var traits: AccessibilityTraits = []
        if semantics.header { traits.formUnion(.isHeader) }
        if semantics.image { traits.formUnion(.isImage) }
        if semantics.button { traits.formUnion(.isButton) }
        if semantics.updatesFrequently { traits.formUnion(.updatesFrequently) }
        return accessibilityAddTraits(traits)
    }
}

/// A live line (Android's polite live region): marked as one (spoken(.liveLine) or .notice), and its text
/// announced to VoiceOver when it appears and whenever it changes while its view stays, queued behind what
/// VoiceOver is saying (polite), never interrupting it. Its text is fixed or public: no secret is announced.
struct LiveLine: ViewModifier {
    let text: String
    let live: Bool
    var kind = Spoken.liveLine

    func body(content: Content) -> some View {
        if live {
            content
                .spoken(kind)
                .onAppear { announcePolitely(text) }
                .onChange(of: text) { _, now in announcePolitely(now) }
        } else {
            content
        }
    }
}

/// text announced to VoiceOver, queued behind what it is saying (UIAccessibility's queue-announcement
/// attribute), while VoiceOver runs.
func announcePolitely(_ text: String) {
    guard spokenSemantics(.liveLine).announced, UIAccessibility.isVoiceOverRunning else { return }
    let queued = NSAttributedString(string: text, attributes: [.accessibilitySpeechQueueAnnouncement: true])
    UIAccessibility.post(notification: .announcement, argument: queued)
}
