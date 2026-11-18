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

/// A text's look: its face and colour (Android's TextStyle).
struct KitStyle {
    let font: Font
    let color: Color

    static var body: KitStyle { KitStyle(font: KitType.body, color: KitColors.text) }
    static var small: KitStyle { KitStyle(font: KitType.small, color: KitColors.muted) }
    static var warning: KitStyle { KitStyle(font: KitType.body, color: KitColors.warning) }
    static var hex: KitStyle { KitStyle(font: KitType.hex, color: KitColors.text) }
    static var large: KitStyle { KitStyle(font: KitType.large, color: KitColors.text) }
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

    /// Read so a change of the user's text size draws the screen again at its new sizes (KitType).
    @Environment(\.dynamicTypeSize) private var typeSize
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
        let _ = typeSize
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
            #if KC_TEST_HOOKS
            Color.clear.frame(height: 0)
                .onChange(of: scrolling) { _, now in TestHooks.shared.noteLayout(now ? "actions scroll" : "actions fixed") }
                .onChange(of: contentBottom > viewportHeight + 1) { _, now in TestHooks.shared.noteLayout(now ? "more below shown" : "more below gone") }
            #endif
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
    /// Kept to this many whole lines, shrinking instead of wrapping (Q97: C's four rows), or wrapping freely (nil).
    var whole: Int?

    init(_ text: String, style: KitStyle = .body, id: String? = nil, whole: Int? = nil) {
        self.text = text
        self.style = style
        self.id = id
        self.whole = whole
    }

    private var live: Bool { id.map(liveLineIds.contains) ?? false }

    var body: some View {
        let line = Text(text)
            .font(style.font)
            .foregroundColor(style.color)
            .lineLimit(whole)
            .minimumScaleFactor(whole == nil ? 1 : KitType.fitScale)
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

extension View {
    /// Q97: a text kept to its own lines (lines, its hard lines), shrunk down to KitType.fitScale of its size instead
    /// of breaking a line: no line break inside a seed word, the go-ahead code, the typed letters, the Seal ID or a
    /// row of C's and D's hex groups.
    func wholeLines(_ lines: Int = 1) -> some View {
        lineLimit(lines).minimumScaleFactor(KitType.fitScale)
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

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.replacingUnspecifiedDimensions().width
        if sideBySide(width) {
            let half = (width - KitPair.spacing) / 2
            let height = subviews.map { $0.sizeThatFits(ProposedViewSize(width: half, height: nil)).height }.max() ?? 0
            return CGSize(width: width, height: height)
        }
        let height = subviews.map { $0.sizeThatFits(ProposedViewSize(width: width, height: nil)).height }.reduce(0, +)
        return CGSize(width: width, height: height)
    }

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

/// The press gate (lead decision M6-23; PressGuard.swift): the one way a press on the screens runs its
/// action. KitButton, the pads' keys (PadViews.swift) and the overlay's tap (Screens.swift) each hand their
/// action to it; Screens sets it to ask the press guard whether the touch that made the press was admitted,
/// and drops the action silently when it was not. Unset, it runs nothing (fail closed): a press drawn outside
/// the screens does nothing.
struct PressGate {
    let run: (() -> Void) -> Void

    /// action, run if the press guard permits it.
    func callAsFunction(_ action: () -> Void) {
        run(action)
    }
}

private struct PressGateKey: EnvironmentKey {
    static let defaultValue = PressGate { _ in }
}

extension EnvironmentValues {
    /// The screens' press gate.
    var pressGate: PressGate {
        get { self[PressGateKey.self] }
        set { self[PressGateKey.self] = newValue }
    }
}

/// A button (Android's KitButton): framed, full width (two sharing a row share it), its text the
/// VoiceOver label, with the button trait. A disabled one is grey, takes no tap, and VoiceOver says so. Its
/// action runs through the press gate.
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

    @Environment(\.pressGate) private var pressGate

    var body: some View {
        let colour = enabled ? KitColors.text : KitColors.muted
        Button(action: {
            #if KC_TEST_HOOKS
            // U2j's probe: the Button's closure ran at all, before the press gate decides.
            MainActor.assumeIsolated { TestHooks.shared.noteFired(id) }
            #endif
            pressGate {
                #if KC_TEST_HOOKS
                MainActor.assumeIsolated { TestHooks.shared.noteAction(id) }
                #endif
                action()
            }
        }) {
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

/// The notice line above a screen: why the last session was wiped, black on the warning yellow. Its type
/// follows the user's text size, as Android's 16 sp (lead decision M6-26).
struct NoticeBar: View {
    let text: String
    /// Read so a change of the user's text size draws it again (KitType).
    @Environment(\.dynamicTypeSize) private var typeSize

    var body: some View {
        let _ = typeSize
        Text(text)
            .font(.system(size: KitType.scaled(16)))
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
    /// Read so a change of the user's text size draws it again; its 18 follows it, as Android's sp (M6-26).
    @Environment(\.dynamicTypeSize) private var typeSize

    var body: some View {
        let _ = typeSize
        Text(ShellTexts.testRegistry)
            .font(.system(size: KitType.scaled(18), weight: .bold))
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

/// A node whose text is a secret (lead decision M6-20, Q84's answer on Android: the shipping app names no secret
/// node). Its identifier, the UI tests' name for it, is compiled in under KC_TEST_HOOKS alone (TestHooks.swift
/// holds the names); in Shipping and WithTestRegistry the node has none, and --ios-app refuses each name
/// (mobile/ios/expected/secret-identifiers.txt) in those apps' binaries.
enum SecretNode: CaseIterable {
    /// An insert's word (the insert view and the read-back's match), its SeedBook number and each braille face.
    case insertWord, insertSeedbook, insertFace
    /// An overview line, the letters typed (the read-back, the confirm, Check a backup) and a mismatch's verdict.
    case overviewLine, typedLetters, verdictLine
    /// The backup passphrase's page and a confirm choice.
    case passphraseText, confirmChoice
    /// The BIP39 passphrase typed and D.
    case bip39Text, deviceLeg
    /// The dice face picked before its Confirm (a roll of R, the seed's own in dice-only mode).
    case dicePick
}

extension View {
    /// A secret node's identifier, in the TestHooks build alone (SecretNode).
    @ViewBuilder
    func secretIdentifier(_ node: SecretNode) -> some View {
        #if KC_TEST_HOOKS
        accessibilityIdentifier(node.testIdentifier)
        #else
        self
        #endif
    }
}
