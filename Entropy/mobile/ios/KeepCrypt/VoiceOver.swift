// What VoiceOver is told of each kind of element (tasks/todo.md, M6 item D8; Android's semantics in Kit.kt,
// Pads.kt, Drawing.kt and Screens.kt), as one table the views apply (Kit.swift's spoken(_:)) and the tests
// hold to Android's: a heading or the title is a header (Android's heading()); a live line, and the notice,
// is spoken politely when it appears or changes while its screen stays (liveRegion Polite: here a queued
// announcement of its own fixed or public text, and the updates-frequently trait); a QR code is an image
// named by its kind, never by its data (Role.Image, contentDescription kind.spoken); a pad's key is a button
// named by its label, its letter or "space" (Role.Button, its text the label); the cover and the idle
// warning are a button that takes them away (clickable). Android's stateDescription is used nowhere, so
// nothing stands for it. Android marks a secret's node and a Protected pad's keys sensitive (isSensitiveData),
// so only accessibility tools read them; iOS has no such mark, and VoiceOver reads them as any element
// (the iPhone residual, the owner's I5 check). Each screen's title, the gate's, the cover's and the idle
// warning's are told as they open (Screens.swift; paneTitle(of:), Android's paneTitle).

/// The kinds of element VoiceOver is told of.
enum Spoken: CaseIterable {
    case heading, title, liveLine, notice, qrCode, padKey, overlay
}

/// What VoiceOver is told of one kind: its traits, whether its text is announced as it appears or changes,
/// and whether its label is set apart from what it draws (a QR code's kind; a key's label).
struct SpokenSemantics: Hashable {
    var header = false
    var image = false
    var button = false
    var updatesFrequently = false
    var announced = false
    var labelled = false
}

/// The table (Android's semantics, kind by kind).
func spokenSemantics(_ kind: Spoken) -> SpokenSemantics {
    switch kind {
    case .heading, .title: return SpokenSemantics(header: true)
    case .liveLine, .notice: return SpokenSemantics(updatesFrequently: true, announced: true)
    case .qrCode: return SpokenSemantics(image: true, labelled: true)
    case .padKey: return SpokenSemantics(button: true, labelled: true)
    case .overlay: return SpokenSemantics(button: true)
    }
}

/// The lines spoken as live, by id: Android's (each KitText(..., tag, live = true) of :screens), and the
/// iPhone's own offline check's line (C5's network_state, which changes while Go offline stays, as Android's
/// airplane-mode and Wi-Fi lines do without being live; D3's choice, kept).
let liveLineIds: Set<String> = androidLiveLineIds.union(["network_state"])

/// Android's live lines, by tag.
let androidLiveLineIds: Set<String> = [
    "scan_line", "code_refused", "wrong_confirm", "save_failure", "entry_refusal", "keys_page", "file_refusal",
    "dice_count", "dice_minimum", "dice_cap", "more_below",
]
