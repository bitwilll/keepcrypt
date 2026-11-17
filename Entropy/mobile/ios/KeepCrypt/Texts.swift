// The screens' fixed texts and the functions that lay out their public values (tasks/todo.md, M6 item D3):
// Android's :screens sources' own words (Kit.kt, Screens.kt, FirstLaunch.kt, StartScreens.kt, HomeScreens.kt),
// copied once here, apart from the views, so KeepCryptTests' ScreenTextsTests can pin each against those
// Kotlin files and the two apps say the same thing screen for screen. The few lines the iPhone says its own
// way (the offline check's, a screenshot's notice) are marked so. Nothing here is built from a secret.

/// The app's version: every M6 build is a development build, as every M5 APK is.
let appVersion = "0.0.0"

/// First launch's line for every build (Android's DEVELOPMENT_BUILD).
let developmentBuild = appVersion + " development build: do not use for real funds."

/// The app's name, the first screens' title.
let appName = "KeepCrypt"

/// The texts of the start screens, in each screen's order (Android's FirstLaunch.kt and StartScreens.kt).
enum StartTexts {
    static let firstLaunchMakes =
        "KeepCrypt makes a Bitcoin seed offline, from dice you roll and, unless you choose dice only, this phone's own randomness."
    static let firstLaunchPi = "Use the Raspberry Pi device for life savings and inheritance wallets."
    static let firstLaunchCannotStop =
        "What no app can stop: malware with OS-level control, a second camera pointed at the screen, or a rooted or jailbroken device."
    static let firstLaunchOffline = "A ceremony needs airplane mode on and Wi-Fi off."
    static let continueButton = "Continue"

    static let selfTestRunning = "The known-answer tests are running."
    static let selfTestFailure = "A failure stops the app before any ceremony."

    static let goOfflineNeeds =
        "A ceremony needs airplane mode on and Wi-Fi off. Going online during one wipes it. Bluetooth may stay on, for a braille display."
    /// The iPhone's own (C5): the offline check's one reading, where Android shows airplane mode's and Wi-Fi's.
    static let pathNone = "No usable network path: the phone is offline."
    /// The iPhone's own (C5).
    static let pathUsable = "A network path is usable: turn on airplane mode and turn off Wi-Fi."
    /// The iPhone's own: Android's "Start stays disabled until airplane mode is on and Wi-Fi is off.", for the path.
    static let startDisabled = "Start stays disabled until no network path is usable."
    static let start = "Start"

    static let homeModes =
        "New seed mixes your dice with this phone's own randomness. Dice-only seed uses your rolls alone, as a Coldcard does."
    static let newSeed = "New seed"
    static let diceOnlySeed = "Dice-only seed"
    static let checkBackup = "Check a backup"
    static let loadSnapshot = "Load registry snapshot"
    static let about = "About"
    static let noSnapshot = "No registry snapshot loaded"

    static let lengthNote = "12 words fill one KeepCrypt Hinge or Screw; 24 words need two."
    static let twelveWords = "12 words (default)"
    static let twentyFourWords = "24 words"

    /// The one sentence that explains the default mode (docs/mobile-apps.md, "Entropy sources on phones").
    static let safeIfEither = "Your seed is safe if either your phone or your dice are honest."
    static let deviceEntropyNote =
        "Tap the screen and move the phone if you like: your touches and its motion are mixed in, though the seed's safety never rests on them. The phone's own random source is read when you continue."

    static let commitmentNote = "Only verification runs need to write it down."

    static let picked = "Picked"
    static let undo = "Undo"
    static let confirm = "Confirm"
    static let done = "Done"
    static let diceMinimum = "Minimum reached: Done makes the seed, or roll more, up to 256."
    static let diceCap = "256 rolls: the most a seed takes."
    static let diceHow = "Roll a die, tap its face, then Confirm. Earlier rolls are never shown."
    /// The dice-only line (the Pi's): no device leg, E = SHA-256(R), as Coldcard.
    static let diceOnly = "No device randomness is mixed in: the seed is SHA-256 of your rolls, as on a Coldcard."
}

/// The texts every screen may show over or around itself (Android's Screens.kt and Kit.kt).
enum ShellTexts {
    static let working = "Working..."
    static let stopped = "KeepCrypt stopped"
    static let stopNote =
        "Something failed, so everything the session held was wiped. Close the app; its next start runs the self-test again before any ceremony."
    static let closeApp = "Close app"
    static let coverLine = "Tap to show the screen again"
    static let warningLine = "No input for 9 minutes. The session is wiped in one minute: tap to keep it."
    static let testRegistry = "TEST REGISTRY"
    /// What a Protected screen shows while a recording of the screen is reported.
    static let redacted = "Hidden while the screen is recorded. Stop the recording to go on."
    /// The line under a screen's column while it can scroll further (Q85): fixed text, never a secret.
    static let moreBelow = "More below"
}

/// The privacy gate's pane title (U3g).
let privacyGateTitle = "Privacy gate"

/// The privacy cover's pane title (U3g).
let coverTitle = "Screen covered"

/// The idle warning's pane title (U3g).
let idleWarningTitle = "Idle warning"

/// What VoiceOver is told as a state opens (Android's paneTitleOf, U3g): the cover's or the warning's
/// while one lies over the screen, the privacy gate's while one stands before a Protected screen, else the
/// screen's own title; fixed text either way, never a value the screen shows.
func paneTitle(of state: UiState) -> String {
    switch state.overlay {
    case .cover: return coverTitle
    case .warning: return idleWarningTitle
    case nil: return state.gate ? privacyGateTitle : state.screen.title
    }
}

/// A screen's actions scroll with its text, after it, once they are taller than this share of the
/// screen's height (Android's ACTIONS_SHARE; Q78, Q85; lead decision M5-84 (a)).
let actionsShare = 0.5

/// Whether actions actionsHeight high join a screen's scrolling column on a screen screenHeight high
/// (Android's actionsScroll): when they are taller than actionsShare of it. Before the first layout both
/// are 0, and the actions stay under the column.
func actionsScroll(_ actionsHeight: Double, _ screenHeight: Double) -> Bool {
    actionsHeight > screenHeight * actionsShare
}

/// The dice line (the Pi's dice_text): "37 / 50 rolls, 95.6 bits", from core's counts, the bits truncated
/// to a tenth.
func diceText(_ rolls: Int, _ minimum: Int, _ millibits: UInt32) -> String {
    let tenths = Int(millibits) / 100
    return String(rolls) + " / " + String(minimum) + " rolls, " + String(tenths / 10) + "." + String(tenths % 10) + " bits"
}

/// A registry date (YYYYMMDD) as ISO 8601's YYYY-MM-DD (Android's registryDate).
func registryDate(_ date: UInt32) -> String {
    func padded(_ value: UInt32, _ width: Int) -> String {
        let text = String(value)
        return String(repeating: "0", count: max(0, width - text.count)) + text
    }
    return padded(date / 10_000, 4) + "-" + padded(date / 100 % 100, 2) + "-" + padded(date % 100, 2)
}

/// Home's snapshot line (the Pi's): the one loaded, by number and date, or that none is.
func homeSnapshotLine(_ loaded: RegistryHeader?) -> String {
    guard let loaded else { return StartTexts.noSnapshot }
    return "Snapshot No. " + String(loaded.number) + ", dated " + registryDate(loaded.date)
}

/// Home's line when Check a backup or Load registry snapshot opened no file (Android's fileRefusalText).
func fileRefusalText(_ refusal: FileRefusal) -> String {
    switch refusal {
    case .notAge: return "That file was not opened: a KeepCrypt backup's name ends in " + Core.backupSuffix + "."
    case .notKcr: return "That file was not opened: a registry snapshot's name ends in " + Core.snapshotSuffix + "."
    case .noSize: return "That file was not opened: its size is not known, so it is not read."
    case .tooLarge: return "That file was not opened: it is larger than a backup can be (8 KiB)."
    case .snapshotTooLarge: return "That file was not opened: it is larger than a registry snapshot can be (75.5 MB)."
    case .unreadable: return "That file could not be read."
    }
}

/// The collision check's and Load registry snapshot's texts (Android's CheckScreens.kt, HomeScreens.kt and
/// Kit.kt's OneWayConfirm; docs/seal-watchonly-braille.md, "Checking the seal", word for word).
enum CheckTexts {
    static let question = "Check for collisions before you see your words?"
    static let prompt =
        "KeepCrypt can compare this new wallet's seal with the public KeepCrypt registry. If anyone has ever registered the same seal, your seed is not unique: it will be destroyed without being shown, and you will make a new one."
    static let checkNow = "Check now (recommended)"
    static let skip = "Skip"
    static let skipConfirm =
        "The words will be shown without a collision check. Skip is offered only now: once a check starts, only a verified go-ahead shows the words."
    static let skipAction = "Skip the check"
    static let skipped = "You skipped the check: the seal can be checked later from the words."
    static let sealCardNote = "Your checker draws this seal from the check QR on the next page: compare the two."
    static let showCheckQr = "Show check QR"
    static let scanQr = "Scan go-ahead QR"
    static let typeCode = "Type go-ahead code"
    static let matchFound = "Match found"
    static let cannotCheck = "Cannot check"
    static let checkQrNote =
        "Scan the check QR with the registry website or the offline checker app, and compare the seal it draws with the seal card (Back)."
    static let actions = "Go ahead: scan its QR or type its code. Stop: Match found. A network or snapshot error: Cannot check."
    static let back = "Back"
    static let codeHow = "Type the 8-character code your checker shows."
    static let codeRefused = "Code not accepted. Check the code on your checker and type it again: the check stays open."
    static let delete = "Delete"
    static let matchFoundConsequence = "Only when your checker said Stop: the seed is destroyed without being shown."
    static let destroy = "Destroy this seed"
    static let cannotCheckConsequence = "The seed is destroyed without being shown, and a new ceremony starts."
    static let startAgain = "Start again"
    static let collisionFound = "Collision found. This seed is not unique and has been destroyed."
    static let collisionSuspect =
        "A genuine collision means this phone's randomness or this app is suspect: report the phone model and the app's version to admin@keepcrypt.com, and make a verification run with the offline verifier."
    static let collisionNext = "Next: the collision report QR, then fresh entropy with at least 99 rolls."
    static let showReport = "Show the collision report"
    static let reportNote =
        "Scan it on a second device to report the collision: registering this destroyed seed's code raises the seal's count, so the earlier owner's next re-check shows the alarm. The destroyed seed is never used, so sharing its code is harmless."
    static let addFreshEntropy = "Add fresh entropy"
    static let checkSkipped = "Check skipped"
    static let checkPassed = "Check passed"
    static let wordsNext = "Next: the words, on a private screen."
    static let showWords = "Show words"
    static let stale = "This snapshot is more than 30 days old: seals registered since it was made are not in it."
    static let future = "This snapshot is dated after today on this phone: check the phone's date."
    static let scanGuide =
        "Point the phone at the go-ahead QR your checker shows, about 20-40 cm away, with the whole code in view. Nothing the camera sees is shown or kept."
    static let scanning = "Looking for the go-ahead QR..."
    static let scanRefused =
        "The camera was not allowed, so the go-ahead QR cannot be scanned. Type the go-ahead code instead: the check stays open."
    static let scanMissing = "This phone has no camera the app can use. Type the go-ahead code instead: the check stays open."
    static let scanFailed =
        "The camera stopped working. Go back and scan again, or type the go-ahead code: the check stays open."
    static let scanNotAccepted =
        "That QR code is not the go-ahead for this seal. Go back and scan the go-ahead QR your checker shows, or type its code: the check stays open."
    static let scanNoRegistryKey =
        "This build trusts no registry key yet, so it cannot check a go-ahead QR. Type the go-ahead code instead: the check stays open."
    /// The iPhone's own: once the camera was refused iOS never asks again, so the scan screen offers the
    /// app's page in Settings (OpenSettings.swift).
    static let openSettings = "Open Settings"
    static let snapshotNotLoaded = "Snapshot not loaded"
    static let snapshotLoaded = "Snapshot loaded"
    static let snapshotLoadedNote = "Check now runs the check against it on its own. It stays loaded until the app closes."
    static let snapshotRejected = "registry snapshot or proof rejected: "
    static let snapshotNoRegistryKey = "This build trusts no registry key yet, so it cannot load a registry snapshot."
}

/// The privacy gate's texts (Android's Screens.kt and WordsScreens.kt).
enum GateTexts {
    static let line = "The next screen shows a secret. No person or camera may see it."
    /// The gate's one action, as docs/mobile-apps.md quotes it.
    static let action = "I'm alone, show words"
    static let headphones = "If a screen reader speaks the next screen, use headphones: no app can tell where it speaks."
    static let seedBookRules =
        "The SeedBook is a public reference: never write the real phrase in it or store a marked copy with the wallet. Work one word at a time, in order, alone and offline; rehearse on a spare insert first. Never use a computer-driven embosser or printer for a real seed."
}

/// A loaded snapshot's line (the Pi's): its number, date and entry count.
func snapshotLine(_ header: RegistryHeader) -> String {
    "Snapshot No. " + String(header.number) + ", dated " + registryDate(header.date) + ", " + String(header.count) + " entries."
}

/// A scanned go-ahead QR's line: its snapshot's number and date, and how many entries this seal's bucket
/// holds, the proof's count, never the snapshot's total of seals (lead decision M5-55).
func proofLine(_ header: RegistryHeader) -> String {
    let entries = header.count == 1 ? "1 entry" : String(header.count) + " entries"
    return "Proof from snapshot No. " + String(header.number) + ", dated " + registryDate(header.date) + ": " + entries
        + " in this seal's bucket."
}

/// What the scan screen says of its scanner: that it reads, or why it stopped, or why core refused its text.
func scanLine(_ state: UiState) -> String {
    if let refusal = state.scanRefusal {
        return refusal == .noRegistryKey ? CheckTexts.scanNoRegistryKey : CheckTexts.scanNotAccepted
    }
    switch state.scanStop {
    case nil: return CheckTexts.scanning
    case .refused: return CheckTexts.scanRefused
    case .missing: return CheckTexts.scanMissing
    case .failed: return CheckTexts.scanFailed
    }
}

/// The freshness warning a phone gives (swb:120), or none for a Current snapshot.
func freshnessWarning(_ freshness: Freshness) -> String? {
    switch freshness {
    case .current: return nil
    case .stale: return CheckTexts.stale
    case .future: return CheckTexts.future
    }
}

/// The result of a verified go-ahead (swb's "Results"): as of the loaded snapshot's date, or, after a
/// typed code, as of the date the checker showed, which the phone cannot know.
func clearText(_ sealId: String, _ registry: RegistryHeader?) -> String {
    guard let registry else { return "No collision for seal " + sealId + ", as of the date your checker showed." }
    return "No collision for seal " + sealId + " as of " + registryDate(registry.date) + "."
}

/// The code entry's code: the symbols typed, an underscore for each still to come, a dash after the fourth
/// (the checker's two groups).
func codeShown(_ code: PadEntry) -> String {
    var out = ""
    for index in 0..<code.capacity {
        if index == code.capacity / 2 { out.append("-") }
        out.append(index < code.length ? code.keyAt(index) : "_")
    }
    return out
}

/// Core's text for a refusal of a snapshot (core/src/error.rs's Display, as Android's snapshotRefusalText
/// gives it), or the phone's own line for a build with no registry key; nil for any other refusal.
func snapshotRefusalText(_ refusal: Refusal) -> String? {
    let rejected = CheckTexts.snapshotRejected
    switch refusal {
    case .noRegistryKey: return CheckTexts.snapshotNoRegistryKey
    case .tooShort: return rejected + "too short"
    case .badMagic: return rejected + "wrong magic"
    case .badVersion: return rejected + "unsupported version"
    case .badSignature: return rejected + "bad signature"
    case .badDate: return rejected + "bad date"
    case .tooManyEntries: return rejected + "too many entries"
    case .badLength: return rejected + "wrong length"
    case .unsorted: return rejected + "entries out of order"
    case .duplicate: return rejected + "duplicate entry"
    case .zeroCount: return rejected + "zero registration count"
    case .rootMismatch: return rejected + "bucket root mismatch"
    case .bucketOutOfRange: return rejected + "bucket index out of range"
    case .entryOutsideBucket: return rejected + "entry outside its bucket"
    case .proofCount: return rejected + "more bucket entries than the snapshot holds"
    default: return nil
    }
}
