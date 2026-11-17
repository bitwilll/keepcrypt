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
