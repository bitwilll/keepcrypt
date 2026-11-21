// Every screen the iPhone app draws (tasks/todo.md, M6 items D1 and D2; Q86): the Swift copy of :screens'
// Screen.kt, in its order, each with its id (the raw value, Android's screenId), its fixed title
// (Android's screenTitle, the screen reader's pane title) and its kind (Android's isProtected). The two
// apps' flows are written twice, in Kotlin and in Swift, so the shared table mobile/screens.json holds
// both to one list: :screens' ScreenTableTest holds Screen.kt to it and KeepCryptTests' ScreenTableTests
// this file. Each switch below is exhaustive, so a screen added here without its title or kind does not
// compile.

/// A screen of the ceremony (docs/mobile-apps.md, "Screens and user flow"), in Screen.kt's order: First
/// launch, the start-up self-test, Go offline, Home, Length, Device entropy and Commitment (Mixed only),
/// Dice; the collision check; the words to the end of the ceremony; the encrypted backup and the other
/// exports; Home's Check a backup, Load registry snapshot and About; "Working...", which every other long
/// call shows; and the stop screen a halt ends on.
enum Screen: String, CaseIterable {
    case firstLaunch = "first_launch"
    case selfTest = "self_test"
    case goOffline = "go_offline"
    case home = "home"
    case length = "length"
    case deviceEntropy = "device_entropy"
    case commitment = "commitment"
    case dice = "dice"
    case checkPrompt = "check_prompt"
    case skipConfirm = "skip_confirm"
    case sealCard = "seal_card"
    case checkQr = "check_qr"
    case scan = "scan"
    case codeEntry = "code_entry"
    case matchFoundConfirm = "match_found_confirm"
    case cannotCheckConfirm = "cannot_check_confirm"
    case collision = "collision"
    case collisionReport = "collision_report"
    case checkResult = "check_result"
    case words = "words"
    case wordsOverview = "words_overview"
    case deviceSwap = "device_swap"
    case readbackEntry = "readback_entry"
    case readbackMismatch = "readback_mismatch"
    case readbackDone = "readback_done"
    case wallet = "wallet"
    case backupOffer = "backup_offer"
    case backupPassphrase = "backup_passphrase"
    case backupConfirm = "backup_confirm"
    case backupSave = "backup_save"
    case backupVerified = "backup_verified"
    case watchOffer = "watch_offer"
    case bip39Ask = "bip39_ask"
    case bip39Entry = "bip39_entry"
    case watchSummary = "watch_summary"
    case watchAccountQr = "watch_account_qr"
    case watchDescriptorQr = "watch_descriptor_qr"
    case registerOffer = "register_offer"
    case registerQr = "register_qr"
    case revealDOffer = "reveal_d_offer"
    case revealD = "reveal_d"
    case checklist = "checklist"
    case backupCheckEntry = "backup_check_entry"
    case backupCheckResult = "backup_check_result"
    case backupRecheck = "backup_recheck"
    case snapshot = "snapshot"
    case about = "about"
    case working = "working"
    case stop = "stop"

    /// The screen's id: its accessibility identifier, the UI tests' name for it.
    var id: String { rawValue }

    /// The screen's title, VoiceOver's name for it as it opens: fixed text, never built from data, so
    /// announcing it says which screen came and nothing it shows.
    var title: String {
        switch self {
        case .firstLaunch: return "First launch"
        case .selfTest: return "Self-test"
        case .goOffline: return "Go offline"
        case .home: return "Home"
        case .length: return "How many words?"
        case .deviceEntropy: return "Device entropy"
        case .commitment: return "Commitment C"
        case .dice: return "Dice"
        case .checkPrompt: return "Check for collisions"
        case .skipConfirm: return "Skip the check?"
        case .sealCard: return "Seal card"
        case .checkQr: return "Check QR"
        case .scan: return "Scan go-ahead QR"
        case .codeEntry: return "Go-ahead code"
        case .matchFoundConfirm: return "Match found?"
        case .cannotCheckConfirm: return "Cannot check?"
        case .collision: return "Collision"
        case .collisionReport: return "Report collision"
        case .checkResult: return "Check result"
        case .words: return "Seed words"
        case .wordsOverview: return "Seed words: overview"
        case .deviceSwap: return "Device swap"
        case .readbackEntry: return "Read-back"
        case .readbackMismatch: return "Read-back mismatch"
        case .readbackDone: return "Read-back complete"
        case .wallet: return "Wallet summary"
        case .backupOffer: return "Encrypted backup"
        case .backupPassphrase: return "Backup passphrase"
        case .backupConfirm: return "Check your copy"
        case .backupSave: return "Save the backup"
        case .backupVerified: return "Backup verified"
        case .watchOffer: return "Watch-only export"
        case .bip39Ask: return "BIP39 passphrase?"
        case .bip39Entry: return "BIP39 passphrase"
        case .watchSummary: return "Watch-only wallet"
        case .watchAccountQr: return "Account QR for Sparrow"
        case .watchDescriptorQr: return "Descriptor QR for Bitcoin Core"
        case .registerOffer: return "Register seal"
        case .registerQr: return "Registration QR"
        case .revealDOffer: return "Reveal D"
        case .revealD: return "Device leg D"
        case .checklist: return "Before you walk away"
        case .backupCheckEntry: return "Check a backup"
        case .backupCheckResult: return "Backup check result"
        case .backupRecheck: return "Re-check QR"
        case .snapshot: return "Registry snapshot"
        case .about: return "About"
        case .working: return "Working"
        case .stop: return "KeepCrypt stopped"
        }
    }

    /// Whether the screen is Protected (docs/pi-firmware.md, "Protected screens and idle", adopted for
    /// the phones by docs/mobile-apps.md, "Session lifetime"): it shows a secret, so it is entered
    /// through the privacy gate from a Public one, covered after 30 s without input, and leaving the app
    /// on it discards the session at once. The collision-report QR, the words in insert view and
    /// overview, the read-back entry and mismatch, the backup passphrase and its confirm, Check a
    /// backup's passphrase entry, the BIP39 passphrase's entry, the account and descriptor QRs, the
    /// registration QR and D; every other screen is Public.
    var isProtected: Bool {
        switch self {
        case .collisionReport, .words, .wordsOverview, .readbackEntry, .readbackMismatch, .backupPassphrase,
             .backupConfirm, .bip39Entry, .watchAccountQr, .watchDescriptorQr, .registerQr, .revealD,
             .backupCheckEntry:
            return true
        case .firstLaunch, .selfTest, .goOffline, .home, .length, .deviceEntropy, .commitment, .dice,
             .checkPrompt, .skipConfirm, .sealCard, .checkQr, .scan, .codeEntry, .matchFoundConfirm,
             .cannotCheckConfirm, .collision, .checkResult, .deviceSwap, .readbackDone, .wallet, .backupOffer,
             .backupSave, .backupVerified, .watchOffer, .bip39Ask, .watchSummary, .registerOffer, .revealDOffer,
             .checklist, .backupCheckResult, .backupRecheck, .snapshot, .about, .working, .stop:
            return false
        }
    }

    /// Whether the screen stands for a long call: the start-up self-test's screen and "Working...", which
    /// take no input (docs/pi-firmware.md, "Buttons": a press while the device is busy does nothing).
    var isWorking: Bool { self == .working || self == .selfTest }
}
