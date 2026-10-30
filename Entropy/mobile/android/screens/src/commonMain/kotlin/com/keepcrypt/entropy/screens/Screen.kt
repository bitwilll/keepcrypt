package com.keepcrypt.entropy.screens

/**
 * Every screen the app draws (tasks/todo.md, M5 groups 6, 14, 15 and 16). The capture harness proves
 * each one drawn and then black in every capture; screenId's when is exhaustive, so a screen added
 * here without an id fails to compile, and so does one without its class in isProtected. The order is
 * the one walk CaptureTest takes through them in one activity: First launch, the first screen of
 * every start, the self-test its Continue runs (lead decision M5-50), Go offline, Home, Length, Device
 * entropy (Mixed only), Commitment (Mixed only) and Dice (commit 16); the collision check (commit 17):
 * the check prompt, Skip's confirm, the seal card, its check QR (Stage U's U3d), the scan screen (commit
 * 18), the code entry, Match found's and Cannot check's confirms, the collision result, the
 * collision-report QR and, after the restart it leads to, the result before the words; the words to
 * the end of the ceremony (commit 19):
 * the words in insert view, their overview, the device swap a 24-word seed's pages pass, the read-back
 * entry and its mismatch, the read-back's end, the wallet summary, the encrypted backup (commit 20:
 * its offer, the passphrase, its confirm, the save and "Backup verified"), the watch-only export
 * (commit 21: its offer, the BIP39 passphrase's question and its entry on the ASCII pad, the watch-only
 * summary, the account QR and the descriptor QR), the registration (its offer and its QR), D (Mixed
 * only: its offer and D) and the checklist Finish ends; Home's Check a backup (commit 20): the
 * passphrase's entry, its result and the re-check QR (its words are the words' screens); Home's Load
 * registry snapshot's result and About (commit 21); then the "Working..." screen every other long call
 * shows, and the stop screen a halt ends on. In :screens' common code, beside the screens themselves.
 */
enum class Screen {
    FirstLaunch,
    SelfTest,
    GoOffline,
    Home,
    Length,
    DeviceEntropy,
    Commitment,
    Dice,
    CheckPrompt,
    SkipConfirm,
    SealCard,
    CheckQr,
    Scan,
    CodeEntry,
    MatchFoundConfirm,
    CannotCheckConfirm,
    Collision,
    CollisionReport,
    CheckResult,
    Words,
    WordsOverview,
    DeviceSwap,
    ReadbackEntry,
    ReadbackMismatch,
    ReadbackDone,
    Wallet,
    BackupOffer,
    BackupPassphrase,
    BackupConfirm,
    BackupSave,
    BackupVerified,
    WatchOffer,
    Bip39Ask,
    Bip39Entry,
    WatchSummary,
    WatchAccountQr,
    WatchDescriptorQr,
    RegisterOffer,
    RegisterQr,
    RevealDOffer,
    RevealD,
    Checklist,
    BackupCheckEntry,
    BackupCheckResult,
    BackupRecheck,
    Snapshot,
    About,
    Working,
    Stop,
}

/** The screen's id, the capture harness's name for it (and the test tag of its root). */
fun screenId(screen: Screen): String = when (screen) {
    Screen.FirstLaunch -> "first_launch"
    Screen.SelfTest -> "self_test"
    Screen.GoOffline -> "go_offline"
    Screen.Home -> "home"
    Screen.Length -> "length"
    Screen.DeviceEntropy -> "device_entropy"
    Screen.Commitment -> "commitment"
    Screen.Dice -> "dice"
    Screen.CheckPrompt -> "check_prompt"
    Screen.SkipConfirm -> "skip_confirm"
    Screen.SealCard -> "seal_card"
    Screen.CheckQr -> "check_qr"
    Screen.Scan -> "scan"
    Screen.CodeEntry -> "code_entry"
    Screen.MatchFoundConfirm -> "match_found_confirm"
    Screen.CannotCheckConfirm -> "cannot_check_confirm"
    Screen.Collision -> "collision"
    Screen.CollisionReport -> "collision_report"
    Screen.CheckResult -> "check_result"
    Screen.Words -> "words"
    Screen.WordsOverview -> "words_overview"
    Screen.DeviceSwap -> "device_swap"
    Screen.ReadbackEntry -> "readback_entry"
    Screen.ReadbackMismatch -> "readback_mismatch"
    Screen.ReadbackDone -> "readback_done"
    Screen.Wallet -> "wallet"
    Screen.BackupOffer -> "backup_offer"
    Screen.BackupPassphrase -> "backup_passphrase"
    Screen.BackupConfirm -> "backup_confirm"
    Screen.BackupSave -> "backup_save"
    Screen.BackupVerified -> "backup_verified"
    Screen.WatchOffer -> "watch_offer"
    Screen.Bip39Ask -> "bip39_ask"
    Screen.Bip39Entry -> "bip39_entry"
    Screen.WatchSummary -> "watch_summary"
    Screen.WatchAccountQr -> "watch_account_qr"
    Screen.WatchDescriptorQr -> "watch_descriptor_qr"
    Screen.RegisterOffer -> "register_offer"
    Screen.RegisterQr -> "register_qr"
    Screen.RevealDOffer -> "reveal_d_offer"
    Screen.RevealD -> "reveal_d"
    Screen.Checklist -> "checklist"
    Screen.BackupCheckEntry -> "backup_check_entry"
    Screen.BackupCheckResult -> "backup_check_result"
    Screen.BackupRecheck -> "backup_recheck"
    Screen.Snapshot -> "snapshot"
    Screen.About -> "about"
    Screen.Working -> "working"
    Screen.Stop -> "stop"
}

/**
 * Whether screen is Protected (docs/pi-firmware.md, "Protected screens and idle", adopted for the phone
 * by Q57): it shows a secret, so it is entered through the privacy gate from a Public one, covered
 * after 30 s without input, and leaving the app on it discards the session at once. They are the
 * collision-report QR (it carries the destroyed seed's seal code), the words in insert view and
 * overview, the read-back entry and mismatch screens (commit 19), the backup passphrase, its
 * confirm and Check a backup's passphrase entry (commit 20), and the BIP39 passphrase's entry, the
 * account and descriptor QRs (each carries the xpub), the registration QR (the seal code) and D (commit
 * 21; the Pi's list); every other screen is Public, the dice screen, C, the seal card and its check QR
 * (T and a nonce) included, and the device swap, the read-back's end, the wallet summary, the backup's
 * offer, save and "Backup verified", the watch-only offer, the BIP39 question and the watch-only
 * summary (Q29), the registration's and D's offers, the checklist, Check a backup's result and its
 * re-check QR (T alone; the Pi's list), the scan screen, which draws nothing the camera sees, Load
 * registry snapshot's result and About.
 */
fun isProtected(screen: Screen): Boolean = when (screen) {
    Screen.CollisionReport, Screen.Words, Screen.WordsOverview, Screen.ReadbackEntry, Screen.ReadbackMismatch,
    Screen.BackupPassphrase, Screen.BackupConfirm, Screen.Bip39Entry, Screen.WatchAccountQr, Screen.WatchDescriptorQr,
    Screen.RegisterQr, Screen.RevealD, Screen.BackupCheckEntry -> true
    Screen.FirstLaunch, Screen.SelfTest, Screen.GoOffline, Screen.Home, Screen.Length, Screen.DeviceEntropy,
    Screen.Commitment, Screen.Dice, Screen.CheckPrompt, Screen.SkipConfirm, Screen.SealCard, Screen.CheckQr, Screen.Scan,
    Screen.CodeEntry, Screen.MatchFoundConfirm, Screen.CannotCheckConfirm, Screen.Collision, Screen.CheckResult,
    Screen.DeviceSwap, Screen.ReadbackDone, Screen.Wallet, Screen.BackupOffer, Screen.BackupSave, Screen.BackupVerified,
    Screen.WatchOffer, Screen.Bip39Ask, Screen.WatchSummary, Screen.RegisterOffer, Screen.RevealDOffer, Screen.Checklist,
    Screen.BackupCheckResult, Screen.BackupRecheck, Screen.Snapshot, Screen.About, Screen.Working, Screen.Stop -> false
}

/**
 * Whether screen stands for a long call: the start-up self-test's screen and "Working...", which take
 * no input (docs/pi-firmware.md, "Buttons": a press while the device is busy does nothing).
 */
fun isWorking(screen: Screen): Boolean = screen == Screen.Working || screen == Screen.SelfTest
