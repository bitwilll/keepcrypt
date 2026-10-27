package com.keepcrypt.entropy.screens

/**
 * Every screen the app draws (tasks/todo.md, M5 groups 6, 14, 15 and 16). The capture harness proves
 * each one drawn and then black in every capture; screenId's when is exhaustive, so a screen added
 * here without an id fails to compile, and so does one without its class in isProtected. The order is
 * the one walk CaptureTest takes through them in one activity: First launch, the first screen of
 * every start, the self-test its Continue runs (lead decision M5-50), Go offline, Home, Length, Device
 * entropy (Mixed only), Commitment (Mixed only) and Dice (commit 16); the collision check (commit 17):
 * the check prompt, Skip's confirm, the seal card, the scan screen (commit 18), the code entry, Match
 * found's and Cannot check's confirms, the collision result, the collision-report QR and, after the
 * restart it leads to, the result before the words; the words to the end of the ceremony (commit 19):
 * the words in insert view, their overview, the device swap a 24-word seed's pages pass, the read-back
 * entry and its mismatch, the read-back's end, the wallet summary and the checklist Finish ends; then
 * the "Working..." screen every other long call shows, and the stop screen a halt ends on. The backup
 * and the other exports come with commits 20 and 21. In :screens' common code, beside the screens
 * themselves.
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
    Checklist,
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
    Screen.Checklist -> "checklist"
    Screen.Working -> "working"
    Screen.Stop -> "stop"
}

/**
 * Whether screen is Protected (docs/pi-firmware.md, "Protected screens and idle", adopted for the phone
 * by Q57): it shows a secret, so it is entered through the privacy gate from a Public one, covered
 * after 30 s without input, and leaving the app on it discards the session at once. They are the
 * collision-report QR (it carries the destroyed seed's seal code), the words in insert view and
 * overview, and the read-back entry and mismatch screens (commit 19); every other screen so far is
 * Public, the dice screen, C and the seal card's check QR (T and a nonce) included, and the device
 * swap, the read-back's end, the wallet summary and the checklist (the Pi's list), and the scan
 * screen, which draws nothing the camera sees; the passphrases, D and the other QR codes that carry
 * a secret come with commits 20 and 21.
 */
fun isProtected(screen: Screen): Boolean = when (screen) {
    Screen.CollisionReport, Screen.Words, Screen.WordsOverview, Screen.ReadbackEntry, Screen.ReadbackMismatch -> true
    Screen.FirstLaunch, Screen.SelfTest, Screen.GoOffline, Screen.Home, Screen.Length, Screen.DeviceEntropy,
    Screen.Commitment, Screen.Dice, Screen.CheckPrompt, Screen.SkipConfirm, Screen.SealCard, Screen.Scan,
    Screen.CodeEntry, Screen.MatchFoundConfirm, Screen.CannotCheckConfirm, Screen.Collision, Screen.CheckResult,
    Screen.DeviceSwap, Screen.ReadbackDone, Screen.Wallet, Screen.Checklist, Screen.Working, Screen.Stop -> false
}

/**
 * Whether screen stands for a long call: the start-up self-test's screen and "Working...", which take
 * no input (docs/pi-firmware.md, "Buttons": a press while the device is busy does nothing).
 */
fun isWorking(screen: Screen): Boolean = screen == Screen.Working || screen == Screen.SelfTest
