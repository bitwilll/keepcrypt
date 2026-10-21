package com.keepcrypt.entropy.screens

/**
 * Every screen the app draws (tasks/todo.md, M5 groups 6, 14, 15 and 16). The capture harness proves
 * each one drawn and then black in every capture; screenId's when is exhaustive, so a screen added
 * here without an id fails to compile, and so does one without its class in isProtected. The order is
 * the one walk CaptureTest takes through them in one activity: First launch, the first screen of
 * every start, the self-test its Continue runs (lead decision M5-50), Go offline, Home, Length, Device
 * entropy (Mixed only), Commitment (Mixed only) and Dice (commit 16); the collision check (commit 17):
 * the check prompt, Skip's confirm, the seal card, the code entry, Match found's and Cannot check's
 * confirms, the collision result, the collision-report QR and, after the restart it leads to, the
 * result before the words; then the "Working..." screen every other long call shows, and the stop
 * screen a halt ends on. The words and the rest come with commits 19-21. In :screens' common code,
 * beside the screens themselves.
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
    CodeEntry,
    MatchFoundConfirm,
    CannotCheckConfirm,
    Collision,
    CollisionReport,
    CheckResult,
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
    Screen.CodeEntry -> "code_entry"
    Screen.MatchFoundConfirm -> "match_found_confirm"
    Screen.CannotCheckConfirm -> "cannot_check_confirm"
    Screen.Collision -> "collision"
    Screen.CollisionReport -> "collision_report"
    Screen.CheckResult -> "check_result"
    Screen.Working -> "working"
    Screen.Stop -> "stop"
}

/**
 * Whether screen is Protected (docs/pi-firmware.md, "Protected screens and idle", adopted for the phone
 * by Q57): it shows a secret, so it is entered through the privacy gate from a Public one, covered
 * after 30 s without input, and leaving the app on it discards the session at once. The first is the
 * collision-report QR (it carries the destroyed seed's seal code); every other screen so far is
 * Public, the dice screen, C and the seal card's check QR (T and a nonce) included (the Pi's list); the
 * words, the read-back, the passphrases, D and the other QR codes that carry a secret come with
 * commits 19-21.
 */
fun isProtected(screen: Screen): Boolean = when (screen) {
    Screen.CollisionReport -> true
    Screen.FirstLaunch, Screen.SelfTest, Screen.GoOffline, Screen.Home, Screen.Length, Screen.DeviceEntropy,
    Screen.Commitment, Screen.Dice, Screen.CheckPrompt, Screen.SkipConfirm, Screen.SealCard, Screen.CodeEntry,
    Screen.MatchFoundConfirm, Screen.CannotCheckConfirm, Screen.Collision, Screen.CheckResult, Screen.Working,
    Screen.Stop -> false
}

/**
 * Whether screen stands for a long call: the start-up self-test's screen and "Working...", which take
 * no input (docs/pi-firmware.md, "Buttons": a press while the device is busy does nothing).
 */
fun isWorking(screen: Screen): Boolean = screen == Screen.Working || screen == Screen.SelfTest
