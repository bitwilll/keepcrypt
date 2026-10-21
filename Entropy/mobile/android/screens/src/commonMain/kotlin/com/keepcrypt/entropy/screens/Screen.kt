package com.keepcrypt.entropy.screens

/**
 * Every screen the app draws (tasks/todo.md, M5 groups 6, 14 and 15). The capture harness proves each
 * one drawn and then black in every capture; screenId's when is exhaustive, so a screen added here
 * without an id fails to compile, and so does one without its class in isProtected. The order is the
 * ceremony's (CaptureTest walks it in this order in one activity): First launch, the first screen of
 * every start, the self-test its Continue runs (lead decision M5-50), Go offline, Home, Length, Device
 * entropy (Mixed only), Commitment (Mixed only) and Dice (commit 16); then the "Working..." screen
 * every other long call shows, and the stop screen a halt ends on. The collision check, the words and
 * the rest come with commits 17-21. In :screens' common code, beside the screens themselves.
 */
enum class Screen { FirstLaunch, SelfTest, GoOffline, Home, Length, DeviceEntropy, Commitment, Dice, Working, Stop }

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
    Screen.Working -> "working"
    Screen.Stop -> "stop"
}

/**
 * Whether screen is Protected (docs/pi-firmware.md, "Protected screens and idle", adopted for the phone
 * by Q57): it shows a secret, so it is entered through the privacy gate from a Public one, covered
 * after 30 s without input, and leaving the app on it discards the session at once. Every screen so far
 * is Public, the dice screen and C included (the Pi's list); the words, the read-back, the passphrases,
 * D and the QR codes that carry a secret come with commits 19-21.
 */
fun isProtected(screen: Screen): Boolean = when (screen) {
    Screen.FirstLaunch, Screen.SelfTest, Screen.GoOffline, Screen.Home, Screen.Length, Screen.DeviceEntropy,
    Screen.Commitment, Screen.Dice, Screen.Working, Screen.Stop -> false
}

/**
 * Whether screen stands for a long call: the start-up self-test's screen and "Working...", which take
 * no input (docs/pi-firmware.md, "Buttons": a press while the device is busy does nothing).
 */
fun isWorking(screen: Screen): Boolean = screen == Screen.Working || screen == Screen.SelfTest
