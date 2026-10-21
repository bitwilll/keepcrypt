package com.keepcrypt.entropy.screens

/**
 * Every screen the app draws (tasks/todo.md, M5 groups 6 and 14). The capture harness proves each one
 * drawn and then black in every capture; screenId's when is exhaustive, so a screen added here without
 * an id fails to compile, and so does one without its class in isProtected. Until the ceremony screens
 * arrive (commits 16-21): the development-build first screen, the "Working..." screen every long call
 * shows, and the stop screen a halt ends on. In :screens' common code, beside the screens themselves.
 */
enum class Screen { FirstLaunch, Working, Stop }

/** The screen's id, the capture harness's name for it. */
fun screenId(screen: Screen): String = when (screen) {
    Screen.FirstLaunch -> "first_launch"
    Screen.Working -> "working"
    Screen.Stop -> "stop"
}

/**
 * Whether screen is Protected (docs/pi-firmware.md, "Protected screens and idle", adopted for the phone
 * by Q57): it shows a secret, so it is entered through the privacy gate from a Public screen, covered
 * after 30 s without input, and leaving the app on it discards the session at once. Every screen so far
 * is Public; the words, the read-back, the passphrases, D and the QR codes that carry a secret come
 * with commits 19-21.
 */
fun isProtected(screen: Screen): Boolean = when (screen) {
    Screen.FirstLaunch, Screen.Working, Screen.Stop -> false
}
