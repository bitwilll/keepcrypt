package com.keepcrypt.entropy.screens

import androidx.compose.runtime.Composable

/**
 * The first screen, shown on every start before any core call (docs/mobile-apps.md, "Role and honest
 * limits" and steps 1-3; tasks/todo.md, M5 group 15; lead decision M5-50): what the app does, what no
 * app can stop, that the Pi is the device for life savings, and that every M5 build is a 0.0.0
 * development build. Nothing records that it was read (rule 8), so it shows again on the next start.
 * Its Continue runs the start-up self-test, then Go offline; the capture control draws it without one
 * (onContinue null). With testRegistry, the TEST REGISTRY strip is on top (Q60). Written once in
 * :screens' common code (the re-plan for Compose Multiplatform), it is drawn by the app and the
 * capture control on Android; whether the iPhone reuses it is M6's question (Q73).
 */
@Composable
fun FirstLaunch(testRegistry: Boolean, onContinue: (() -> Unit)? = null) {
    val tag = screenId(Screen.FirstLaunch)
    if (onContinue == null) {
        KitScreen(tag, testRegistry) { FirstLaunchText() }
    } else {
        KitScreen(tag, testRegistry, actions = { KitButton("Continue", "first_launch_continue", onClick = onContinue) }) {
            FirstLaunchText()
        }
    }
}

/** The first screen's text; its yellow line is the capture tests' known colour. */
@Composable
private fun FirstLaunchText() {
    KitText("KeepCrypt", KitType.title)
    Gap(16)
    KitText("0.0.0 development build: do not use for real funds.", KitType.body.copy(color = KitColors.warning))
    KitText(
        "KeepCrypt makes a Bitcoin seed offline, from dice you roll and, unless you choose dice " +
            "only, this phone's own randomness.",
    )
    KitText("Use the Raspberry Pi device for life savings and inheritance wallets.")
    KitText(
        "What no app can stop: malware with OS-level control, a second camera pointed at the " +
            "screen, or a rooted or jailbroken device.",
    )
    KitText("A ceremony needs airplane mode on and Wi-Fi off.")
}
