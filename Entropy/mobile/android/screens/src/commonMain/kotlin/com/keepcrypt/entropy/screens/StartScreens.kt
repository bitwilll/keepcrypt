package com.keepcrypt.entropy.screens

import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.key
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.keepcrypt.entropy.ffi.Words

// The screens from the start to the dice (tasks/todo.md, M5 group 15; docs/mobile-apps.md, "Screens
// and user flow", steps 2-8; the Pi's wording, docs/pi-firmware.md steps 1-6 and pi/app's screens.rs,
// wherever mobile-apps.md says nothing else): Self-test, Go offline, Home, Length, Device entropy,
// Commitment and Dice; First launch is FirstLaunch.kt. Each is Public, drawn with the UI kit, and
// hands its presses to the ceremony model, which ignores a press its screen no longer shows. Home's
// Check a backup (commit 20), Load registry snapshot and About (commit 21) come with their screens, and
// the dice screen's Done with the collision check (commit 17), so no control here leads nowhere.

/** The one sentence that explains the default mode (docs/mobile-apps.md, "Entropy sources on phones"). */
const val SAFE_IF_EITHER = "Your seed is safe if either your phone or your dice are honest."

/** The dice-only line (the Pi's): no device leg, E = SHA-256(R), as Coldcard. */
const val DICE_ONLY = "No device randomness is mixed in: the seed is SHA-256 of your rolls, as on a Coldcard."

/** The hex digits by nibble, lower case (the Pi's ui/hex.rs, which verify.py reads back). */
private const val HEX_DIGITS = "0123456789abcdef"

/**
 * C as the commitment screen shows it (the Pi's ui/hex.rs): 32 bytes as 16 groups of 4 lower-case hex
 * digits, a space between the groups of a row and a line feed between the four rows. verify.py drops
 * the spaces and line feeds and takes the 64 digits. C is public; D (commit 21) is not, and is never
 * made into a String.
 */
fun hexGroups(bytes: ByteArray): String {
    check(bytes.size == 32)
    return buildString(79) {
        for (index in bytes.indices) {
            if (index > 0 && index % 8 == 0) {
                append('\n')
            } else if (index > 0 && index % 2 == 0) {
                append(' ')
            }
            val byte = bytes[index].toInt() and 0xFF
            append(HEX_DIGITS[byte shr 4])
            append(HEX_DIGITS[byte and 0x0F])
        }
    }
}

/** The dice line (the Pi's dice_text): "37 / 50 rolls, 95.6 bits", from core's counts, the bits truncated to a tenth. */
fun diceText(rolls: Int, minimum: Int, millibits: Long): String {
    val tenths = millibits / 100
    return "$rolls / $minimum rolls, ${tenths / 10}.${tenths % 10} bits"
}

/** The self-test's screen (docs/mobile-apps.md, step 2; the Pi's boot screen): core's known-answer tests run behind it, and it takes no input. */
@Composable
fun SelfTest(testRegistry: Boolean) {
    KitScreen(screenId(Screen.SelfTest), testRegistry) {
        KitText("KeepCrypt", KitType.title)
        Gap(16)
        Heading("Self-test")
        KitText("The known-answer tests are running.")
        KitText("A failure stops the app before any ceremony.", KitType.small)
    }
}

/**
 * Go offline (docs/mobile-apps.md, step 3; Q57): the airplane-mode and Wi-Fi states, a button that
 * opens the system's airplane-mode settings, and Start, disabled until airplane mode is on and Wi-Fi
 * off.
 */
@Composable
fun GoOffline(state: UiState, testRegistry: Boolean, onSettings: () -> Unit, onStart: () -> Unit) {
    KitScreen(
        screenId(Screen.GoOffline),
        testRegistry,
        actions = {
            KitButton("Open airplane-mode settings", "airplane_settings", onClick = onSettings)
            KitButton("Start", "start", enabled = state.offline, onClick = onStart)
        },
    ) {
        Heading("Go offline")
        KitText("A ceremony needs airplane mode on and Wi-Fi off. Going online during one wipes it. Bluetooth may stay on, for a braille display.")
        Gap(8)
        KitText(if (state.airplaneMode) "Airplane mode: on" else "Airplane mode: off", tag = "airplane_mode")
        KitText(if (state.wifiOff) "Wi-Fi: off" else "Wi-Fi: on", tag = "wifi")
        if (!state.offline) {
            KitText("Start stays disabled until airplane mode is on and Wi-Fi is off.", KitType.small)
        }
    }
}

/** Home (docs/mobile-apps.md, step 4): New seed and Dice-only seed. */
@Composable
fun Home(testRegistry: Boolean, onNewSeed: () -> Unit, onDiceOnly: () -> Unit) {
    KitScreen(
        screenId(Screen.Home),
        testRegistry,
        actions = {
            KitButton("New seed", "new_seed", onClick = onNewSeed)
            KitButton("Dice-only seed", "dice_only_seed", onClick = onDiceOnly)
        },
    ) {
        KitText("KeepCrypt", KitType.title)
        Gap(16)
        KitText("New seed mixes your dice with this phone's own randomness. Dice-only seed uses your rolls alone, as a Coldcard does.", KitType.small)
    }
}

/** Length (docs/mobile-apps.md, step 5): 12 words, the default, or 24. */
@Composable
fun Length(testRegistry: Boolean, onWords: (Words) -> Unit) {
    KitScreen(
        screenId(Screen.Length),
        testRegistry,
        actions = {
            KitButton("12 words (default)", "words_12") { onWords(Words.Twelve) }
            KitButton("24 words", "words_24") { onWords(Words.TwentyFour) }
        },
    ) {
        Heading("How many words?")
        KitText("12 words fill one KeepCrypt Hinge or Screw; 24 words need two.", KitType.small)
    }
}

/**
 * Device entropy, Mixed mode only (docs/mobile-apps.md, step 6, and "Entropy sources on phones"): the
 * default mode's one sentence; touches and the phone's motion go into the pool while it shows, with
 * no credit (the model's touched and its motion source), and Continue makes the commitment, which
 * reads the phone's random source.
 */
@Composable
fun DeviceEntropy(testRegistry: Boolean, onContinue: () -> Unit) {
    KitScreen(
        screenId(Screen.DeviceEntropy),
        testRegistry,
        actions = { KitButton("Continue", "continue", onClick = onContinue) },
    ) {
        Heading("Device entropy")
        KitText(SAFE_IF_EITHER, tag = "device_entropy_sentence")
        KitText(
            "Tap the screen and move the phone if you like: your touches and its motion are mixed in, " +
                "though the seed's safety never rests on them. The phone's own random source is read when " +
                "you continue.",
            KitType.small,
        )
    }
}

/** Commitment, Mixed mode only (docs/mobile-apps.md, step 7; the Pi's step 5): C as 16 groups of 4 hex characters. */
@Composable
fun Commitment(state: UiState, testRegistry: Boolean, onContinue: () -> Unit) {
    KitScreen(
        screenId(Screen.Commitment),
        testRegistry,
        actions = { KitButton("Continue", "continue", onClick = onContinue) },
    ) {
        Heading("Commitment C")
        KitText(state.commitment ?: "", KitType.hex, tag = "commitment_hex")
        KitText("Only verification runs need to write it down.", KitType.small)
    }
}

/**
 * Dice (docs/mobile-apps.md, step 8; the Pi's step 6): the 1 to 6 pad picks a face, Confirm pushes it
 * (disabled with no face picked and at 256 rolls, where the pad is disabled too), Undo takes the last
 * roll back; the screen shows the count and the bits, never the roll history, and says when the
 * minimum is reached (Done comes with the collision check, commit 17). The pick lives in the model's
 * PadEntry, not in Compose state: version only redraws the pick when the pad changes it.
 */
@Composable
fun Dice(state: UiState, pick: PadEntry, testRegistry: Boolean, onConfirm: () -> Unit, onUndo: () -> Unit) {
    val dice = state.dice ?: return
    var version by remember { mutableIntStateOf(0) }
    val open = dice.rolls < MAX_ROLLS
    KitScreen(
        screenId(Screen.Dice),
        testRegistry,
        actions = {
            key(version) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    KitText("Picked")
                    BasicText(
                        if (pick.length == 1) keyLabel(pick.keyAt(0)) else "-",
                        Modifier.padding(horizontal = 16.dp).testTag("dice_pick"),
                        style = KitType.large,
                    )
                }
                DicePad(pick, enabled = open) { version += 1 }
                Row {
                    KitButton("Undo", "undo", enabled = dice.rolls > 0, modifier = Modifier.weight(1f).padding(end = 6.dp), onClick = onUndo)
                    KitButton(
                        "Confirm",
                        "confirm",
                        enabled = open && pick.length == 1,
                        modifier = Modifier.weight(1f).padding(start = 6.dp),
                        onClick = onConfirm,
                    )
                }
            }
        },
    ) {
        Heading("Dice")
        KitText(diceText(dice.rolls, dice.minimum, dice.millibits), tag = "dice_count")
        KitText("Roll a die, tap its face, then Confirm. Earlier rolls are never shown.", KitType.small)
        if (dice.rolls >= dice.minimum) {
            KitText("Minimum reached: more rolls are allowed, up to 256.", tag = "dice_minimum")
        }
        if (!open) {
            KitText("256 rolls: the most a seed takes.", tag = "dice_cap")
        }
        if (state.diceOnly) {
            KitText(DICE_ONLY, KitType.small, tag = "dice_only")
        }
    }
}
