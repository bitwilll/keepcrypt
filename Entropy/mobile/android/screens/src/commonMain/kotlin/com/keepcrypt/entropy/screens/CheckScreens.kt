package com.keepcrypt.entropy.screens

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.keepcrypt.entropy.ffi.Freshness
import com.keepcrypt.entropy.ffi.RegistryHeader

// The collision check (tasks/todo.md, M5 group 16; docs/mobile-apps.md, step 9;
// docs/seal-watchonly-braille.md, "Checking the seal", whose prompt and results these use word for
// word; the Pi's wording, pi/app's screens.rs, wherever those say nothing else): the prompt, Skip's
// confirm, the seal card with its check QR and the checker's answers, the code entry on the Crockford
// pad, Match found's and Cannot check's confirms, the collision result and its report QR (the first
// Protected screen), and the result before the words. Each hands its presses to the ceremony model,
// which ignores a press its screen no longer shows. The camera's "Scan go-ahead QR" comes with its
// screen (commit 18) and the result's way on to the words with theirs (commit 19), so no control here
// leads nowhere (lead decision M5-48).

/** The prompt's question (swb's prompt, the same words on the Pi and the phones). */
const val CHECK_QUESTION = "Check for collisions before you see your words?"

/** The prompt's explanation (swb's prompt). */
const val CHECK_PROMPT = "KeepCrypt can compare this new wallet's seal with the public KeepCrypt registry. If anyone " +
    "has ever registered the same seal, your seed is not unique: it will be destroyed without being shown, and " +
    "you will make a new one."

/** Skip's confirm (the Pi's): Skip exists only before a check starts (rule 6). */
const val SKIP_CONFIRM = "The words will be shown without a collision check. Skip is offered only now: once a " +
    "check starts, only a verified go-ahead shows the words."

/** The result after Skip (swb's "Results": the words come with this note). */
const val SKIPPED = "You skipped the check: the seal can be checked later from the words."

/** The seal card's answers (the Pi's): which of its actions each of the checker's answers takes. */
const val CHECK_ACTIONS = "Go ahead: type its code. Stop: Match found. A network or snapshot error: Cannot check."

/** A refused go-ahead code: the check stays open, with the same seal card and nonce (the code entry's Back). */
const val CODE_REFUSED = "Code not accepted. Check the code on your checker and type it again: the check stays open."

/** The collision result (swb's "Results", Stop). */
const val COLLISION_FOUND = "Collision found. This seed is not unique and has been destroyed."

/** swb's suggestion after a collision: a report to the security address (SECURITY.md) and a verification run. */
const val COLLISION_SUSPECT = "A genuine collision means this phone's randomness or this app is suspect: report the " +
    "phone model and the app's version to admin@keepcrypt.com, and make a verification run with the offline verifier."

/** What the collision report is for (swb's "Reporting a collision"). */
const val REPORT_NOTE = "Scan it on a second device to report the collision: registering this destroyed seed's code " +
    "raises the seal's count, so the earlier owner's next re-check shows the alarm. The destroyed seed is never " +
    "used, so sharing its code is harmless."

/** A Stale snapshot's warning (swb:120: phones warn from day 31; a warning, never a refusal). */
const val STALE_WARNING = "This snapshot is more than 30 days old: seals registered since it was made are not in it."

/** A Future snapshot's warning: its date is after today's on this phone. */
const val FUTURE_WARNING = "This snapshot is dated after today on this phone: check the phone's date."

/** A QR code's side on the phone: the seal's 240 dp, inside a 320 dp phone's margins. */
const val QR_SIDE_DP = 240

/** A registry date (YYYYMMDD) as the Pi writes it: 2026-03-01. */
fun registryDate(date: Int): String {
    val year = (date / 10_000).toString().padStart(4, '0')
    val month = (date / 100 % 100).toString().padStart(2, '0')
    val day = (date % 100).toString().padStart(2, '0')
    return "$year-$month-$day"
}

/** A loaded snapshot's line (the Pi's): its number, date and entry count. */
fun snapshotLine(header: RegistryHeader): String =
    "Snapshot No. ${header.number}, dated ${registryDate(header.date)}, ${header.count} entries."

/** The freshness warning a phone gives (lessons 3; swb:120), or none for a Current snapshot. */
fun freshnessWarning(freshness: Freshness): String? = when (freshness) {
    Freshness.Current -> null
    Freshness.Stale -> STALE_WARNING
    Freshness.Future -> FUTURE_WARNING
}

/**
 * The result of a verified go-ahead (swb's "Results"): as of the loaded snapshot's date, or, after a
 * typed code, as of the date the checker showed, which the phone cannot know.
 */
fun clearText(sealId: String, registry: RegistryHeader?): String = if (registry == null) {
    "No collision for seal $sealId, as of the date your checker showed."
} else {
    "No collision for seal $sealId as of ${registryDate(registry.date)}."
}

/** The code entry's code: the symbols typed, an underscore for each still to come, a dash after the fourth (the checker's two groups). */
fun codeShown(code: PadEntry): String = buildString(code.capacity + 1) {
    for (index in 0 until code.capacity) {
        if (index == code.capacity / 2) append('-')
        append(if (index < code.length) code.keyAt(index) else '_')
    }
}

/**
 * The check prompt (swb's prompt), right after the dice and before any word: the question and why,
 * this seed's seal card (its Seal ID to compare before the check, as the owner's drills do), and "Check
 * now (recommended)" and "Skip".
 */
@Composable
fun CheckPrompt(state: UiState, testRegistry: Boolean, onCheckNow: () -> Unit, onSkip: () -> Unit) {
    KitScreen(
        screenId(Screen.CheckPrompt),
        testRegistry,
        actions = {
            KitButton("Check now (recommended)", "check_now", onClick = onCheckNow)
            KitButton("Skip", "skip", onClick = onSkip)
        },
    ) {
        Heading("Check for collisions")
        KitText(CHECK_QUESTION)
        KitText(CHECK_PROMPT, KitType.small)
        val seal = state.seal
        if (seal != null) {
            Gap(16)
            Centred { SealCardImage(seal) }
        }
    }
}

/** Skip's confirm screen. */
@Composable
fun SkipConfirm(testRegistry: Boolean, onSkip: () -> Unit, onBack: () -> Unit) {
    OneWayConfirm(screenId(Screen.SkipConfirm), testRegistry, "Skip the check?", SKIP_CONFIRM, "Skip the check", onSkip, onBack)
}

/**
 * The seal card (swb's "The seal card"; the Pi's three pages and actions page on one screen): the seal
 * at 240 dp with its Seal ID and braille, the check QR (T and this check's nonce) for the registry
 * website or the offline checker app, and the checker's answers: "Type go-ahead code", "Match found"
 * and "Cannot check", each of the last two confirmed on its own screen.
 */
@Composable
fun SealCardScreen(state: UiState, testRegistry: Boolean, onTypeCode: () -> Unit, onMatchFound: () -> Unit, onCannotCheck: () -> Unit) {
    KitScreen(
        screenId(Screen.SealCard),
        testRegistry,
        actions = {
            KitButton("Type go-ahead code", "type_code", onClick = onTypeCode)
            KitButton("Match found", "match_found", onClick = onMatchFound)
            KitButton("Cannot check", "cannot_check", onClick = onCannotCheck)
        },
    ) {
        Heading("Seal card")
        KitText(
            "Scan the check QR with the registry website or the offline checker app, and compare the seal it draws " +
                "with this one.",
            KitType.small,
        )
        val seal = state.seal
        if (seal != null) {
            Centred { SealCardImage(seal) }
        }
        Gap(16)
        val request = state.checkRequest
        if (request != null) {
            Centred { QrCode(request, QR_SIDE_DP.dp) }
        }
        Gap(8)
        KitText(CHECK_ACTIONS, KitType.small)
    }
}

/**
 * The go-ahead code (the Pi's code entry, on the Crockford pad): the code as typed, in the checker's
 * two groups, Delete, Done once all 8 symbols are typed, and Back to the seal card with the same check
 * and nonce, the typed code wiped. A refused code says so here and is wiped; the check stays. The code
 * lives in the model's PadEntry, not in Compose state: version redraws it when the pad, Delete or Done
 * change it.
 */
@Composable
fun CodeEntry(state: UiState, code: PadEntry, testRegistry: Boolean, onDone: () -> Unit, onBack: () -> Unit) {
    var version by remember { mutableIntStateOf(0) }
    KitScreen(
        screenId(Screen.CodeEntry),
        testRegistry,
        actions = {
            if (state.codeRefused) {
                KitText(CODE_REFUSED, KitType.body.copy(color = KitColors.warning), tag = "code_refused")
            }
            key(version) {
                BasicText(
                    codeShown(code),
                    Modifier.padding(vertical = 6.dp).testTag("code"),
                    style = KitType.large.copy(fontFamily = FontFamily.Monospace),
                )
                CrockfordPad(code) { version += 1 }
                Row {
                    KitButton("Delete", "code_delete", enabled = code.length > 0, modifier = Modifier.weight(1f).padding(end = 6.dp)) {
                        code.delete()
                        version += 1
                    }
                    KitButton("Done", "code_done", enabled = code.isFull, modifier = Modifier.weight(1f).padding(start = 6.dp)) {
                        onDone()
                        version += 1
                    }
                }
            }
            KitButton("Back", "back", onClick = onBack)
        },
    ) {
        Heading("Go-ahead code")
        KitText("Type the 8-character code your checker shows.", KitType.small)
    }
}

/** Match found's confirm screen: only after the checker's Stop. */
@Composable
fun MatchFoundConfirm(testRegistry: Boolean, onDestroy: () -> Unit, onBack: () -> Unit) {
    OneWayConfirm(
        screenId(Screen.MatchFoundConfirm),
        testRegistry,
        "Match found?",
        "Only when your checker said Stop: the seed is destroyed without being shown.",
        "Destroy this seed",
        onDestroy,
        onBack,
    )
}

/** Cannot check's confirm screen. */
@Composable
fun CannotCheckConfirm(testRegistry: Boolean, onStartAgain: () -> Unit, onBack: () -> Unit) {
    OneWayConfirm(
        screenId(Screen.CannotCheckConfirm),
        testRegistry,
        "Cannot check?",
        "The seed is destroyed without being shown, and a new ceremony starts.",
        "Start again",
        onStartAgain,
        onBack,
    )
}

/**
 * The collision result (swb's "Results", Stop): the seed was wiped unseen, by the loaded snapshot's
 * check (its number, date and any warning shown) or by Match found; swb's suggestion of a report and a
 * verification run; then the report QR, behind the privacy gate.
 */
@Composable
fun CollisionResult(state: UiState, testRegistry: Boolean, onShowReport: () -> Unit) {
    KitScreen(
        screenId(Screen.Collision),
        testRegistry,
        actions = { KitButton("Show the collision report", "show_report", onClick = onShowReport) },
    ) {
        Heading("Collision")
        KitText(COLLISION_FOUND, tag = "collision_text")
        RegistryLines(state.registry)
        KitText(COLLISION_SUSPECT, KitType.small)
        KitText("Next: the collision report QR, then fresh entropy with at least 99 rolls.", KitType.small)
    }
}

/**
 * The collision-report QR (swb's "Reporting a collision"), a Protected screen (it carries the destroyed
 * seed's seal code): behind the privacy gate, hidden while a recording is reported, covered after 30 s
 * without input, and leaving the app on it discards at once (Q57 (b)). "Add fresh entropy" starts a new
 * ceremony from the kept Wiped, which needs at least 99 rolls.
 */
@Composable
fun CollisionReport(state: UiState, testRegistry: Boolean, passGate: () -> Unit, onAddFreshEntropy: () -> Unit) {
    Protected(state, testRegistry, passGate, gateAction = "I'm alone, show the report") {
        KitScreen(
            screenId(Screen.CollisionReport),
            testRegistry,
            actions = { KitButton("Add fresh entropy", "add_fresh_entropy", onClick = onAddFreshEntropy) },
        ) {
            Heading("Report collision")
            val report = state.report
            if (report != null) {
                Centred { QrCode(report, QR_SIDE_DP.dp) }
            }
            Gap(8)
            KitText(REPORT_NOTE, KitType.small)
        }
    }
}

/**
 * The result before the words (swb's "Results"): Go ahead, verified against the loaded snapshot (its
 * number, date and any warning shown before the privacy gate) or by the typed code; or Skip's note. Its
 * way on, the privacy gate and the words, comes with them (commit 19).
 */
@Composable
fun CheckResult(state: UiState, testRegistry: Boolean) {
    KitScreen(screenId(Screen.CheckResult), testRegistry) {
        Heading(if (state.skipped) "Check skipped" else "Check passed")
        val text = if (state.skipped) SKIPPED else clearText(state.seal?.sealId.orEmpty(), state.registry)
        KitText(text, tag = "check_result_text")
        RegistryLines(state.registry)
    }
}

/** A loaded snapshot's line and its freshness warning, when the check ran against one. */
@Composable
private fun RegistryLines(registry: RegistryHeader?) {
    if (registry == null) return
    KitText(snapshotLine(registry), KitType.small, tag = "snapshot_line")
    val warning = freshnessWarning(registry.freshness)
    if (warning != null) {
        KitText(warning, KitType.body.copy(color = KitColors.warning), tag = "snapshot_warning")
    }
}

/** content centred across the screen's text column. */
@Composable
private fun Centred(content: @Composable () -> Unit) {
    Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
        content()
    }
}
