package com.keepcrypt.entropy.screens

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.keepcrypt.entropy.ffi.Freshness
import com.keepcrypt.entropy.ffi.Refusal
import com.keepcrypt.entropy.ffi.RegistryHeader

// The collision check (tasks/todo.md, M5 group 16; docs/mobile-apps.md, step 9;
// docs/seal-watchonly-braille.md, "Checking the seal", whose prompt and results these use word for
// word; the Pi's wording, pi/app's screens.rs, wherever those say nothing else): the prompt, Skip's
// confirm, the seal card, its check QR with the checker's answers, the scan screen (commit 18), the
// code entry on the Crockford pad, Match found's and Cannot check's confirms, the collision result and
// its report QR (the first Protected screen), and the result before the words, whose "Show words" leads
// on to them (WordsScreens.kt, commit 19). Each hands its presses to the ceremony model, which ignores a
// press its screen no longer shows.

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

/** The check QR's answers (the Pi's, with the phone's scan): which of its actions each of the checker's answers takes. */
const val CHECK_ACTIONS = "Go ahead: scan its QR or type its code. Stop: Match found. A network or snapshot error: " +
    "Cannot check."

/** A refused go-ahead code: the check stays open, with the same check QR and nonce (the code entry's Back). */
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

/**
 * How to aim, on the scan screen, which draws nothing the camera sees (no preview: the window keeps
 * FLAG_SECURE as its one surface).
 */
const val SCAN_GUIDE = "Point the phone at the go-ahead QR your checker shows, about 20-40 cm away, with the whole code " +
    "in view. Nothing the camera sees is shown or kept."

/** The scan screen while its scanner reads. */
const val SCANNING = "Looking for the go-ahead QR..."

/** The scan screen after the camera prompt's refusal: the typed code stays. */
const val SCAN_REFUSED = "The camera was not allowed, so the go-ahead QR cannot be scanned. Type the go-ahead code " +
    "instead: the check stays open."

/** The scan screen on a phone with no camera the app can use (the CI emulators have none). */
const val SCAN_MISSING = "This phone has no camera the app can use. Type the go-ahead code instead: the check stays open."

/** The scan screen after the camera failed or could not be opened. */
const val SCAN_FAILED = "The camera stopped working. Go back and scan again, or type the go-ahead code: the check " +
    "stays open."

/** The scan screen after core refused the scanned text: no go-ahead QR, or another seal's. */
const val SCAN_NOT_ACCEPTED = "That QR code is not the go-ahead for this seal. Go back and scan the go-ahead QR your " +
    "checker shows, or type its code: the check stays open."

/** The scan screen in a build that pins no registry key (the shipping APK until M9), which can check no proof. */
const val SCAN_NO_REGISTRY_KEY = "This build trusts no registry key yet, so it cannot check a go-ahead QR. Type the " +
    "go-ahead code instead: the check stays open."

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

/**
 * A scanned go-ahead QR's line: its snapshot's number and date, and how many entries this seal's bucket
 * holds, the proof's count, never the snapshot's total of seals (lead decision M5-55).
 */
fun proofLine(header: RegistryHeader): String {
    val entries = if (header.count == 1L) "1 entry" else "${header.count} entries"
    return "Proof from snapshot No. ${header.number}, dated ${registryDate(header.date)}: $entries in this seal's bucket."
}

/** What the scan screen says of its scanner: that it reads, or why it stopped, or why core refused its text. */
fun scanLine(state: UiState): String {
    val refusal = state.scanRefusal
    if (refusal != null) return if (refusal == Refusal.NoRegistryKey) SCAN_NO_REGISTRY_KEY else SCAN_NOT_ACCEPTED
    return when (state.scanStop) {
        null -> SCANNING
        ScanStop.Refused -> SCAN_REFUSED
        ScanStop.Missing -> SCAN_MISSING
        ScanStop.Failed -> SCAN_FAILED
    }
}

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
 * The check prompt (swb's prompt, and the Pi's CheckPrompt in pi/app's screens.rs), right after the
 * dice and before any word: the question and why, and "Check now (recommended)" and "Skip" only. It
 * draws no seal card (lead decision M5-55): the Seal ID's first four characters are the bucket a
 * registry lookup takes, so a seal shown beside Skip would let a Stop be read and then skipped past,
 * which swb's "Go-ahead before reveal" rules out. The Seal ID shows from Check now on.
 */
@Composable
fun CheckPrompt(testRegistry: Boolean, onCheckNow: () -> Unit, onSkip: () -> Unit) {
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
    }
}

/** Skip's confirm screen. */
@Composable
fun SkipConfirm(testRegistry: Boolean, onSkip: () -> Unit, onBack: () -> Unit) {
    OneWayConfirm(screenId(Screen.SkipConfirm), testRegistry, "Skip the check?", SKIP_CONFIRM, "Skip the check", onSkip, onBack)
}

/**
 * The seal card (swb's "The seal card"; the Pi's seal pages, PF:93): the seal at 240 dp with its Seal
 * ID and braille, and "Show check QR", its next page. The check has started, so Back does nothing here.
 */
@Composable
fun SealCardScreen(state: UiState, testRegistry: Boolean, onShowCheckQr: () -> Unit) {
    KitScreen(
        screenId(Screen.SealCard),
        testRegistry,
        actions = { KitButton("Show check QR", "show_check_qr", onClick = onShowCheckQr) },
    ) {
        Heading("Seal card")
        KitText("Your checker draws this seal from the check QR on the next page: compare the two.", KitType.small)
        val seal = state.seal
        if (seal != null) {
            Centred { SealCardImage(seal) }
        }
    }
}

/**
 * The seal card's check QR (the Pi's check QR page and actions page, PF:93): the check QR (T and this
 * check's nonce) for the registry website or the offline checker app, wholly on screen above the
 * checker's answers, two to a row: "Scan go-ahead QR" (the scan screen, commit 18), "Type go-ahead
 * code", "Match found" and "Cannot check", each of the last two confirmed on its own screen. Back
 * returns to the seal card, with the same check and nonce.
 */
@Composable
fun CheckQrScreen(
    state: UiState,
    testRegistry: Boolean,
    onScan: () -> Unit,
    onTypeCode: () -> Unit,
    onMatchFound: () -> Unit,
    onCannotCheck: () -> Unit,
) {
    KitScreen(
        screenId(Screen.CheckQr),
        testRegistry,
        actions = {
            Row {
                KitButton("Scan go-ahead QR", "scan_qr", modifier = Modifier.weight(1f).padding(end = 6.dp), onClick = onScan)
                KitButton("Type go-ahead code", "type_code", modifier = Modifier.weight(1f).padding(start = 6.dp), onClick = onTypeCode)
            }
            Row {
                KitButton("Match found", "match_found", modifier = Modifier.weight(1f).padding(end = 6.dp), onClick = onMatchFound)
                KitButton("Cannot check", "cannot_check", modifier = Modifier.weight(1f).padding(start = 6.dp), onClick = onCannotCheck)
            }
        },
    ) {
        Heading("Check QR")
        val request = state.checkRequest
        if (request != null) {
            Centred { QrCode(request, QrKind.CheckRequest, QR_SIDE_DP.dp, Modifier.testTag("check_request")) }
        }
        Gap(8)
        KitText(
            "Scan the check QR with the registry website or the offline checker app, and compare the seal it draws " +
                "with the seal card (Back).",
            KitType.small,
        )
        KitText(CHECK_ACTIONS, KitType.small)
    }
}

/**
 * The scan screen (docs/mobile-apps.md, step 9; swb's "Go-ahead QR"): the checker's go-ahead QR scanned
 * back with the camera, which nothing here draws (no preview, so the window keeps FLAG_SECURE as its one
 * surface): the screen only says how to aim, and what the scan does. Its scanner (the platform's seam)
 * runs while the screen shows uncovered and has not stopped, so it starts as the screen opens, asking
 * for the camera then (the system's prompt, while the app does not hold it), stops under the cover or
 * the idle warning and starts again when that goes, and stops when the screen leaves. Its first text
 * goes to onText (the model's onGoAheadText, which checks it behind "Working..."), and a stop without a
 * code to onStopped. A refused, missing or failed camera, or a text core refused, is said here, and the
 * scanner stays stopped; "Type go-ahead code" and Back (to the check QR, the same check and nonce) stay.
 */
@Composable
fun ScanScreen(
    state: UiState,
    scanner: QrScanner,
    testRegistry: Boolean,
    onText: (String) -> Unit,
    onStopped: (ScanStop) -> Unit,
    onTypeCode: () -> Unit,
    onBack: () -> Unit,
) {
    val scanning = state.overlay == null && state.scanStop == null && state.scanRefusal == null
    DisposableEffect(scanning) {
        if (scanning) scanner.start(onText, onStopped)
        onDispose {
            if (scanning) scanner.stop()
        }
    }
    KitScreen(
        screenId(Screen.Scan),
        testRegistry,
        actions = {
            KitButton("Type go-ahead code", "type_code", onClick = onTypeCode)
            KitButton("Back", "back", onClick = onBack)
        },
    ) {
        Heading("Scan go-ahead QR")
        KitText(SCAN_GUIDE)
        val line = scanLine(state)
        val style = if (line == SCANNING) KitType.small else KitType.body.copy(color = KitColors.warning)
        KitText(line, style, tag = "scan_line", live = true)
    }
}

/**
 * The go-ahead code (the Pi's code entry, on the Crockford pad): the code as typed, in the checker's
 * two groups, Delete, Done once all 8 symbols are typed, and Back to the check QR with the same check
 * and nonce, the typed code wiped. A refused code says so here and is wiped; the check stays. The code
 * lives in the model's PadEntry, whose length is Compose state (Pads.kt): a symbol's press goes to onKey and
 * Delete to onDelete (the model's padKey and padDelete), and only what reads the code redraws when it changes.
 */
@Composable
fun CodeEntry(
    state: UiState,
    code: PadEntry,
    testRegistry: Boolean,
    onKey: (Char) -> Unit,
    onDelete: () -> Unit,
    onDone: () -> Unit,
    onBack: () -> Unit,
) {
    KitScreen(
        screenId(Screen.CodeEntry),
        testRegistry,
        actions = {
            if (state.codeRefused) {
                KitText(CODE_REFUSED, KitType.body.copy(color = KitColors.warning), tag = "code_refused", live = true)
            }
            BasicText(
                codeShown(code),
                Modifier.padding(vertical = 6.dp).testTag("code"),
                style = KitType.large.copy(fontFamily = FontFamily.Monospace),
            )
            CrockfordPad(onKey)
            Row {
                KitButton("Delete", "code_delete", enabled = code.length > 0, modifier = Modifier.weight(1f).padding(end = 6.dp), onClick = onDelete)
                KitButton("Done", "code_done", enabled = code.isFull, modifier = Modifier.weight(1f).padding(start = 6.dp), onClick = onDone)
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
 * check (its number, date and any warning shown), by a scanned go-ahead QR (its snapshot's number and
 * date, the entries in this seal's bucket and any warning) or by Match found; under that text the
 * destroyed seed's seal (public: the grid, the Seal ID the owner's drills compare here, and its braille;
 * lead decision M5-55); swb's suggestion of a report and a verification run; then the report QR, behind
 * the privacy gate.
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
        RegistryLines(state.registry, state.proof)
        val seal = state.seal
        if (seal != null) {
            Gap(16)
            Centred { SealCardImage(seal) }
            Gap(16)
        }
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
    Protected(state, testRegistry, passGate) {
        KitScreen(
            screenId(Screen.CollisionReport),
            testRegistry,
            actions = { KitButton("Add fresh entropy", "add_fresh_entropy", onClick = onAddFreshEntropy) },
        ) {
            Heading("Report collision")
            val report = state.report
            if (report != null) {
                Centred { QrCode(report, QrKind.CollisionReport, QR_SIDE_DP.dp) }
            }
            Gap(8)
            KitText(REPORT_NOTE, KitType.small)
        }
    }
}

/**
 * The result before the words (swb's "Results"): Go ahead, verified against the loaded snapshot (its
 * number, date and any warning shown before the privacy gate), by a scanned go-ahead QR (its snapshot's
 * number and date, the entries in this seal's bucket and any warning, as before the gate) or by the
 * typed code; or Skip's note. "Show words" leads on, through the privacy gate (the Pi's check-clear:
 * "Next: the words, on a private screen").
 */
@Composable
fun CheckResult(state: UiState, testRegistry: Boolean, onShowWords: () -> Unit) {
    KitScreen(
        screenId(Screen.CheckResult),
        testRegistry,
        actions = { KitButton("Show words", "show_words", onClick = onShowWords) },
    ) {
        Heading(if (state.skipped) "Check skipped" else "Check passed")
        val text = if (state.skipped) SKIPPED else clearText(state.seal?.sealId.orEmpty(), state.registry)
        KitText(text, tag = "check_result_text")
        RegistryLines(state.registry, state.proof)
        KitText("Next: the words, on a private screen.", KitType.small)
    }
}

/**
 * A loaded snapshot's line, or a scanned go-ahead QR's (proof), and the freshness warning, when the check
 * ran against one.
 */
@Composable
private fun RegistryLines(registry: RegistryHeader?, proof: Boolean) {
    if (registry == null) return
    if (proof) {
        KitText(proofLine(registry), KitType.small, tag = "proof_line")
    } else {
        KitText(snapshotLine(registry), KitType.small, tag = "snapshot_line")
    }
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
