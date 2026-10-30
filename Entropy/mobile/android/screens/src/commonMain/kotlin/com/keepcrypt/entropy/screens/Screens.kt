package com.keepcrypt.entropy.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.changedToDown
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.keepcrypt.entropy.ffi.HaltReason
import com.keepcrypt.entropy.ffi.Mode

/**
 * The app's screens over its ceremony model (tasks/todo.md, M5 groups 6 and 14-16): the screen is a
 * when over the model's state, so no back stack reaches a saved-state Bundle. Every tap first reaches
 * the model (input, the idle timer; touched, which Device entropy mixes in); the cover and the warning
 * lie over the screen and take the tap that removes them, so it reaches nothing under them.
 * airplaneSettings is Go offline's button, scanner the scan screen's go-ahead QR scanner and documents
 * the backup's, Check a backup's and Load registry snapshot's document pickers (the platform's seams,
 * which the save screen's Save and Home's Check a backup and Load registry snapshot hand to the model); onShown reports each screen once it is composed
 * (the capture harness's drawn-screen proof); onClose is the stop screen's "Close app", which ends the
 * process (the platform's). The system Back is the platform's too, and goes to the model's back.
 */
@Composable
fun Screens(
    model: CeremonyModel,
    airplaneSettings: AirplaneSettings,
    scanner: QrScanner,
    documents: DocumentPickers,
    onClose: () -> Unit,
    onShown: (Screen) -> Unit,
) {
    val state by model.state.collectAsState()
    val registry = model.testRegistry
    Box(
        Modifier
            .fillMaxSize()
            .background(KitColors.background)
            .pointerInput(model) {
                awaitPointerEventScope {
                    while (true) {
                        val event = awaitPointerEvent(PointerEventPass.Initial)
                        val down = event.changes.firstOrNull { it.changedToDown() }
                        if (down != null) {
                            model.input()
                            model.touched(down.uptimeMillis)
                        }
                    }
                }
            },
    ) {
        // The system bars' insets are taken here, once, so a screen's own safeDrawingPadding adds none.
        Column(Modifier.fillMaxSize().safeDrawingPadding()) {
            val notice = state.notice
            if (notice != null && !isWorking(state.screen) && state.screen != Screen.Stop) {
                NoticeLine(notice)
            }
            when (state.screen) {
                Screen.SelfTest -> SelfTest(registry)
                Screen.FirstLaunch -> FirstLaunch(registry, onContinue = model::firstLaunchDone)
                Screen.GoOffline -> GoOffline(state, registry, onSettings = airplaneSettings::open, onStart = model::startOffline)
                Screen.Home -> Home(
                    state,
                    registry,
                    onNewSeed = { model.chooseMode(Mode.Mixed) },
                    onDiceOnly = { model.chooseMode(Mode.DiceOnly) },
                    onCheckBackup = { model.checkBackup(documents) },
                    onLoadSnapshot = { model.loadSnapshot(documents) },
                    onAbout = model::about,
                )
                Screen.Length -> Length(registry, onWords = model::chooseLength)
                Screen.DeviceEntropy -> DeviceEntropy(registry, onContinue = model::deviceEntropyDone)
                Screen.Commitment -> Commitment(state, registry, onContinue = model::commitmentDone)
                Screen.Dice -> Dice(
                    state,
                    model.dicePick,
                    registry,
                    onKey = model::padKey,
                    onConfirm = model::confirmRoll,
                    onUndo = model::undoRoll,
                    onDone = model::diceDone,
                )
                Screen.CheckPrompt -> CheckPrompt(registry, onCheckNow = model::checkNow, onSkip = model::skip)
                Screen.SkipConfirm -> SkipConfirm(registry, onSkip = model::skipConfirmed, onBack = model::back)
                Screen.SealCard -> SealCardScreen(state, registry, onShowCheckQr = model::showCheckQr)
                Screen.CheckQr -> CheckQrScreen(
                    state,
                    registry,
                    onScan = model::scanQr,
                    onTypeCode = model::typeCode,
                    onMatchFound = model::matchFound,
                    onCannotCheck = model::cannotCheck,
                )
                Screen.Scan -> ScanScreen(
                    state,
                    scanner,
                    registry,
                    onText = model::onGoAheadText,
                    onStopped = model::scanStopped,
                    onTypeCode = model::typeCode,
                    onBack = model::back,
                )
                Screen.CodeEntry -> CodeEntry(
                    state,
                    model.goAheadCode,
                    registry,
                    onKey = model::padKey,
                    onDelete = model::padDelete,
                    onDone = model::codeDone,
                    onBack = model::back,
                )
                Screen.MatchFoundConfirm -> MatchFoundConfirm(registry, onDestroy = model::matchFoundConfirmed, onBack = model::back)
                Screen.CannotCheckConfirm -> CannotCheckConfirm(registry, onStartAgain = model::cannotCheckConfirmed, onBack = model::back)
                Screen.Collision -> CollisionResult(state, registry, onShowReport = model::showReport)
                Screen.CollisionReport -> CollisionReport(
                    state,
                    registry,
                    passGate = model::passGate,
                    onAddFreshEntropy = model::addFreshEntropy,
                )
                Screen.CheckResult -> CheckResult(state, registry, onShowWords = model::showWords)
                Screen.Words -> WordsInsert(
                    state,
                    registry,
                    passGate = model::passGate,
                    onPrevious = model::previousPage,
                    onNext = model::nextPage,
                    onOverview = model::toOverview,
                    onReadback = model::startReadback,
                    onBackToReadback = model::backToReadback,
                    onBackupDone = model::backupWordsDone,
                )
                Screen.WordsOverview -> WordsOverview(
                    state,
                    registry,
                    passGate = model::passGate,
                    onPrevious = model::previousPage,
                    onNext = model::nextPage,
                    onInsertView = model::toInsertView,
                )
                Screen.DeviceSwap -> DeviceSwap(registry, onContinue = model::swapDone)
                Screen.ReadbackEntry -> ReadbackEntry(
                    state,
                    model.readbackLetters,
                    registry,
                    passGate = model::passGate,
                    onKey = model::padKey,
                    onDelete = model::padDelete,
                    onDone = model::readbackTyped,
                    onNext = model::readbackNext,
                )
                Screen.ReadbackMismatch -> ReadbackMismatch(
                    state,
                    registry,
                    passGate = model::passGate,
                    onAgain = model::readbackAgain,
                    onShowInsert = model::reviewInsert,
                )
                Screen.ReadbackDone -> ReadbackDone(registry, onNext = model::showSummary)
                Screen.Wallet -> WalletSummary(state, registry, onNext = model::summaryDone)
                Screen.BackupOffer -> BackupOffer(registry, onMake = model::makeBackup, onSkip = model::skipBackup)
                Screen.BackupPassphrase -> BackupPassphrase(
                    state,
                    registry,
                    passGate = model::passGate,
                    onPrevious = model::previousPage,
                    onNext = model::nextPage,
                    onConfirm = model::passphraseWritten,
                )
                Screen.BackupConfirm -> BackupConfirm(
                    state,
                    model.backupLetters,
                    registry,
                    passGate = model::passGate,
                    onKey = model::padKey,
                    onDelete = model::padDelete,
                    onDone = model::confirmTyped,
                )
                Screen.BackupSave -> BackupSave(state, registry, onSave = { model.saveBackup(documents) }, onSkip = model::skipBackup)
                Screen.BackupVerified -> BackupVerified(registry, onNext = model::backupVerifiedDone)
                Screen.WatchOffer -> WatchOffer(registry, onShow = model::showWatchOnly, onSkip = model::skipWatchOnly)
                Screen.Bip39Ask -> Bip39Ask(registry, onNone = model::noBip39Passphrase, onPassphrase = model::withBip39Passphrase)
                Screen.Bip39Entry -> Bip39Entry(
                    state,
                    model.bip39Letters,
                    registry,
                    passGate = model::passGate,
                    onKey = model::padKey,
                    onPreviousKeys = model::previousPage,
                    onNextKeys = model::nextPage,
                    onDelete = model::padDelete,
                    onDone = model::bip39Typed,
                    onBack = model::back,
                )
                Screen.WatchSummary -> WatchSummary(state, registry, onNext = model::watchSummaryDone)
                Screen.WatchAccountQr -> WatchAccountQr(state, registry, passGate = model::passGate, onNext = model::nextPage)
                Screen.WatchDescriptorQr -> WatchDescriptorQr(
                    state,
                    registry,
                    passGate = model::passGate,
                    onPrevious = model::previousPage,
                    onDone = model::watchDone,
                )
                Screen.RegisterOffer -> RegisterOffer(registry, onShow = model::showRegistration, onSkip = model::skipRegistration)
                Screen.RegisterQr -> RegisterQr(state, registry, passGate = model::passGate, onNext = model::registrationDone)
                Screen.RevealDOffer -> RevealDOffer(registry, onShow = model::showDeviceLeg, onSkip = model::skipDeviceLeg)
                Screen.RevealD -> RevealD(state, registry, passGate = model::passGate, onNext = model::deviceLegDone)
                Screen.Checklist -> Checklist(state, registry, onFinish = model::finishCeremony)
                Screen.BackupCheckEntry -> BackupCheckEntry(
                    state,
                    model.backupLetters,
                    registry,
                    passGate = model::passGate,
                    onKey = model::padKey,
                    onDelete = model::padDelete,
                    onDone = model::entryTyped,
                    onBack = model::back,
                )
                Screen.BackupCheckResult -> BackupCheckResult(
                    state,
                    registry,
                    onShowWords = model::showBackupWords,
                    onRecheck = model::showRecheck,
                    onDone = model::closeBackup,
                )
                Screen.BackupRecheck -> BackupRecheck(state, registry, onBack = model::back)
                Screen.Snapshot -> SnapshotResult(state, registry, onDone = model::snapshotDone)
                Screen.About -> About(registry, onBack = model::back)
                Screen.Working -> Working(registry)
                Screen.Stop -> Stop(state, registry, onClose = onClose)
            }
        }
        val overlay = state.overlay
        if (overlay != null) {
            OverlayScreen(overlay, registry) { model.dismissOverlay() }
        }
        SideEffect { onShown(state.screen) }
    }
}

/**
 * The Protected wrapper (tasks/todo.md, M5 group 14; docs/mobile-apps.md, "Rules for Claude Code"): a
 * Protected screen's content shows only past the privacy gate, and never while a recording of the
 * screen is reported (a redacted placeholder instead, the second layer under FLAG_SECURE). The gate and
 * the placeholder each fill the screen, so each carries the TEST REGISTRY strip in that build (Q60).
 * Its 30 s cover is the timers', drawn over every screen by Screens. The gate before the words (insert
 * view or overview) also gives the SeedBook's safety rules, as the Pi's does.
 */
@Composable
fun Protected(state: UiState, testRegistry: Boolean, passGate: () -> Unit, content: @Composable () -> Unit) {
    when {
        state.gate -> PrivacyGate(testRegistry, passGate, words = state.screen == Screen.Words || state.screen == Screen.WordsOverview)
        state.recording -> Redacted(testRegistry)
        else -> content()
    }
}

/** "Working...": a long call runs; no input goes anywhere (the model ignores every tap). */
@Composable
fun Working(testRegistry: Boolean) {
    Column(Modifier.fillMaxSize().background(KitColors.background).safeDrawingPadding().testTag(screenId(Screen.Working))) {
        if (testRegistry) {
            TestRegistryStrip()
        }
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            BasicText("Working...", style = KitType.heading)
        }
    }
}

/**
 * The stop screen (docs/mobile-apps.md, "When something fails (Android)"): red, fixed text naming the
 * failure (stopLine, the halt's reason), nothing held, and one action, "Close app", which ends the
 * process; the next start runs the self-test again.
 */
@Composable
fun Stop(state: UiState, testRegistry: Boolean, onClose: () -> Unit) {
    KitScreen(
        screenId(Screen.Stop),
        testRegistry,
        background = KitColors.stop,
        actions = { KitButton("Close app", "close_app", onClick = onClose) },
    ) {
        KitText("KeepCrypt stopped", KitType.title)
        Gap(16)
        KitText(stopLine(state.halt), tag = "halt_reason")
        KitText(
            "Something failed, so everything the session held was wiped. Close the app; its next " +
                "start runs the self-test again before any ceremony.",
        )
    }
}

/**
 * The stop screen's line for why the slot halted (docs/mobile-apps.md:36, pi-firmware.md's "Finish and
 * halts"): one fixed line per reason, built from no data and never from a message; with no reason,
 * internal's.
 */
internal fun stopLine(reason: HaltReason?): String = when (reason) {
    HaltReason.KnownAnswerTest -> "A known-answer test failed."
    HaltReason.EntropySource -> "The entropy source failed."
    HaltReason.HealthTest -> "An entropy health test failed."
    HaltReason.ExportSelfCheck -> "The watch-only export failed its self-check."
    HaltReason.Panic -> "The app's core stopped unexpectedly."
    HaltReason.Internal, null -> "An internal check failed."
}

/**
 * The privacy gate before a Protected screen (docs/mobile-apps.md, "Session lifetime" and step 10;
 * docs/pi-firmware.md's gate): every Protected screen is entered through "I'm alone, show words". Before
 * the words it also gives the SeedBook's safety rules (swb's "enforced in the copy on screen"; the Pi's
 * gate before words-insert) and the warning to use headphones if a screen reader speaks them (swb's
 * "Accessibility").
 */
@Composable
fun PrivacyGate(testRegistry: Boolean, pass: () -> Unit, words: Boolean = false) {
    KitScreen("privacy_gate", testRegistry, actions = { KitButton("I'm alone, show words", "pass_gate", onClick = pass) }) {
        KitText("The next screen shows a secret. No person or camera may see it.")
        if (words) {
            KitText(SEEDBOOK_RULES, KitType.small, tag = "seedbook_rules")
            KitText(HEADPHONES_WARNING, KitType.small, tag = "headphones_warning")
        }
    }
}

/** What a Protected screen shows while a recording of the screen is reported, under the TEST REGISTRY strip in that build. */
@Composable
private fun Redacted(testRegistry: Boolean) {
    Column(Modifier.fillMaxSize().background(KitColors.background).testTag("redacted")) {
        if (testRegistry) {
            TestRegistryStrip()
        }
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            BasicText(
                "Hidden while the screen is recorded. Stop the recording to go on.",
                Modifier.padding(24.dp),
                style = KitType.body.copy(fontSize = KitType.button.fontSize),
            )
        }
    }
}

/**
 * An overlay over the screen: the privacy cover (it hides the screen, and the tap on it only takes it
 * away) or the warning a minute before the idle wipe (the tap on it keeps everything). It fills the
 * window and takes the tap that removes it (anywhere on it, so the tap reaches nothing under it), with
 * its text centred inside the system bars' insets under the TEST REGISTRY strip in that build, as every
 * screen has it (Q60, lead decision M5-51). Both come from this one call, so the strip and the insets
 * are the same code for each and CaptureTest's check of the cover's strip holds for the warning's; only
 * the text is the overlay's own.
 */
@Composable
private fun OverlayScreen(overlay: Overlay, testRegistry: Boolean, dismiss: () -> Unit) {
    val tag = when (overlay) {
        Overlay.Cover -> "cover"
        Overlay.Warning -> "idle_warning"
    }
    Column(Modifier.fillMaxSize().background(KitColors.background).clickable(onClick = dismiss).testTag(tag).safeDrawingPadding()) {
        if (testRegistry) {
            TestRegistryStrip()
        }
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            when (overlay) {
                Overlay.Cover -> BasicText("Tap to show the screen again", style = KitType.body.copy(fontSize = KitType.button.fontSize))
                Overlay.Warning -> BasicText(
                    "No input for 9 minutes. The session is wiped in one minute: tap to keep it.",
                    Modifier.padding(24.dp),
                    style = KitType.body.copy(color = KitColors.warning, fontSize = KitType.button.fontSize),
                )
            }
        }
    }
}

/** Why the last session was wiped, above the start screen. */
@Composable
private fun NoticeLine(notice: Notice) {
    val text = when (notice) {
        Notice.Left -> "The session was wiped: the app was left during it."
        Notice.Offline -> "The session was wiped: the phone went online."
        Notice.Idle -> "The session was wiped after 10 minutes without input."
        Notice.Background -> "The session was wiped after 60 seconds away from the app."
    }
    NoticeBar(text)
}
