// The collision check and Load registry snapshot's result (tasks/todo.md, M6 item D4; Android's
// CheckScreens.kt and HomeScreens.kt's SnapshotResult; docs/mobile-apps.md, step 9;
// docs/seal-watchonly-braille.md, "Checking the seal", word for word): the prompt, Skip's confirm, the seal
// card, its check QR with the checker's answers, the scan screen, the code entry on the Crockford pad, Match
// found's and Cannot check's confirms, the collision result and its report QR (the first Protected screen),
// and the result before the words. Each hands its presses to the ceremony model, which ignores a press its
// screen no longer shows.

import SwiftUI

/// The check prompt, right after the dice and before any word: the question and why, and "Check now
/// (recommended)" and "Skip" only. It draws no seal card (lead decision M5-55).
struct CheckPromptScreen: View {
    let testRegistry: Bool
    let onCheckNow: () -> Void
    let onSkip: () -> Void

    var body: some View {
        KitScreen(Screen.checkPrompt.id, testRegistry: testRegistry) {
            Heading(Screen.checkPrompt.title)
            KitText(CheckTexts.question)
            KitText(CheckTexts.prompt, style: .small)
        } actions: {
            KitButton(CheckTexts.checkNow, id: "check_now", action: onCheckNow)
            KitButton(CheckTexts.skip, id: "skip", action: onSkip)
        }
    }
}

/// The seal card: the seal at 240 points with its Seal ID and braille, and "Show check QR", its next page.
/// The check has started, so Back does nothing here.
struct SealCardScreen: View {
    let state: UiState
    let testRegistry: Bool
    let onShowCheckQr: () -> Void

    var body: some View {
        KitScreen(Screen.sealCard.id, testRegistry: testRegistry) {
            Heading(Screen.sealCard.title)
            KitText(CheckTexts.sealCardNote, style: .small)
            if let seal = state.seal {
                SealCardImage(card: seal).frame(maxWidth: .infinity)
            }
        } actions: {
            KitButton(CheckTexts.showCheckQr, id: "show_check_qr", action: onShowCheckQr)
        }
    }
}

/// The seal card's check QR (T and this check's nonce) above the checker's answers, two to a row: "Scan
/// go-ahead QR", "Type go-ahead code", "Match found" and "Cannot check". Back returns to the seal card,
/// with the same check and nonce: its own button here (U3b: Android's is the system Back, which an iPhone
/// has not, and this screen's note says "compare ... with the seal card (Back)").
struct CheckQrScreen: View {
    let state: UiState
    let testRegistry: Bool
    let onScan: () -> Void
    let onTypeCode: () -> Void
    let onMatchFound: () -> Void
    let onCannotCheck: () -> Void
    let onBack: () -> Void

    var body: some View {
        KitScreen(Screen.checkQr.id, testRegistry: testRegistry) {
            Heading(Screen.checkQr.title)
            if let request = state.checkRequest {
                QrCodeView(matrix: request, kind: .checkRequest)
                    .frame(maxWidth: .infinity)
                    .accessibilityIdentifier("check_request")
            }
            Gap(8)
            KitText(CheckTexts.checkQrNote, style: .small)
            KitText(CheckTexts.actions, style: .small)
        } actions: {
            KitPair(CheckTexts.scanQr, CheckTexts.typeCode) {
                KitButton(CheckTexts.scanQr, id: "scan_qr", action: onScan)
                KitButton(CheckTexts.typeCode, id: "type_code", action: onTypeCode)
            }
            KitPair(CheckTexts.matchFound, CheckTexts.cannotCheck) {
                KitButton(CheckTexts.matchFound, id: "match_found", action: onMatchFound)
                KitButton(CheckTexts.cannotCheck, id: "cannot_check", action: onCannotCheck)
            }
            KitButton(CheckTexts.back, id: "back", action: onBack)
        }
    }
}

/// The scan screen: the checker's go-ahead QR read with the camera, which nothing here draws (no preview):
/// the screen only says how to aim and what the scan does. Its scanner runs while the screen shows
/// uncovered and has not stopped: it starts as the screen opens, asking for the camera then, stops under
/// the cover or the idle warning and starts again when that goes, and stops when the screen leaves. Its
/// first text goes to onText (the model's onGoAheadText, which core checks behind "Working..."), and a stop
/// without a code to onStopped. After a refused camera the iPhone adds "Open Settings" (iOS never asks
/// again), the gate's one settings call.
struct ScanScreen: View {
    let state: UiState
    let scanner: QrScanner
    let testRegistry: Bool
    let onText: (String) -> Void
    let onStopped: (ScanStop) -> Void
    let onTypeCode: () -> Void
    let onBack: () -> Void

    private var scanning: Bool {
        state.overlay == nil && state.scanStop == nil && state.scanRefusal == nil
    }

    var body: some View {
        let line = scanLine(state)
        KitScreen(Screen.scan.id, testRegistry: testRegistry) {
            Heading(Screen.scan.title)
            KitText(CheckTexts.scanGuide)
            KitText(line, style: line == CheckTexts.scanning ? .small : .warning, id: "scan_line")
        } actions: {
            if state.scanStop == .refused {
                KitButton(CheckTexts.openSettings, id: "open_settings") { OpenSettings.show() }
            }
            KitButton(CheckTexts.typeCode, id: "type_code", action: onTypeCode)
            KitButton(CheckTexts.back, id: "back", action: onBack)
        }
        .onChange(of: scanning, initial: true) { _, now in
            if now {
                scanner.start(found: onText, stopped: onStopped)
            } else {
                scanner.stop()
            }
        }
        .onDisappear { scanner.stop() }
    }
}

/// The go-ahead code on the Crockford pad: the code as typed, in the checker's two groups, Delete, Done
/// once all 8 symbols are typed, and Back to the check QR with the same check and nonce, the typed code
/// wiped. A refused code says so here and is wiped; the check stays.
struct CodeEntryScreen: View {
    let state: UiState
    @ObservedObject var code: PadEntry
    let testRegistry: Bool
    let onKey: (Character) -> Void
    let onDelete: () -> Void
    let onDone: () -> Void
    let onBack: () -> Void

    var body: some View {
        KitScreen(Screen.codeEntry.id, testRegistry: testRegistry) {
            Heading(Screen.codeEntry.title)
            KitText(CheckTexts.codeHow, style: .small)
        } actions: {
            if state.codeRefused {
                KitText(CheckTexts.codeRefused, style: .warning, id: "code_refused")
            }
            Text(codeShown(code))
                .font(.system(size: KitType.scaled(48), weight: .bold, design: .monospaced))
                .wholeLines()
                .foregroundColor(KitColors.text)
                .padding(.vertical, 6)
                .accessibilityIdentifier("code")
            CrockfordPad(onKey: onKey)
            KitPair(CheckTexts.delete, StartTexts.done) {
                KitButton(CheckTexts.delete, id: "code_delete", enabled: code.length > 0, action: onDelete)
                KitButton(StartTexts.done, id: "code_done", enabled: code.isFull, action: onDone)
            }
            KitButton(CheckTexts.back, id: "back", action: onBack)
        }
    }
}

/// A loaded snapshot's line, or a scanned go-ahead QR's (proof), and the freshness warning, when the check
/// ran against one.
struct RegistryLines: View {
    let registry: RegistryHeader?
    let proof: Bool

    var body: some View {
        if let registry {
            if proof {
                KitText(proofLine(registry), style: .small, id: "proof_line")
            } else {
                KitText(snapshotLine(registry), style: .small, id: "snapshot_line")
            }
            if let warning = freshnessWarning(registry.freshness) {
                KitText(warning, style: .warning, id: "snapshot_warning")
            }
        }
    }
}

/// The collision result (swb's "Results", Stop): the seed was wiped unseen; the registry it was found in;
/// the destroyed seed's seal (public); swb's suggestion of a report and a verification run; then the report
/// QR, behind the privacy gate.
struct CollisionScreen: View {
    let state: UiState
    let testRegistry: Bool
    let onShowReport: () -> Void

    var body: some View {
        KitScreen(Screen.collision.id, testRegistry: testRegistry) {
            Heading(Screen.collision.title)
            KitText(CheckTexts.collisionFound, id: "collision_text")
            RegistryLines(registry: state.registry, proof: state.proof)
            if let seal = state.seal {
                Gap(16)
                SealCardImage(card: seal).frame(maxWidth: .infinity)
                Gap(16)
            }
            KitText(CheckTexts.collisionSuspect, style: .small)
            KitText(CheckTexts.collisionNext, style: .small)
        } actions: {
            KitButton(CheckTexts.showReport, id: "show_report", action: onShowReport)
        }
    }
}

/// The collision-report QR, a Protected screen (it carries the destroyed seed's seal code): behind the
/// privacy gate, drawn inside SecureLayer (Q88), covered after 30 s without input; "Add fresh entropy"
/// starts a new ceremony from the kept Wiped, which needs at least 99 rolls.
struct CollisionReportScreen: View {
    let state: UiState
    let testRegistry: Bool
    let passGate: () -> Void
    let onAddFreshEntropy: () -> Void

    var body: some View {
        Protected(state: state, testRegistry: testRegistry, passGate: passGate) {
            KitScreen(Screen.collisionReport.id, testRegistry: testRegistry) {
                Heading(Screen.collisionReport.title)
                if let report = state.report {
                    SecureLayer {
                        QrCodeView(matrix: report, kind: .collisionReport)
                    }
                    .frame(width: CGFloat(qrSide), height: CGFloat(qrSide))
                    .frame(maxWidth: .infinity)
                    .accessibilityElement()
                    .accessibilityLabel(QrKind.collisionReport.spoken)
                    .spoken(.qrCode)
                }
                Gap(8)
                KitText(CheckTexts.reportNote, style: .small)
            } actions: {
                KitButton(CheckTexts.addFreshEntropy, id: "add_fresh_entropy", action: onAddFreshEntropy)
            }
        }
    }
}

/// The result before the words: Go ahead, verified against the loaded snapshot, by a scanned go-ahead QR or
/// by the typed code; or Skip's note. "Show words" leads on, through the privacy gate.
struct CheckResultScreen: View {
    let state: UiState
    let testRegistry: Bool
    let onShowWords: () -> Void

    var body: some View {
        KitScreen(Screen.checkResult.id, testRegistry: testRegistry) {
            Heading(state.skipped ? CheckTexts.checkSkipped : CheckTexts.checkPassed)
            KitText(state.skipped ? CheckTexts.skipped : clearText(state.seal?.sealId ?? "", state.registry), id: "check_result_text")
            RegistryLines(registry: state.registry, proof: state.proof)
            KitText(CheckTexts.wordsNext, style: .small)
        } actions: {
            KitButton(CheckTexts.showWords, id: "show_words", action: onShowWords)
        }
    }
}

/// Load registry snapshot's result: the snapshot loaded, with its number, date and count and any Stale or
/// Future warning, or that it was not loaded and why; Done returns Home.
struct SnapshotScreen: View {
    let state: UiState
    let testRegistry: Bool
    let onDone: () -> Void

    var body: some View {
        KitScreen(Screen.snapshot.id, testRegistry: testRegistry) {
            Heading(Screen.snapshot.title)
            if let refusal = state.snapshotRefusal {
                KitText(CheckTexts.snapshotNotLoaded, id: "snapshot_result")
                KitText(snapshotRefusalText(refusal) ?? "", style: .warning, id: "snapshot_refusal")
            } else if let loaded = state.loaded {
                KitText(CheckTexts.snapshotLoaded, id: "snapshot_result")
                KitText(snapshotLine(loaded), style: .small, id: "snapshot_line")
                if let warning = freshnessWarning(loaded.freshness) {
                    KitText(warning, style: .warning, id: "snapshot_warning")
                }
                KitText(CheckTexts.snapshotLoadedNote, style: .small)
            }
        } actions: {
            KitButton(StartTexts.done, id: "snapshot_done", action: onDone)
        }
    }
}
