// The encrypted backup (tasks/todo.md, M6 item D6; Android's BackupScreens.kt; docs/mobile-apps.md,
// "Encrypted backup only" and step 13): the offer after the wallet summary, the 8-word passphrase two pages
// of four and its confirm, two questions answered on D3's letter pad (Protected), the save through the
// system's exporter (DocumentPicker.swift), its read-back and "Backup verified"; and (D7) Home's Check a
// backup: the passphrase's entry on the letter pad (Protected), "Backup OK" with the fingerprint and the Seal
// ID, and the re-check QR (Public); in Android's words, order and identifiers. A checked backup's words show
// on the words' own screens (WordsScreens.swift), through the privacy gate. Each hands its presses to the ceremony model, which
// ignores a press its screen no longer shows. The secret text (the passphrase's words, the confirm's
// choices and the letters typed) is read from the Secrets the state holds and the pad's entry as each body
// draws, into a String that lives only for that drawing (Q58; Swift's strings and SwiftUI's drawn text are
// MA:17's residual), and drawn inside SecureLayer (Q88), where Android marks each node secret; no view keeps
// one in its own state. The backup's bytes never reach a view: Save hands them from the model to the
// exporter.

import SwiftUI

/// The backup's offer (docs/mobile-apps.md, step 13; the Pi's backup-offer), a Public screen after the
/// wallet summary: what the file is, that the paper words stay the primary backup, and "Make an encrypted
/// backup" or Skip, which goes on without one.
struct BackupOfferScreen: View {
    let testRegistry: Bool
    let onMake: () -> Void
    let onSkip: () -> Void

    var body: some View {
        KitScreen(Screen.backupOffer.id, testRegistry: testRegistry) {
            Heading(Screen.backupOffer.title)
            KitText(BackupTexts.offer, style: .small)
        } actions: {
            KitButton(BackupTexts.make, id: "make_backup", action: onMake)
            KitButton(CheckTexts.skip, id: "skip_backup", action: onSkip)
        }
    }
}

/// The backup passphrase (pi-firmware.md, USB step 1; the Pi's backup-passphrase), a Protected screen
/// behind the privacy gate: core's 8 words, four a page, each after its number, the page's four lines one
/// text inside SecureLayer, as the Pi draws them in one Protected text; Previous and Next page, and the
/// second page's "I wrote it down" goes on to the confirm. After a wrong confirm it shows again from its
/// first page, saying so.
struct BackupPassphraseScreen: View {
    let state: UiState
    let testRegistry: Bool
    let passGate: () -> Void
    let onPrevious: () -> Void
    let onNext: () -> Void
    let onConfirm: () -> Void

    var body: some View {
        Protected(state: state, testRegistry: testRegistry, passGate: passGate) {
            if let text = state.passphrase {
                let last = state.page == 1
                KitScreen(Screen.backupPassphrase.id, testRegistry: testRegistry) {
                    Heading(Screen.backupPassphrase.title)
                    if state.wrongConfirm {
                        KitText(BackupTexts.wrongConfirm, style: .warning, id: "wrong_confirm")
                    }
                    KitText(BackupTexts.passphraseNote, style: .small)
                    KitText(passphrasePageText(state.page), style: .small, id: "passphrase_page")
                    SecureLayer {
                        Text(passphraseText(state.page, text))
                            .font(KitType.hex)
                            .foregroundColor(KitColors.text)
                            .lineSpacing(10)
                            .padding(.vertical, 6)
                            .secretIdentifier(.passphraseText)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                } actions: {
                    KitPair {
                        KitButton(WordsTexts.previous, id: "previous", enabled: last, action: onPrevious)
                        KitButton(WordsTexts.next, id: "next", enabled: !last, action: onNext)
                    }
                    if last {
                        KitButton(BackupTexts.written, id: "passphrase_written", action: onConfirm)
                    }
                }
            }
        }
    }
}

/// The passphrase's confirm (pi-firmware.md, USB step 2; the Pi's backup-confirm), a Protected screen:
/// question page + 1 of two, "Which is word N?", core's four choices two a row inside SecureLayer, and the
/// answer typed on the letter pad, its first four letters or a whole three-letter word, so no choice is a
/// button that names its word; Delete, and Done at three or four letters. The letters live in the model's
/// PadEntry, observed here.
struct BackupConfirmScreen: View {
    let state: UiState
    @ObservedObject var letters: PadEntry
    let testRegistry: Bool
    let passGate: () -> Void
    let onKey: (Character) -> Void
    let onDelete: () -> Void
    let onDone: () -> Void

    var body: some View {
        Protected(state: state, testRegistry: testRegistry, passGate: passGate) {
            if let questions = state.challenge?.questions, questions.indices.contains(state.page) {
                let question = questions[state.page]
                KitScreen(Screen.backupConfirm.id, testRegistry: testRegistry) {
                    KitText(confirmQuestionText(state.page), style: .small, id: "confirm_question")
                    Heading(whichWordText(question.position))
                    SecureLayer {
                        VStack(alignment: .leading, spacing: 0) {
                            ForEach(Array(stride(from: 0, to: question.choices.count, by: 2)), id: \.self) { first in
                                HStack(spacing: 0) {
                                    ForEach(first..<min(first + 2, question.choices.count), id: \.self) { index in
                                        Text(choiceText(question.choices[index]))
                                            .secretIdentifier(.confirmChoice)
                                            .font(KitType.hex)
                                            .wholeLines()
                                            .foregroundColor(KitColors.text)
                                            .padding(.vertical, 4)
                                            .frame(maxWidth: .infinity, alignment: .leading)
                                    }
                                }
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    KitText(BackupTexts.confirmHow, style: .small)
                } actions: {
                    LetterEntry(letters: letters, done: "confirm_done", onKey: onKey, onDelete: onDelete, onDone: onDone)
                }
            }
        }
    }
}

/// The letters typed (inside SecureLayer) and the letter pad, Delete and Done (at three or four letters), as
/// the read-back entry has them: the confirm's and Check a backup's entry (D7). Delete is enabled while
/// canDelete (Check a backup's also reopens the word before).
struct LetterEntry: View {
    @ObservedObject var letters: PadEntry
    let done: String
    let onKey: (Character) -> Void
    let onDelete: () -> Void
    let onDone: () -> Void
    var canDelete: Bool?

    var body: some View {
        SecureLayer {
            Text(typedFaces(letters))
                .font(.system(size: KitType.scaled(48), weight: .bold, design: .monospaced))
                .wholeLines()
                .foregroundColor(KitColors.text)
                .padding(.vertical, 6)
                .secretIdentifier(.typedLetters)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        LetterPad(onKey: onKey)
        KitPair {
            KitButton(CheckTexts.delete, id: "letters_delete", enabled: canDelete ?? (letters.length > 0), action: onDelete)
            KitButton(StartTexts.done, id: done, enabled: letters.length >= readbackMinLetters, action: onDone)
        }
    }
}

/// The save (docs/mobile-apps.md, "Saving", steps 2-5), a Public screen once core has encrypted the backup
/// in memory: core's suggested name, MA:156's cloud-folder line, and Save, which opens the system's
/// exporter; the bytes are written there once, read back and verified by core before "Backup verified". A
/// failed save names its step, and Save again or Skip; the session stays.
struct BackupSaveScreen: View {
    let state: UiState
    let testRegistry: Bool
    let onSave: () -> Void
    let onSkip: () -> Void

    var body: some View {
        if let name = state.backupName {
            let failure = state.saveFailure
            KitScreen(Screen.backupSave.id, testRegistry: testRegistry) {
                Heading(Screen.backupSave.title)
                if let failure {
                    KitText(saveFailureText(failure), style: .warning, id: "save_failure")
                    KitText(BackupTexts.saveAgainNote, style: .small)
                }
                KitText(BackupTexts.theFile, style: .small)
                KitText(name, id: "backup_name")
                KitText(BackupTexts.saveHow, style: .small)
                KitText(BackupTexts.cloudFolder, style: .small, id: "cloud_folder")
            } actions: {
                KitButton(failure == nil ? BackupTexts.save : BackupTexts.saveAgain, id: "save_backup", action: onSave)
                KitButton(CheckTexts.skip, id: "skip_backup", action: onSkip)
            }
        }
    }
}

/// "Backup verified" (the Pi's backup-verified), a Public screen: the file read back opened; Next goes on.
struct BackupVerifiedScreen: View {
    let testRegistry: Bool
    let onNext: () -> Void

    var body: some View {
        KitScreen(Screen.backupVerified.id, testRegistry: testRegistry) {
            Heading(Screen.backupVerified.title)
            KitText(BackupTexts.verified, style: .small)
        } actions: {
            KitButton(WordsTexts.next, id: "backup_next", action: onNext)
        }
    }
}

/// Check a backup's passphrase entry (docs/mobile-apps.md, "Checking a backup"; the Pi's backup-check-entry,
/// Q32 (b)), a Protected screen behind the privacy gate: word page + 1 of 8, each its first four letters on
/// the letter pad, or a whole three-letter word; after the eighth core opens the file. Delete on word N > 1's
/// empty pad reopens word N - 1 (the model's padDelete). A refusal shows core's text with the instruction
/// under it, the entry emptied from word 1; Back goes Home, wiping the file read and the letters typed.
struct BackupCheckEntryScreen: View {
    let state: UiState
    @ObservedObject var letters: PadEntry
    let testRegistry: Bool
    let passGate: () -> Void
    let onKey: (Character) -> Void
    let onDelete: () -> Void
    let onDone: () -> Void
    let onBack: () -> Void

    var body: some View {
        Protected(state: state, testRegistry: testRegistry, passGate: passGate) {
            KitScreen(Screen.backupCheckEntry.id, testRegistry: testRegistry) {
                Heading(Screen.backupCheckEntry.title)
                KitText(entryWordText(state.page), style: .small, id: "entry_word")
                if let refusal = state.entryRefusal {
                    KitText(backupRefusalText(refusal) ?? "", style: .warning, id: "entry_refusal")
                }
                KitText(CheckBackupTexts.firstFours, style: .small)
            } actions: {
                LetterEntry(
                    letters: letters, done: "entry_done", onKey: onKey, onDelete: onDelete, onDone: onDone,
                    canDelete: letters.length > 0 || state.page > 0)
                KitButton(CheckTexts.back, id: "back", action: onBack)
            }
        }
    }
}

/// Check a backup's result (docs/mobile-apps.md, "Checking a backup"; the Pi's backup-check-result), a Public
/// screen: "Backup OK", the backup's fingerprint and its Seal ID; "Show the words" (through the privacy gate,
/// on the words' screens), "Re-check QR" and Done, which wipes the backup's words in core and returns Home.
struct BackupCheckResultScreen: View {
    let state: UiState
    let testRegistry: Bool
    let onShowWords: () -> Void
    let onRecheck: () -> Void
    let onDone: () -> Void

    var body: some View {
        if let opened = state.opened {
            KitScreen(Screen.backupCheckResult.id, testRegistry: testRegistry) {
                Heading(CheckBackupTexts.backupOk)
                KitText(WordsTexts.fingerprint, style: .small)
                KitText(fingerprintHex(opened.fingerprint), style: .hex, id: "backup_fingerprint")
                KitText(CheckBackupTexts.sealId, style: .small)
                KitText(opened.seal.sealId, style: .hex, id: "backup_seal_id")
                KitText(CheckBackupTexts.okNote, style: .small)
            } actions: {
                KitButton(CheckBackupTexts.showWords, id: "show_backup_words", action: onShowWords)
                KitButton(CheckBackupTexts.recheck, id: "recheck", action: onRecheck)
                KitButton(StartTexts.done, id: "backup_done", action: onDone)
            }
        }
    }
}

/// The re-check QR (the Pi's backup-check-recheck-qr), a Public screen: the seal's T alone, drawn as the
/// check QR is; Back returns to the result.
struct BackupRecheckScreen: View {
    let state: UiState
    let testRegistry: Bool
    let onBack: () -> Void

    var body: some View {
        if let opened = state.opened {
            KitScreen(Screen.backupRecheck.id, testRegistry: testRegistry) {
                Heading(Screen.backupRecheck.title)
                QrCodeView(matrix: opened.recheck, kind: .recheck)
                    .frame(maxWidth: .infinity)
                Gap(8)
                KitText(CheckBackupTexts.recheckNote, style: .small)
            } actions: {
                KitButton(CheckTexts.back, id: "back", action: onBack)
            }
        }
    }
}
