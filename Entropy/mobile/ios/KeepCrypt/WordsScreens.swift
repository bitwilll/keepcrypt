// The words to the wallet summary (tasks/todo.md, M6 item D5; Android's WordsScreens.kt; docs/mobile-apps.md,
// steps 10-12; docs/seal-watchonly-braille.md, "Braille backup"): the words in insert view and their overview
// (Protected), the device swap between a 24-word seed's two devices, the read-back entry on D3's letter pad
// and its mismatch (Protected), the read-back's end and the wallet summary (Public), in Android's words,
// order and identifiers. Each hands its presses to the ceremony model, which ignores a press its screen no
// longer shows. Every secret (a word, its SeedBook number and faces, an overview line, the letters typed, a
// verdict) is read from the WordPage, PadEntry or Mismatch the model holds, as each body draws, into a
// String that lives only for that drawing (Q58; Swift's strings and SwiftUI's drawn text are MA:17's
// residual), and drawn inside SecureLayer (Q88); no view keeps one in its own state.

import SwiftUI

/// The insert's word large, its letters past the fourth lighter (swb's insert view).
private struct InsertWord: View {
    let insert: WordPage

    var body: some View {
        let word = wordText(insert)
        (Text(String(word.prefix(lighterFrom))).foregroundColor(KitColors.text)
            + Text(String(word.dropFirst(lighterFrom))).foregroundColor(KitColors.muted))
            .font(KitType.large)
            .padding(.vertical, 6)
    }
}

/// The words in insert view (docs/mobile-apps.md, step 10; swb's "On screen"; the Pi's step 8), a Protected
/// screen behind the privacy gate: one insert a page, its position and device, the word large with its
/// letters past the fourth lighter, its SeedBook number, faces 1-5 (blank faces "leave blank", mirror-pair
/// letters "mirror", face 5 lighter) and face 6. Previous and Next page through the inserts, Overview shows
/// four words a page, and the last insert starts the read-back. A mismatch's insert offers only the way
/// back to it. A checked backup's words have no read-back: their last insert's Done returns to the result.
struct WordsInsertScreen: View {
    let state: UiState
    let testRegistry: Bool
    let passGate: () -> Void
    let onPrevious: () -> Void
    let onNext: () -> Void
    let onOverview: () -> Void
    let onReadback: () -> Void
    let onBackToReadback: () -> Void
    let onBackupDone: () -> Void

    var body: some View {
        Protected(state: state, testRegistry: testRegistry, passGate: passGate) {
            if let insert = state.insert {
                let last = state.page + 1 == insert.count
                KitScreen(Screen.words.id, testRegistry: testRegistry) {
                    Heading(Screen.words.title)
                    KitText(insertHeader(insert), style: .small, id: "insert_header")
                    SecureLayer {
                        VStack(alignment: .leading, spacing: 0) {
                            InsertWord(insert: insert)
                            KitText(seedbookText(insert.seedbook))
                            HStack(spacing: 0) {
                                ForEach(1...5, id: \.self) { n in
                                    BrailleFaceView(face: insert.face(n))
                                }
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    KitText(faceSixText(insert.sequence), style: .small, id: "face_six")
                    if state.reviewing {
                        KitText(WordsTexts.reviewing, style: .small)
                    }
                } actions: {
                    if state.reviewing {
                        KitButton(WordsTexts.backToReadback, id: "back_to_readback", action: onBackToReadback)
                    } else {
                        HStack(spacing: 12) {
                            KitButton(WordsTexts.previous, id: "previous", enabled: state.page > 0, action: onPrevious)
                            KitButton(WordsTexts.next, id: "next", enabled: !last, action: onNext)
                        }
                        KitButton(WordsTexts.overview, id: "overview", action: onOverview)
                        if last, state.opened != nil {
                            KitButton(StartTexts.done, id: "backup_words_done", action: onBackupDone)
                        } else if last {
                            KitButton(WordsTexts.startReadback, id: "start_readback", action: onReadback)
                        }
                    }
                }
            }
        }
    }
}

/// The overview (swb's "An overview of four words per page is available for the paper copy"), a Protected
/// screen: four words a page, each with its position and SeedBook number, under the page's word range and
/// device. Previous and Next page, and Insert view shows the page's first insert.
struct WordsOverviewScreen: View {
    let state: UiState
    let testRegistry: Bool
    let passGate: () -> Void
    let onPrevious: () -> Void
    let onNext: () -> Void
    let onInsertView: () -> Void

    var body: some View {
        Protected(state: state, testRegistry: testRegistry, passGate: passGate) {
            if let inserts = state.overview, let first = inserts.first, let last = inserts.last {
                let more = (state.page + 1) * overviewWords < first.count
                KitScreen(Screen.wordsOverview.id, testRegistry: testRegistry) {
                    Heading(Screen.wordsOverview.title)
                    KitText(overviewHeader(first, last), style: .small, id: "overview_header")
                    SecureLayer {
                        VStack(alignment: .leading, spacing: 0) {
                            ForEach(0..<inserts.count, id: \.self) { index in
                                KitText(overviewLine(inserts[index]), style: .hex)
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    KitText(WordsTexts.overviewNote, style: .small)
                } actions: {
                    HStack(spacing: 12) {
                        KitButton(WordsTexts.previous, id: "previous", enabled: state.page > 0, action: onPrevious)
                        KitButton(WordsTexts.next, id: "next", enabled: more, action: onNext)
                    }
                    KitButton(WordsTexts.insertView, id: "insert_view", action: onInsertView)
                }
            }
        }
    }
}

/// The device swap (swb's "24-word seeds"), a Public screen between a 24-word seed's word 12 and word 13:
/// device 1 of 2 is closed and put away before device 2 of 2 is opened. Continue shows word 13's page,
/// through the privacy gate again.
struct DeviceSwapScreen: View {
    let testRegistry: Bool
    let onContinue: () -> Void

    var body: some View {
        KitScreen(Screen.deviceSwap.id, testRegistry: testRegistry) {
            Heading(Screen.deviceSwap.title)
            KitText(WordsTexts.deviceSwapWords, id: "device_swap_text")
            KitText(WordsTexts.deviceSwap, style: .small)
        } actions: {
            KitButton(StartTexts.continueButton, id: "continue", action: onContinue)
        }
    }
}

/// The read-back entry (docs/mobile-apps.md, step 11; swb's "Read-back from the metal", mandatory), a
/// Protected screen: the insert to read back, its position and device, and the faces typed so far on the
/// letter pad, with no suggestion; Delete, and Done at three or four letters. After a match the whole word
/// shows, and Next goes on. The letters live in the model's PadEntry, observed here.
struct ReadbackEntryScreen: View {
    let state: UiState
    @ObservedObject var letters: PadEntry
    let testRegistry: Bool
    let passGate: () -> Void
    let onKey: (Character) -> Void
    let onDelete: () -> Void
    let onDone: () -> Void
    let onNext: () -> Void

    var body: some View {
        Protected(state: state, testRegistry: testRegistry, passGate: passGate) {
            if let insert = state.insert {
                KitScreen(Screen.readbackEntry.id, testRegistry: testRegistry) {
                    Heading(Screen.readbackEntry.title)
                    KitText(readbackHeader(insert), style: .small, id: "readback_header")
                    if state.matched {
                        KitText(WordsTexts.readbackMatched, id: "readback_matched")
                        SecureLayer {
                            InsertWord(insert: insert).frame(maxWidth: .infinity, alignment: .leading)
                        }
                    } else {
                        KitText(WordsTexts.readbackHow, style: .small)
                    }
                } actions: {
                    if state.matched {
                        KitButton(WordsTexts.next, id: "readback_next", action: onNext)
                    } else {
                        SecureLayer {
                            Text(typedFaces(letters))
                                .font(.system(size: 48, weight: .bold, design: .monospaced))
                                .foregroundColor(KitColors.text)
                                .padding(.vertical, 6)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        LetterPad(onKey: onKey)
                        HStack(spacing: 12) {
                            KitButton(CheckTexts.delete, id: "letters_delete", enabled: letters.length > 0, action: onDelete)
                            KitButton(
                                StartTexts.done, id: "letters_done", enabled: letters.length >= readbackMinLetters, action: onDone)
                        }
                    }
                }
            }
        }
    }
}

/// The read-back mismatch, a Protected screen: the insert that does not match, and each of faces 1-4's
/// verdict, core's (a mirror-pair misread named as one), with the Pi's advice. "Read it again" returns to
/// its entry; "Show the insert" shows its page to compare with the metal.
struct ReadbackMismatchScreen: View {
    let state: UiState
    let testRegistry: Bool
    let passGate: () -> Void
    let onAgain: () -> Void
    let onShowInsert: () -> Void

    var body: some View {
        Protected(state: state, testRegistry: testRegistry, passGate: passGate) {
            if let insert = state.insert, let mismatch = state.mismatch {
                KitScreen(Screen.readbackMismatch.id, testRegistry: testRegistry) {
                    Heading(Screen.readbackEntry.title)
                    KitText(mismatchHeader(insert), style: .warning, id: "mismatch_header")
                    SecureLayer {
                        VStack(alignment: .leading, spacing: 0) {
                            ForEach(1...4, id: \.self) { face in
                                KitText(verdictLine(face, mismatch.face(face)))
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    KitText(WordsTexts.mirrors, style: .small)
                } actions: {
                    KitButton(WordsTexts.readAgain, id: "readback_again", action: onAgain)
                    KitButton(WordsTexts.showInsert, id: "review_insert", action: onShowInsert)
                }
            }
        }
    }
}

/// The read-back's end: every insert matched; Next shows the wallet summary.
struct ReadbackDoneScreen: View {
    let testRegistry: Bool
    let onNext: () -> Void

    var body: some View {
        KitScreen(Screen.readbackDone.id, testRegistry: testRegistry) {
            Heading(Screen.readbackDone.title)
            KitText(WordsTexts.readbackComplete)
        } actions: {
            KitButton(WordsTexts.next, id: "show_summary", action: onNext)
        }
    }
}

/// The wallet summary (docs/mobile-apps.md, step 12), a Public screen as the Pi's (Q29): the fingerprint
/// and the first receive address, to compare after any restore.
struct WalletSummaryScreen: View {
    let state: UiState
    let testRegistry: Bool
    let onNext: () -> Void

    var body: some View {
        if let summary = state.summary {
            KitScreen(Screen.wallet.id, testRegistry: testRegistry) {
                Heading(Screen.wallet.title)
                KitText(WordsTexts.fingerprint, style: .small)
                KitText(fingerprintHex(summary.fingerprint), style: .hex, id: "fingerprint")
                KitText(WordsTexts.firstAddress, style: .small)
                KitText(summary.firstAddress, id: "first_address")
                KitText(WordsTexts.compareAfterRestore, style: .small)
            } actions: {
                KitButton(WordsTexts.next, id: "summary_next", action: onNext)
            }
        }
    }
}
