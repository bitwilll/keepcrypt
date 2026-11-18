// The exports after the encrypted backup (tasks/todo.md, M6 item D6; Android's ExportScreens.kt;
// docs/mobile-apps.md, steps 14-16; docs/seal-watchonly-braille.md, "Watch-only export" and "Registering a
// new seal"): the watch-only offer, the BIP39 passphrase's question and its entry on the ASCII pad
// (Protected), the watch-only summary (Public, Q29), the account QR for Sparrow and the descriptor QR for
// Bitcoin Core (Protected: each carries the xpub); the registration's offer and its QR (Protected: the seal
// code), once; and, in Mixed mode alone, D's offer, whose text is its warning, and D (Protected) as 16
// groups of 4 hex digits, as C is; in Android's words, order and identifiers. Each hands its presses to the
// ceremony model, which ignores a press its screen no longer shows. Android marks the passphrase typed and D
// secret, and draws the three QR codes unmarked on their Protected screens (named by kind, never by what
// they hold); here every one of them is drawn inside SecureLayer (Q88), as D4's collision report QR is,
// read from the pad's entry, the Secret or the matrix the state holds as each body draws (Q58), and no view
// keeps one in its own state. The summaries' fingerprint and address are public, as Android's.

import SwiftUI

/// The watch-only offer (docs/mobile-apps.md, step 14; the Pi's watch-offer), a Public screen after the
/// backup: what the two QRs are, and "Show watch-only QRs" or Skip, which goes on to the registration.
struct WatchOfferScreen: View {
    let testRegistry: Bool
    let onShow: () -> Void
    let onSkip: () -> Void

    var body: some View {
        KitScreen(Screen.watchOffer.id, testRegistry: testRegistry) {
            Heading(Screen.watchOffer.title)
            KitText(ExportTexts.watchOffer, style: .small)
        } actions: {
            KitButton(ExportTexts.showWatchOnly, id: "show_watch_only", action: onShow)
            KitButton(CheckTexts.skip, id: "skip_watch_only", action: onSkip)
        }
    }
}

/// The BIP39 passphrase's question (swb, "Watch-only export": asked before the export; the Pi's bip39-ask),
/// a Public screen: "No BIP39 passphrase" exports this seed's wallet, the normal path, and "I use a
/// passphrase" opens its entry.
struct Bip39AskScreen: View {
    let testRegistry: Bool
    let onNone: () -> Void
    let onPassphrase: () -> Void

    var body: some View {
        KitScreen(Screen.bip39Ask.id, testRegistry: testRegistry) {
            Heading(Screen.bip39Ask.title)
            KitText(ExportTexts.bip39Ask, style: .small)
        } actions: {
            KitButton(ExportTexts.noBip39, id: "no_bip39_passphrase", action: onNone)
            KitButton(ExportTexts.withBip39, id: "with_bip39_passphrase", action: onPassphrase)
        }
    }
}

/// The BIP39 passphrase's entry (the Pi's bip39-entry, Q32 (c)), a Protected screen behind the privacy gate:
/// the passphrase as typed (a space a middle dot) inside SecureLayer; the ASCII pad, one of its three pages
/// of keys at a time, the page the model's (Previous keys and Next keys are its previousPage and nextPage);
/// Delete, and Done once a character is typed; Back returns to the question, the passphrase wiped (the Pi's
/// KEY2). The passphrase lives in the model's PadEntry, observed here.
struct Bip39EntryScreen: View {
    let state: UiState
    @ObservedObject var letters: PadEntry
    let testRegistry: Bool
    let passGate: () -> Void
    let onKey: (Character) -> Void
    let onPreviousKeys: () -> Void
    let onNextKeys: () -> Void
    let onDelete: () -> Void
    let onDone: () -> Void
    let onBack: () -> Void

    var body: some View {
        Protected(state: state, testRegistry: testRegistry, passGate: passGate) {
            let keys = state.page
            KitScreen(Screen.bip39Entry.id, testRegistry: testRegistry) {
                Heading(Screen.bip39Entry.title)
                KitText(keysPageText(keys), style: .small, id: "keys_page")
                KitText(ExportTexts.bip39How, style: .small)
            } actions: {
                SecureLayer {
                    Text(bip39Shown(letters))
                        .font(KitType.hex)
                        .foregroundColor(KitColors.text)
                        .padding(.vertical, 6)
                        .secretIdentifier(.bip39Text)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                AsciiPad(page: keys, onKey: onKey)
                KitPair(ExportTexts.previousKeys, ExportTexts.nextKeys) {
                    KitButton(ExportTexts.previousKeys, id: "keys_previous", enabled: keys > 0, action: onPreviousKeys)
                    KitButton(ExportTexts.nextKeys, id: "keys_next", enabled: keys < asciiPages - 1, action: onNextKeys)
                }
                KitPair(CheckTexts.delete, StartTexts.done) {
                    KitButton(CheckTexts.delete, id: "bip39_delete", enabled: letters.length > 0, action: onDelete)
                    KitButton(StartTexts.done, id: "bip39_done", enabled: letters.length > 0, action: onDone)
                }
                KitButton(CheckTexts.back, id: "back", action: onBack)
            }
        }
    }
}

/// The watch-only summary (swb, "Watch-only export"; the Pi's watch-summary), a Public screen as the wallet
/// summary is (Q29): the exported wallet's fingerprint and first receive address, the xpub's warning, and
/// for a BIP39 passphrase's wallet that it is that wallet's; Next shows the account QR.
struct WatchSummaryScreen: View {
    let state: UiState
    let testRegistry: Bool
    let onNext: () -> Void

    var body: some View {
        if let watch = state.watch {
            KitScreen(Screen.watchSummary.id, testRegistry: testRegistry) {
                Heading(Screen.watchSummary.title)
                KitText(WordsTexts.fingerprint, style: .small)
                KitText(fingerprintHex(watch.summary.fingerprint), style: .hex, id: "watch_fingerprint")
                KitText(WordsTexts.firstAddress, style: .small)
                KitText(watch.summary.firstAddress, id: "watch_first_address")
                KitText(ExportTexts.treatPrivate, style: .small)
                if watch.passphraseUsed {
                    KitText(ExportTexts.passphraseWallet, style: .warning, id: "passphrase_wallet")
                }
            } actions: {
                KitButton(WordsTexts.next, id: "watch_summary_next", action: onNext)
            }
        }
    }
}

/// The account QR for Sparrow (swb's crypto-account UR; the Pi's watch-account-qr), a Protected screen
/// behind the privacy gate (it carries the xpub); Next shows the descriptor QR.
struct WatchAccountQrScreen: View {
    let state: UiState
    let testRegistry: Bool
    let passGate: () -> Void
    let onNext: () -> Void

    var body: some View {
        Protected(state: state, testRegistry: testRegistry, passGate: passGate) {
            if let watch = state.watch {
                KitScreen(Screen.watchAccountQr.id, testRegistry: testRegistry) {
                    Heading(Screen.watchAccountQr.title)
                    ExportQr(matrix: watch.account, kind: .account)
                    KitText(ExportTexts.sparrowHow, style: .small)
                } actions: {
                    KitButton(ExportTexts.nextDescriptor, id: "watch_next", action: onNext)
                }
            }
        }
    }
}

/// The descriptor QR for Bitcoin Core (swb's two descriptors with their checksums, receive and change; the
/// Pi's watch-descriptor-qr), a Protected screen (the xpub): Previous returns to the account QR, Done goes
/// on to the registration, the export wiped.
struct WatchDescriptorQrScreen: View {
    let state: UiState
    let testRegistry: Bool
    let passGate: () -> Void
    let onPrevious: () -> Void
    let onDone: () -> Void

    var body: some View {
        Protected(state: state, testRegistry: testRegistry, passGate: passGate) {
            if let watch = state.watch {
                KitScreen(Screen.watchDescriptorQr.id, testRegistry: testRegistry) {
                    Heading(Screen.watchDescriptorQr.title)
                    ExportQr(matrix: watch.descriptors, kind: .descriptor)
                    KitText(ExportTexts.coreHow, style: .small)
                } actions: {
                    KitPair(WordsTexts.previous, StartTexts.done) {
                        KitButton(WordsTexts.previous, id: "watch_previous", action: onPrevious)
                        KitButton(StartTexts.done, id: "watch_done", action: onDone)
                    }
                }
            }
        }
    }
}

/// The registration's offer (swb, "Registering a new seal"; the Pi's register-offer), a Public screen: to
/// register once, never from a restored seed; "Show registration QR" or Skip, which goes on to D's offer in
/// Mixed mode, or to the checklist.
struct RegisterOfferScreen: View {
    let testRegistry: Bool
    let onShow: () -> Void
    let onSkip: () -> Void

    var body: some View {
        KitScreen(Screen.registerOffer.id, testRegistry: testRegistry) {
            Heading(Screen.registerOffer.title)
            KitText(ExportTexts.registerOnce, style: .small)
        } actions: {
            KitButton(ExportTexts.showRegistration, id: "show_registration", action: onShow)
            KitButton(CheckTexts.skip, id: "skip_registration", action: onSkip)
        }
    }
}

/// The registration QR (swb's "Register seal" QR of the seal code; the Pi's register-qr), a Protected screen
/// behind the privacy gate, with the reminder to register once as its heading; Next goes on as the offer's
/// Skip does, the QR wiped.
struct RegisterQrScreen: View {
    let state: UiState
    let testRegistry: Bool
    let passGate: () -> Void
    let onNext: () -> Void

    var body: some View {
        Protected(state: state, testRegistry: testRegistry, passGate: passGate) {
            if let registration = state.registration {
                KitScreen(Screen.registerQr.id, testRegistry: testRegistry) {
                    Heading(ExportTexts.registerQrHeading)
                    ExportQr(matrix: registration, kind: .registration)
                    KitText(ExportTexts.registerHow, style: .small)
                    KitText(ExportTexts.registerOnce, style: .small)
                } actions: {
                    KitButton(WordsTexts.next, id: "registration_done", action: onNext)
                }
            }
        }
    }
}

/// D's offer (docs/mobile-apps.md, step 16; the Pi's reveal-d-offer), a Public screen in Mixed mode alone:
/// its warning, that D and the rolls recreate the seed, and verify.py's prompt; "Show D" or Skip, which goes
/// on to the checklist.
struct RevealDOfferScreen: View {
    let testRegistry: Bool
    let onShow: () -> Void
    let onSkip: () -> Void

    var body: some View {
        KitScreen(Screen.revealDOffer.id, testRegistry: testRegistry) {
            Heading(Screen.revealDOffer.title)
            KitText(ExportTexts.revealD, style: .warning, id: "reveal_d_warning")
            KitText(ExportTexts.verifyPrompt, style: .small)
        } actions: {
            KitButton(ExportTexts.showD, id: "show_d", action: onShow)
            KitButton(CheckTexts.skip, id: "skip_d", action: onSkip)
        }
    }
}

/// D (the Pi's reveal-d), a Protected screen behind the privacy gate: D as 16 groups of 4 hex digits, four
/// rows as C's, inside SecureLayer; Next goes on to the checklist, D wiped.
struct RevealDScreen: View {
    let state: UiState
    let testRegistry: Bool
    let passGate: () -> Void
    let onNext: () -> Void

    var body: some View {
        Protected(state: state, testRegistry: testRegistry, passGate: passGate) {
            if let leg = state.deviceLeg {
                KitScreen(Screen.revealD.id, testRegistry: testRegistry) {
                    Heading(Screen.revealD.title)
                    SecureLayer {
                        Text(deviceLegText(leg))
                            .font(KitType.hex)
                            .wholeLines(4)
                            .foregroundColor(KitColors.text)
                            .padding(.vertical, 6)
                            .secretIdentifier(.deviceLeg)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    KitText(ExportTexts.dNote, style: .small)
                } actions: {
                    KitButton(WordsTexts.next, id: "d_done", action: onNext)
                }
            }
        }
    }
}

/// An export's QR code inside SecureLayer, named by its kind, centred across the text column at the QR side
/// every screen draws (D4's collision report QR's way).
private struct ExportQr: View {
    let matrix: QrMatrix
    let kind: QrKind

    var body: some View {
        SecureLayer {
            QrCodeView(matrix: matrix, kind: kind)
        }
        .frame(width: CGFloat(qrSide), height: CGFloat(qrSide))
        .frame(maxWidth: .infinity)
        .accessibilityElement()
        .accessibilityLabel(kind.spoken)
        .spoken(.qrCode)
        Gap(8)
    }
}
