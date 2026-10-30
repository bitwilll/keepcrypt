package com.keepcrypt.entropy.screens

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.keepcrypt.entropy.ffi.QrMatrix
import com.keepcrypt.entropy.ffi.Secret

// The exports after the encrypted backup (tasks/todo.md, M5 group 18; docs/mobile-apps.md, steps 14-16;
// docs/seal-watchonly-braille.md, "Watch-only export" and "Registering a new seal"; the Pi's wording,
// pi/app's screens/ready.rs, wherever those say nothing else): the watch-only offer, the BIP39
// passphrase's question and its entry on the ASCII pad (Protected), the watch-only summary (Public, Q29),
// the account QR for Sparrow and the descriptor QR for Bitcoin Core (Protected: each carries the xpub);
// the registration's offer and its QR (Protected: the seal code), once; and, in Mixed mode alone, D's
// offer, whose text is its warning, and D (Protected) as 16 groups of 4 hex digits, as C is. Each hands
// its presses to the ceremony model, which ignores a press its screen no longer shows. Their secret text
// (the BIP39 passphrase typed and D) is drawn from the pad's entry and the Secret the state holds, each
// node marked secret (Kit.kt), and a String of it exists only for the text on screen (Q58); the QR codes
// are drawn from their matrices, which hold no text.

/** The watch-only offer (the Pi's). */
const val WATCH_OFFER = "An account QR for Sparrow and a descriptor QR for Bitcoin Core: public keys only, but an xpub " +
    "shows every address and balance."

/** The BIP39 passphrase's question (the Pi's, for the phone's pad). */
const val BIP39_ASK = "Only if you use one: the export is then that passphrase's wallet. The app takes printable ASCII, " +
    "up to 100 characters."

/** How the BIP39 passphrase is typed (the Pi's, on the phone's ASCII pad). */
const val BIP39_HOW = "As typed, · for a space; letter case and spaces count. The keys come in three pages: printable " +
    "ASCII, up to 100 characters."

/** The watch-only summary's note (the Pi's). */
const val TREAT_PRIVATE = "Treat the xpub as private: it shows every address and balance."

/** A BIP39 passphrase's wallet's summary (the Pi's; swb's rule: compare with this summary, not the wallet's). */
const val PASSPHRASE_WALLET = "Your BIP39 passphrase's wallet: compare this address in Sparrow or Core, not the wallet " +
    "summary's."

/** The account QR's note: Sparrow's way to it (swb, "Sparrow"). */
const val SPARROW_HOW = "In Sparrow: New wallet, single signature, native SegWit, Airgapped Hardware Wallet, then scan " +
    "this QR. Confirm its first receive address before funding."

/** The descriptor QR's note (swb, "Bitcoin Core"). */
const val CORE_HOW = "The receive and change descriptors, for Bitcoin Core or any descriptor wallet, imported watch-only. " +
    "Confirm its first receive address before funding."

/** The registration's offer, and the reminder on its QR (the Pi's; swb, "Registering a new seal"). */
const val REGISTER_ONCE = "Register once, and never from a restored seed: a second registration of the same seed looks " +
    "like a collision."

/** What the registration QR is for (swb: the helper page registers the seal code, then discards it). */
const val REGISTER_HOW = "Scan it on a second device: the registry's page registers this seal, and only its tag and count " +
    "are kept."

/** D's offer: its warning (the Pi's). */
const val REVEAL_D = "For verification runs only: D plus the rolls recreates the seed."

/** D's offer's second line (the Pi's). */
const val VERIFY_PROMPT = "On the offline computer, type each value into verify.py only after its prompt appears."

/** Under D (the Pi's). */
const val D_NOTE = "Only for verify.py on an offline computer."

/** A space in the BIP39 passphrase as its entry shows it (the Pi's middle dot), so a space shows. */
private const val SPACE_SHOWN = '·'

/**
 * The BIP39 passphrase as its entry shows it (the Pi's bip39-entry): as typed, each space a middle dot. A
 * String only for the text on screen (Q58).
 */
fun bip39Shown(letters: PadEntry): String = buildString(letters.length) {
    for (index in 0 until letters.length) {
        val key = letters.keyAt(index)
        append(if (key == ' ') SPACE_SHOWN else key)
    }
}

/**
 * D as its screen shows it, laid out as C (hexGroups: 16 groups of 4 lower-case hex digits in four rows,
 * which verify.py reads typed as groups on one line), read from its Secret one byte at a time. A String
 * only for the text on screen (Q58).
 */
fun deviceLegText(d: Secret): String = hexGroupsOf(d.size) { d[it] }

/**
 * The watch-only offer (docs/mobile-apps.md, step 14; the Pi's watch-offer), a Public screen after the
 * backup: what the two QRs are, and "Show watch-only QRs" or Skip, which goes on to the registration.
 */
@Composable
fun WatchOffer(testRegistry: Boolean, onShow: () -> Unit, onSkip: () -> Unit) {
    KitScreen(
        screenId(Screen.WatchOffer),
        testRegistry,
        actions = {
            KitButton("Show watch-only QRs", "show_watch_only", onClick = onShow)
            KitButton("Skip", "skip_watch_only", onClick = onSkip)
        },
    ) {
        Heading("Watch-only export")
        KitText(WATCH_OFFER, KitType.small)
    }
}

/**
 * The BIP39 passphrase's question (swb, "Watch-only export": asked before the export; the Pi's
 * bip39-ask), a Public screen: "No BIP39 passphrase" exports this seed's wallet, "I use a passphrase"
 * opens its entry.
 */
@Composable
fun Bip39Ask(testRegistry: Boolean, onNone: () -> Unit, onPassphrase: () -> Unit) {
    KitScreen(
        screenId(Screen.Bip39Ask),
        testRegistry,
        actions = {
            KitButton("No BIP39 passphrase", "no_bip39_passphrase", onClick = onNone)
            KitButton("I use a passphrase", "with_bip39_passphrase", onClick = onPassphrase)
        },
    ) {
        Heading("BIP39 passphrase?")
        KitText(BIP39_ASK, KitType.small)
    }
}

/**
 * The BIP39 passphrase's entry (the Pi's bip39-entry, Q32 (c)), a Protected screen behind the privacy
 * gate: the passphrase as typed (a space a middle dot), one secret node; the ASCII pad (Pads.kt's
 * AsciiPad, whose keys say only their role), one of its three pages of keys at a time, the page the
 * model's (the state's page: Previous keys and Next keys are its previousPage and nextPage); Delete, and
 * Done once a character is typed; Back returns to the question, the passphrase wiped (the Pi's KEY2). The
 * passphrase lives in the model's PadEntry: a character's press goes to onKey and Delete to onDelete (the
 * model's padKey and padDelete), and only what reads the passphrase (Pads.kt: its length is Compose state)
 * redraws when it changes.
 */
@Composable
fun Bip39Entry(
    state: UiState,
    letters: PadEntry,
    testRegistry: Boolean,
    passGate: () -> Unit,
    onKey: (Char) -> Unit,
    onPreviousKeys: () -> Unit,
    onNextKeys: () -> Unit,
    onDelete: () -> Unit,
    onDone: () -> Unit,
    onBack: () -> Unit,
) {
    Protected(state, testRegistry, passGate) {
        val keys = state.page
        KitScreen(
            screenId(Screen.Bip39Entry),
            testRegistry,
            actions = {
                BasicText(bip39Shown(letters), Modifier.padding(vertical = 6.dp).secret(), style = KitType.hex)
                AsciiPad(keys, onKey = onKey)
                Row {
                    KitButton(
                        "Previous keys",
                        "keys_previous",
                        enabled = keys > 0,
                        modifier = Modifier.weight(1f).padding(end = 6.dp),
                        onClick = onPreviousKeys,
                    )
                    KitButton(
                        "Next keys",
                        "keys_next",
                        enabled = keys < ASCII_PAGES - 1,
                        modifier = Modifier.weight(1f).padding(start = 6.dp),
                        onClick = onNextKeys,
                    )
                }
                Row {
                    KitButton(
                        "Delete",
                        "bip39_delete",
                        enabled = letters.length > 0,
                        modifier = Modifier.weight(1f).padding(end = 6.dp),
                        onClick = onDelete,
                    )
                    KitButton(
                        "Done",
                        "bip39_done",
                        enabled = letters.length > 0,
                        modifier = Modifier.weight(1f).padding(start = 6.dp),
                        onClick = onDone,
                    )
                }
                KitButton("Back", "back", onClick = onBack)
            },
        ) {
            Heading("BIP39 passphrase")
            KitText("Keys, page " + (keys + 1) + " of " + ASCII_PAGES, KitType.small, tag = "keys_page")
            KitText(BIP39_HOW, KitType.small)
        }
    }
}

/**
 * The watch-only summary (swb, "Watch-only export"; the Pi's watch-summary), a Public screen as the
 * wallet summary is (Q29): the exported wallet's fingerprint and first receive address, the xpub's
 * warning, and for a BIP39 passphrase's wallet that it is that wallet's; Next shows the account QR.
 */
@Composable
fun WatchSummary(state: UiState, testRegistry: Boolean, onNext: () -> Unit) {
    val watch = state.watch ?: return
    KitScreen(
        screenId(Screen.WatchSummary),
        testRegistry,
        actions = { KitButton("Next", "watch_summary_next", onClick = onNext) },
    ) {
        Heading("Watch-only wallet")
        KitText("Fingerprint", KitType.small)
        KitText(fingerprintHex(watch.summary.fingerprint), KitType.hex, tag = "watch_fingerprint")
        KitText("First receive address", KitType.small)
        KitText(watch.summary.firstAddress, tag = "watch_first_address")
        KitText(TREAT_PRIVATE, KitType.small)
        if (watch.passphraseUsed) {
            KitText(PASSPHRASE_WALLET, KitType.body.copy(color = KitColors.warning), tag = "passphrase_wallet")
        }
    }
}

/**
 * The account QR for Sparrow (swb's crypto-account UR; the Pi's watch-account-qr), a Protected screen
 * behind the privacy gate (it carries the xpub); Next shows the descriptor QR.
 */
@Composable
fun WatchAccountQr(state: UiState, testRegistry: Boolean, passGate: () -> Unit, onNext: () -> Unit) {
    Protected(state, testRegistry, passGate) {
        val watch = state.watch
        if (watch != null) {
            KitScreen(
                screenId(Screen.WatchAccountQr),
                testRegistry,
                actions = { KitButton("Next: the descriptor QR", "watch_next", onClick = onNext) },
            ) {
                Heading("Account QR for Sparrow")
                ExportQr(watch.account, QrKind.Account)
                KitText(SPARROW_HOW, KitType.small)
            }
        }
    }
}

/**
 * The descriptor QR for Bitcoin Core (swb's two descriptors with their checksums, receive and change;
 * the Pi's watch-descriptor-qr), a Protected screen (the xpub): Previous (and the system Back) returns to
 * the account QR, Done goes on to the registration, the export wiped.
 */
@Composable
fun WatchDescriptorQr(state: UiState, testRegistry: Boolean, passGate: () -> Unit, onPrevious: () -> Unit, onDone: () -> Unit) {
    Protected(state, testRegistry, passGate) {
        val watch = state.watch
        if (watch != null) {
            KitScreen(
                screenId(Screen.WatchDescriptorQr),
                testRegistry,
                actions = {
                    Row {
                        KitButton("Previous", "watch_previous", modifier = Modifier.weight(1f).padding(end = 6.dp), onClick = onPrevious)
                        KitButton("Done", "watch_done", modifier = Modifier.weight(1f).padding(start = 6.dp), onClick = onDone)
                    }
                },
            ) {
                Heading("Descriptor QR for Bitcoin Core")
                ExportQr(watch.descriptors, QrKind.Descriptor)
                KitText(CORE_HOW, KitType.small)
            }
        }
    }
}

/**
 * The registration's offer (swb, "Registering a new seal"; the Pi's register-offer), a Public screen: to
 * register once, never from a restored seed; "Show registration QR" or Skip, which goes on to D's offer
 * in Mixed mode, or to the checklist.
 */
@Composable
fun RegisterOffer(testRegistry: Boolean, onShow: () -> Unit, onSkip: () -> Unit) {
    KitScreen(
        screenId(Screen.RegisterOffer),
        testRegistry,
        actions = {
            KitButton("Show registration QR", "show_registration", onClick = onShow)
            KitButton("Skip", "skip_registration", onClick = onSkip)
        },
    ) {
        Heading("Register seal")
        KitText(REGISTER_ONCE, KitType.small)
    }
}

/**
 * The registration QR (swb's "Register seal" QR of the seal code; the Pi's register-qr), a Protected
 * screen behind the privacy gate, with the reminder to register once as its heading; Next goes on as the
 * offer's Skip does, the QR wiped.
 */
@Composable
fun RegisterQr(state: UiState, testRegistry: Boolean, passGate: () -> Unit, onNext: () -> Unit) {
    Protected(state, testRegistry, passGate) {
        val registration = state.registration
        if (registration != null) {
            KitScreen(
                screenId(Screen.RegisterQr),
                testRegistry,
                actions = { KitButton("Next", "registration_done", onClick = onNext) },
            ) {
                Heading("Register once, never from a restore")
                ExportQr(registration, QrKind.Registration)
                KitText(REGISTER_HOW, KitType.small)
                KitText(REGISTER_ONCE, KitType.small)
            }
        }
    }
}

/**
 * D's offer (docs/mobile-apps.md, step 16; the Pi's reveal-d-offer), a Public screen in Mixed mode alone:
 * its warning, that D and the rolls recreate the seed, and verify.py's prompt; "Show D" or Skip, which
 * goes on to the checklist.
 */
@Composable
fun RevealDOffer(testRegistry: Boolean, onShow: () -> Unit, onSkip: () -> Unit) {
    KitScreen(
        screenId(Screen.RevealDOffer),
        testRegistry,
        actions = {
            KitButton("Show D", "show_d", onClick = onShow)
            KitButton("Skip", "skip_d", onClick = onSkip)
        },
    ) {
        Heading("Reveal D")
        KitText(REVEAL_D, KitType.body.copy(color = KitColors.warning), tag = "reveal_d_warning")
        KitText(VERIFY_PROMPT, KitType.small)
    }
}

/**
 * D (the Pi's reveal-d), a Protected screen behind the privacy gate: D as 16 groups of 4 hex digits,
 * four rows as C's, one secret node; Next goes on to the checklist, D wiped.
 */
@Composable
fun RevealD(state: UiState, testRegistry: Boolean, passGate: () -> Unit, onNext: () -> Unit) {
    Protected(state, testRegistry, passGate) {
        val leg = state.deviceLeg
        if (leg != null) {
            KitScreen(
                screenId(Screen.RevealD),
                testRegistry,
                actions = { KitButton("Next", "d_done", onClick = onNext) },
            ) {
                Heading("Device leg D")
                BasicText(deviceLegText(leg), Modifier.padding(vertical = 6.dp).secret(), style = KitType.hex)
                KitText(D_NOTE, KitType.small)
            }
        }
    }
}

/** An export's QR code, named by its kind, centred across the text column at the QR side every screen draws. */
@Composable
private fun ExportQr(matrix: QrMatrix, kind: QrKind) {
    Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
        QrCode(matrix, kind, QR_SIDE_DP.dp)
    }
    Gap(8)
}
