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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Refusal
import com.keepcrypt.entropy.ffi.RefusalGroup
import com.keepcrypt.entropy.ffi.Secret

// The encrypted backup and Check a backup (tasks/todo.md, M5 group 18; docs/mobile-apps.md, "Encrypted
// backup only" and step 13; the Pi's wording, pi/app's screens/ready.rs and screens/usb.rs, wherever
// those say nothing else): the backup's offer after the wallet summary, the 8-word passphrase two pages
// of four and its confirm, two questions of four choices answered on the letter pad (Protected), the
// save through the system's file picker, its read-back and "Backup verified"; and Home's Check a
// backup: the passphrase's entry on the letter pad (Protected), "Backup OK" with the fingerprint and
// the Seal ID, and the re-check QR. A checked backup's words show on the words' own screens
// (WordsScreens.kt), through the privacy gate. Each hands its presses to the ceremony model, which
// ignores a press its screen no longer shows. Their secret text (the passphrase's words and the letters
// typed) is drawn from the Secrets the state holds and the pad's entry, each node marked secret
// (Kit.kt), and a String of it exists only for the text on screen (Q58). The watch-only export,
// registration and D come between "Backup verified" and the checklist with commit 21.

/** The backup passphrase's words: two pages of four (pi-firmware.md, USB step 1). */
const val PASSPHRASE_WORDS = 8

/** The words on one page of the backup passphrase. */
const val PASSPHRASE_PAGE_WORDS = 4

/** The offer (the Pi's, for a file the user places): the paper words stay the primary backup (MA:151). */
const val BACKUP_OFFER = "Save an encrypted backup file to a place you pick. Its 8-word passphrase is shown once: write " +
    "it on paper and keep it apart from the file. The words on your metal or paper stay the primary backup."

/** Under the passphrase (the Pi's). */
const val PASSPHRASE_NOTE = "Backup passphrase: write it on paper and store it apart from the file."

/** After a wrong confirm (the Pi's backup-confirm-wrong). */
const val WRONG_CONFIRM = "Not that word. The passphrase is shown again from its first word; the questions stay the same."

/** How the confirm is answered on the letter pad, which has no word list (MA:29). */
const val CONFIRM_HOW = "Type its first four letters from your paper copy, or a whole three-letter word, then Done."

/** The save screen: the file is ciphertext, made in memory (MA:154). */
const val SAVE_HOW = "Save opens the phone's file picker. The backup was encrypted in memory: nothing unencrypted is " +
    "ever written."

/** MA:156's one line for a cloud folder. */
const val CLOUD_FOLDER = "A cloud folder is allowed: the passphrase is what protects the file, so keep it on paper, " +
    "away from the file."

/** After a failed save (the Pi's backup-failed, for a file the user places). */
const val SAVE_AGAIN = "Save again writes a new copy under the same passphrase. A file left where this one failed may be " +
    "incomplete: delete it."

/** "Backup verified" (the Pi's). */
const val BACKUP_VERIFIED = "The saved file was read back and opens under the passphrase. On an offline computer, age -d " +
    "and the passphrase open it."

/** Check a backup's entry instruction, under any refusal (the Pi's FIRST_FOURS). */
const val FIRST_FOURS = "Type the first four letters of each word, or a whole three-letter word."

/** Check a backup's result (MA:162): the words only on request. */
const val BACKUP_OK_NOTE = "Its words show only if you ask, on a private screen. Done wipes them."

/** The re-check QR (the Pi's backup-check-recheck-qr): the seal's T, with no nonce. */
const val RECHECK_NOTE = "T only, no nonce: scan it with the registry website or the offline checker app to check this " +
    "seal again."

/** Why a save failed: the step the model names (the session stays). */
enum class SaveStep { Write, ReadBack, Verify }

/** A failed save: its step, and for Verify core's refusal of the file read back. */
class SaveFailure(val step: SaveStep, val refusal: Refusal? = null)

/** Why Check a backup opened no file: its name, its size (unknown, or past core's limit), or a read that failed. */
enum class FileRefusal { NotAge, NoSize, TooLarge, Unreadable }

/**
 * Core's text for a refusal the backup screens show (core/src/error.rs's Display, verbatim, as the Pi
 * shows it; BackupScreensTest pins each against core's source): the passphrase does not open the file,
 * the file holds another seed, or the file does not read; null for any other refusal, which the backup's
 * calls never give.
 */
fun backupRefusalText(refusal: Refusal): String? = when (refusal) {
    Refusal.WrongPassphrase -> "the passphrase does not open this backup"
    Refusal.ReadbackMismatch -> "the backup does not hold this seed"
    Refusal.TooLarge -> "backup rejected: file too large"
    Refusal.Armor -> "backup rejected: bad armor"
    Refusal.Header -> "backup rejected: bad header"
    Refusal.WorkFactor -> "backup rejected: work factor out of range"
    Refusal.HeaderMac -> "backup rejected: header MAC mismatch"
    Refusal.Payload -> "backup rejected: bad payload"
    Refusal.Plaintext -> "backup rejected: bad backup contents"
    Refusal.UnsupportedVersion -> "backup rejected: unsupported backup version"
    Refusal.PassphraseWords -> "backup rejected: the backup passphrase must be 8 words from the BIP39 English list"
    else -> null
}

/** Whether refusal is one the backup's calls give (core's text exists for it): any other is the shell's bug. */
fun isBackupRefusal(refusal: Refusal): Boolean =
    refusal == Refusal.WrongPassphrase || refusal == Refusal.ReadbackMismatch || refusal.group == RefusalGroup.Backup

/** A failed save's line: the step it failed at, and for Verify core's text. */
fun saveFailureText(failure: SaveFailure): String = when (failure.step) {
    SaveStep.Write -> "Backup not saved: writing the file failed."
    SaveStep.ReadBack -> "Backup not saved: reading the file back failed."
    SaveStep.Verify -> "Backup not saved: the file read back does not verify (" +
        failure.refusal?.let { backupRefusalText(it) }.orEmpty() + ")."
}

/** Home's line when Check a backup opened no file. */
fun fileRefusalText(refusal: FileRefusal): String = when (refusal) {
    FileRefusal.NotAge -> "That file was not opened: a KeepCrypt backup's name ends in " + Core.BACKUP_SUFFIX + "."
    FileRefusal.NoSize -> "That file was not opened: its size is not known, so it is not read."
    FileRefusal.TooLarge -> "That file was not opened: it is larger than a backup can be (8 KiB)."
    FileRefusal.Unreadable -> "That file could not be read."
}

/** A word as the text on screen (Q58: a String only for what is drawn): text's bytes from start, until end. */
private fun drawn(text: Secret, start: Int, end: Int): String = buildString(end - start) {
    for (index in start until end) append(Char(text[index].toInt() and 0xFF))
}

/**
 * The passphrase's page on show (core's: its four words one space apart) as the screen's lines, each
 * word after its number, "1 ostrich" (the Pi's).
 */
fun passphraseLines(page: Int, text: Secret): List<String> {
    val lines = ArrayList<String>(PASSPHRASE_PAGE_WORDS)
    var start = 0
    for (index in 0..text.size) {
        if (index == text.size || text[index] == SPACE) {
            lines.add((page * PASSPHRASE_PAGE_WORDS + lines.size + 1).toString() + " " + drawn(text, start, index))
            start = index + 1
        }
    }
    return lines
}

/** A confirm choice (a word of core's) as the text on screen. */
fun choiceText(choice: Secret): String = drawn(choice, 0, choice.size)

/** The space between the passphrase's words on a page. */
private const val SPACE: Byte = 0x20

/**
 * The backup's offer (docs/mobile-apps.md, step 13; the Pi's backup-offer), a Public screen after the
 * wallet summary: what the file is, that the paper words stay the primary backup, and "Make an
 * encrypted backup" or Skip, which goes on without one.
 */
@Composable
fun BackupOffer(testRegistry: Boolean, onMake: () -> Unit, onSkip: () -> Unit) {
    KitScreen(
        screenId(Screen.BackupOffer),
        testRegistry,
        actions = {
            KitButton("Make an encrypted backup", "make_backup", onClick = onMake)
            KitButton("Skip", "skip_backup", onClick = onSkip)
        },
    ) {
        Heading("Encrypted backup")
        KitText(BACKUP_OFFER, KitType.small)
    }
}

/**
 * The backup passphrase (pi-firmware.md, USB step 1; the Pi's backup-passphrase), a Protected screen
 * behind the privacy gate: core's 8 words, four a page, each after its number; Previous and Next page
 * (the system Back is Previous), and the second page's "I wrote it down" goes on to the confirm. After a
 * wrong confirm it shows again from its first page, saying so.
 */
@Composable
fun BackupPassphrase(
    state: UiState,
    testRegistry: Boolean,
    passGate: () -> Unit,
    onPrevious: () -> Unit,
    onNext: () -> Unit,
    onConfirm: () -> Unit,
) {
    Protected(state, testRegistry, passGate) {
        val text = state.passphrase
        if (text != null) {
            val last = state.page == 1
            KitScreen(
                screenId(Screen.BackupPassphrase),
                testRegistry,
                actions = {
                    Row {
                        KitButton("Previous", "previous", enabled = last, modifier = Modifier.weight(1f).padding(end = 6.dp), onClick = onPrevious)
                        KitButton("Next", "next", enabled = !last, modifier = Modifier.weight(1f).padding(start = 6.dp), onClick = onNext)
                    }
                    if (last) {
                        KitButton("I wrote it down", "passphrase_written", onClick = onConfirm)
                    }
                },
            ) {
                Heading("Backup passphrase")
                if (state.wrongConfirm) {
                    KitText(WRONG_CONFIRM, KitType.body.copy(color = KitColors.warning), tag = "wrong_confirm")
                }
                KitText(PASSPHRASE_NOTE, KitType.small)
                val first = state.page * PASSPHRASE_PAGE_WORDS + 1
                KitText("Words " + first + "-" + (first + PASSPHRASE_PAGE_WORDS - 1) + " of " + PASSPHRASE_WORDS, KitType.small, tag = "passphrase_page")
                for (line in passphraseLines(state.page, text)) {
                    BasicText(line, Modifier.padding(vertical = 6.dp).secret(), style = KitType.hex)
                }
            }
        }
    }
}

/**
 * The passphrase's confirm (pi-firmware.md, USB step 2; the Pi's backup-confirm), a Protected screen:
 * question page + 1 of two, "Which is word N?", core's four choices, and the answer typed on the letter
 * pad (Pads.kt's LetterPad, whose keys say only their role), its first four letters or a whole
 * three-letter word, so no choice is a button that names its word; Delete, and Done at three or four
 * letters. The letters live in the model's PadEntry: version redraws them when the pad, Delete or Done
 * change them.
 */
@Composable
fun BackupConfirm(state: UiState, letters: PadEntry, testRegistry: Boolean, passGate: () -> Unit, onDone: () -> Unit) {
    Protected(state, testRegistry, passGate) {
        val questions = state.challenge?.questions.orEmpty()
        if (state.page in questions.indices) {
            val question = questions[state.page]
            var version by remember { mutableIntStateOf(0) }
            KitScreen(
                screenId(Screen.BackupConfirm),
                testRegistry,
                actions = {
                    key(version) {
                        LetterEntry(letters, done = "confirm_done", onDone = onDone) { version += 1 }
                    }
                },
            ) {
                KitText("Check your copy: question " + (state.page + 1) + " of 2", KitType.small, tag = "confirm_question")
                Heading("Which is word " + question.position + "?")
                for (choice in question.choices) {
                    BasicText(choiceText(choice), Modifier.padding(vertical = 4.dp).secret(), style = KitType.hex)
                }
                KitText(CONFIRM_HOW, KitType.small)
            }
        }
    }
}

/**
 * The letters typed and the letter pad, Delete and Done (at three or four letters), as the read-back
 * entry has them (WordsScreens.kt): the confirm's and Check a backup's entry. changed redraws them.
 */
@Composable
private fun LetterEntry(letters: PadEntry, done: String, onDone: () -> Unit, changed: () -> Unit) {
    BasicText(typedFaces(letters), Modifier.padding(vertical = 6.dp).secret(), style = KitType.large.copy(fontFamily = FontFamily.Monospace))
    LetterPad(letters, changed)
    Row {
        KitButton("Delete", "letters_delete", enabled = letters.length > 0, modifier = Modifier.weight(1f).padding(end = 6.dp)) {
            letters.delete()
            changed()
        }
        KitButton("Done", done, enabled = letters.length >= READBACK_MIN_LETTERS, modifier = Modifier.weight(1f).padding(start = 6.dp)) {
            onDone()
            changed()
        }
    }
}

/**
 * The save (docs/mobile-apps.md, "Saving", steps 2-5), a Public screen once core has encrypted the
 * backup in memory: core's suggested name, MA:156's cloud-folder line, and Save, which opens the
 * system's create-document picker; the bytes are written there once, read back and verified by core
 * before "Backup verified". A failed save names its step, and Save again or Skip; the session stays.
 */
@Composable
fun BackupSave(state: UiState, testRegistry: Boolean, onSave: () -> Unit, onSkip: () -> Unit) {
    val name = state.backupName ?: return
    val failure = state.saveFailure
    KitScreen(
        screenId(Screen.BackupSave),
        testRegistry,
        actions = {
            KitButton(if (failure == null) "Save" else "Save again", "save_backup", onClick = onSave)
            KitButton("Skip", "skip_backup", onClick = onSkip)
        },
    ) {
        Heading("Save the backup")
        if (failure != null) {
            KitText(saveFailureText(failure), KitType.body.copy(color = KitColors.warning), tag = "save_failure")
            KitText(SAVE_AGAIN, KitType.small)
        }
        KitText("The file", KitType.small)
        KitText(name, tag = "backup_name")
        KitText(SAVE_HOW, KitType.small)
        KitText(CLOUD_FOLDER, KitType.small, tag = "cloud_folder")
    }
}

/** "Backup verified" (the Pi's backup-verified), a Public screen: the file read back opened; Next goes on. */
@Composable
fun BackupVerified(testRegistry: Boolean, onNext: () -> Unit) {
    KitScreen(
        screenId(Screen.BackupVerified),
        testRegistry,
        actions = { KitButton("Next", "backup_next", onClick = onNext) },
    ) {
        Heading("Backup verified")
        KitText(BACKUP_VERIFIED, KitType.small)
    }
}

/**
 * Check a backup's passphrase entry (docs/mobile-apps.md, "Checking a backup"; the Pi's
 * backup-check-entry, Q32 (b)), a Protected screen behind the privacy gate: word page + 1 of 8, each
 * its first four letters on the letter pad, or a whole three-letter word; after the eighth core opens
 * the file. A refusal shows core's text with the instruction under it, the entry emptied from word 1;
 * Back goes Home, wiping the file read and the letters typed.
 */
@Composable
fun BackupCheckEntry(
    state: UiState,
    letters: PadEntry,
    testRegistry: Boolean,
    passGate: () -> Unit,
    onDone: () -> Unit,
    onBack: () -> Unit,
) {
    Protected(state, testRegistry, passGate) {
        var version by remember { mutableIntStateOf(0) }
        KitScreen(
            screenId(Screen.BackupCheckEntry),
            testRegistry,
            actions = {
                key(version) {
                    LetterEntry(letters, done = "entry_done", onDone = onDone) { version += 1 }
                }
                KitButton("Back", "back", onClick = onBack)
            },
        ) {
            Heading("Check a backup")
            KitText("Backup passphrase, word " + (state.page + 1) + " of " + PASSPHRASE_WORDS, KitType.small, tag = "entry_word")
            val refusal = state.entryRefusal
            if (refusal != null) {
                KitText(backupRefusalText(refusal).orEmpty(), KitType.body.copy(color = KitColors.warning), tag = "entry_refusal")
            }
            KitText(FIRST_FOURS, KitType.small)
        }
    }
}

/**
 * Check a backup's result (docs/mobile-apps.md, "Checking a backup"; the Pi's backup-check-result), a
 * Public screen: "Backup OK", the backup's fingerprint and its Seal ID; "Show the words" (through the
 * privacy gate, on the words' screens), "Re-check QR" and Done, which wipes the backup's words in core
 * and returns Home.
 */
@Composable
fun BackupCheckResult(state: UiState, testRegistry: Boolean, onShowWords: () -> Unit, onRecheck: () -> Unit, onDone: () -> Unit) {
    val opened = state.opened ?: return
    KitScreen(
        screenId(Screen.BackupCheckResult),
        testRegistry,
        actions = {
            KitButton("Show the words", "show_backup_words", onClick = onShowWords)
            KitButton("Re-check QR", "recheck", onClick = onRecheck)
            KitButton("Done", "backup_done", onClick = onDone)
        },
    ) {
        Heading("Backup OK")
        KitText("Fingerprint", KitType.small)
        KitText(fingerprintHex(opened.fingerprint), KitType.hex, tag = "backup_fingerprint")
        KitText("Seal ID", KitType.small)
        KitText(opened.seal.sealId, KitType.hex, tag = "backup_seal_id")
        KitText(BACKUP_OK_NOTE, KitType.small)
    }
}

/** The re-check QR (the Pi's backup-check-recheck-qr), a Public screen: the seal's T alone; Back returns to the result. */
@Composable
fun BackupRecheck(state: UiState, testRegistry: Boolean, onBack: () -> Unit) {
    val opened = state.opened ?: return
    KitScreen(
        screenId(Screen.BackupRecheck),
        testRegistry,
        actions = { KitButton("Back", "back", onClick = onBack) },
    ) {
        Heading("Re-check QR")
        Box(Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
            QrCode(opened.recheck, QR_SIDE_DP.dp)
        }
        Gap(8)
        KitText(RECHECK_NOTE, KitType.small)
    }
}
