package com.keepcrypt.entropy.screens

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
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import com.keepcrypt.entropy.ffi.FaceVerdict
import com.keepcrypt.entropy.ffi.Verdict
import com.keepcrypt.entropy.ffi.WordPage

// The words to the end of the ceremony (tasks/todo.md, M5 group 17; docs/mobile-apps.md, steps 10-12
// and 17; docs/seal-watchonly-braille.md, "Braille backup", whose insert view, read-back, 24-word seeds
// and checklist these follow; the Pi's wording, pi/app's screens/ready.rs, wherever those say nothing
// else): the words in insert view and their overview (Protected), the device swap between a 24-word
// seed's two devices, the read-back entry on the letter pad and its mismatch (Protected), the
// read-back's end, the wallet summary and the checklist (Public). Each hands its presses to the
// ceremony model, which ignores a press its screen no longer shows. Their secret text (the words, the
// SeedBook numbers and faces, the letters typed and the verdicts) is drawn from the word pages and
// verdicts the state holds in Secrets, each node marked secret (Kit.kt), and a String of it exists
// only for the text on screen (Q58). The backup and the other exports (commits 20 and 21) come
// between the summary and the checklist.

/** The insert view shows one insert a page, the overview four (the Pi's). */
const val OVERVIEW_WORDS = 4

/** The inserts of one device: a 24-word seed's words 13-24 go on device 2 of 2 (swb, "24-word seeds"). */
const val INSERTS_PER_DEVICE = 12

/** A word's letters past the fourth are drawn lighter (swb's insert view; the Pi's LIGHTER_FROM). */
const val LIGHTER_FROM = 4

/** The read-back's Done takes three letters (the fourth face blank) or four (the letter pad's capacity). */
const val READBACK_MIN_LETTERS = 3

/** The longest BIP39 word: the overview pads each word to it, so the SeedBook numbers line up. */
private const val LONGEST_WORD = 8

/** Between a header's parts, as the Pi writes it (a middle dot). */
private const val PARTS = " · "

/** How to type the read-back (the Pi's, on the phone's letter pad, which has no key for a blank face). */
const val READBACK_HOW = "Type faces 1-4 as punched on the metal. For a blank face 4, press Done after the three letters."

/** After a match (the Pi's). */
const val READBACK_MATCHED = "It matches the seed, which completes it as:"

/** A mismatch's advice (the Pi's): the mirror pairs read twice. */
const val MIRRORS = "Read the insert again, face by face: the mirror pairs e/i, d/f, h/j and r/w read twice."

/** The reviewed insert's note: compare it with the metal, then read it back again. */
const val REVIEWING = "Compare each face with the metal, then read this insert back again."

/** The read-back's end (the Pi's). */
const val READBACK_COMPLETE = "Every insert matches the seed. Next: the wallet summary."

/** The device swap (the Pi's): device 1 of 2 put away before device 2 is opened. */
const val DEVICE_SWAP = "Close device 1 of 2, fastened shut, and put it away before you open device 2. Both insert " +
    "sets are engraved 01-12."

/** The wallet summary's note (the Pi's). */
const val COMPARE_AFTER_RESTORE = "Compare both after any restore."

/** swb's "Before you walk away", the SeedBook checklist on the final screen, in the Pi's lines. */
val CHECKLIST: List<String> = listOf(
    "- Every face read back.",
    "- Inserts reassembled in sequence order, 01 first.",
    "- Device fastened shut and back in place.",
    "- Whole phrase test-restored from the metal.",
    "- Every paper copy destroyed.",
    "- No photograph of the inserts anywhere.",
)

/** The checklist's line for a 24-word seed (the Pi's; swb: the final checklist says which device holds words 1-12). */
const val TWO_DEVICES = "Device 1 of 2 holds words 1-12; device 2 of 2 holds words 13-24."

/**
 * swb's SeedBook safety rules, "enforced in the copy on screen": on the privacy gate before the words
 * (the Pi's) and on the checklist.
 */
const val SEEDBOOK_RULES = "The SeedBook is a public reference: never write the real phrase in it or store a marked " +
    "copy with the wallet. Work one word at a time, in order, alone and offline; rehearse on a spare insert first. " +
    "Never use a computer-driven embosser or printer for a real seed."

/** number as width decimal digits, zero first (the Pi's push_number). */
private fun digits(number: Int, width: Int): String = number.toString().padStart(width, '0')

/** "device 1 of 2": the device core labels the insert with (swb, "24-word seeds"). */
private fun deviceText(insert: WordPage): String = "device " + insert.device + " of " + insert.devices

/** The insert view's header (the Pi's): "Insert 01 · device 1 of 1". */
fun insertHeader(insert: WordPage): String = "Insert " + digits(insert.position, 2) + PARTS + deviceText(insert)

/** The overview's header (the Pi's): "Words 01-04 · device 1 of 1", the device of its first word. */
fun overviewHeader(first: WordPage, last: WordPage): String =
    "Words " + digits(first.position, 2) + "-" + digits(last.position, 2) + PARTS + deviceText(first)

/** The read-back entry's header (the Pi's): "Read back insert 01 · device 1 of 1". */
fun readbackHeader(insert: WordPage): String = "Read back insert " + digits(insert.position, 2) + PARTS + deviceText(insert)

/** The mismatch's header (the Pi's): "Insert 01 does not match · device 1 of 1". */
fun mismatchHeader(insert: WordPage): String =
    "Insert " + digits(insert.position, 2) + " does not match" + PARTS + deviceText(insert)

/** A SeedBook number as the insert view shows it (the Pi's): "SeedBook 0001", the word's 1-based BIP39 index. */
fun seedbookText(number: Int): String = "SeedBook " + digits(number, 4)

/** Face 6, the insert's engraved sequence number (the Pi's): "Face 6: the engraved number 01". */
fun faceSixText(sequence: Int): String = "Face 6: the engraved number " + digits(sequence, 2)

/** The wallet summary's fingerprint (the Pi's fingerprint_hex): its 4 bytes as 8 lower-case hex digits. */
fun fingerprintHex(fingerprint: ByteArray): String = buildString(2 * fingerprint.size) {
    for (byte in fingerprint) {
        val value = byte.toInt() and 0xFF
        append(HEX[value shr 4])
        append(HEX[value and 0x0F])
    }
}

/** The hex digits by nibble, lower case. */
private const val HEX = "0123456789abcdef"

/** The faces typed so far on the read-back entry (the Pi's): each letter, then a dash for each face still to come, "ab--". */
fun typedFaces(letters: PadEntry): String = buildString(letters.capacity) {
    for (index in 0 until letters.capacity) append(if (index < letters.length) letters.keyAt(index) else '-')
}

/**
 * One face's verdict on the mismatch screen (the Pi's verdict_line): "Face 2: mirror misread" for a
 * mirror-pair letter read as its partner (e/i, d/f, h/j, r/w), "should be blank", "should have a
 * letter", or "wrong letter: missing 1 4, extra 2" with the dots the letter read lacks and has too many.
 */
fun verdictLine(face: Int, verdict: FaceVerdict): String {
    val text = when (verdict.verdict) {
        Verdict.Ok -> "ok"
        Verdict.MirrorMisread -> "mirror misread"
        Verdict.ShouldBeBlank -> "should be blank"
        Verdict.ShouldHaveLetter -> "should have a letter"
        Verdict.WrongLetter -> "wrong letter: missing" + dotsText(verdict.missingDots) + ", extra" + dotsText(verdict.extraDots)
    }
    return "Face " + face + ": " + text
}

/** Each raised dot's number after a space (dot d at bit d - 1), or " none" (the Pi's push_dots). */
private fun dotsText(dots: Int): String {
    val raised = (1..6).filter { isRaised(dots, it) }
    return if (raised.isEmpty()) " none" else raised.joinToString("") { " $it" }
}

/** insert's word as the text on screen (Q58: a String only for what is drawn), its copy wiped. */
private fun wordText(insert: WordPage): String {
    val word = insert.word()
    val text = buildString(word.size) {
        for (index in 0 until word.size) append(Char(word[index].toInt() and 0xFF))
    }
    word.wipe()
    return text
}

/** An overview line (the Pi's): the position, the word padded to the longest, the SeedBook number, "01 abandon  0001". */
fun overviewLine(insert: WordPage): String {
    val word = wordText(insert)
    return digits(insert.position, 2) + " " + word.padEnd(LONGEST_WORD) + " " + digits(insert.seedbook, 4)
}

/** The insert's word large, its letters past the fourth lighter (swb's insert view), marked secret. */
@Composable
private fun InsertWord(insert: WordPage) {
    val word = wordText(insert)
    val text = buildAnnotatedString {
        append(word.take(LIGHTER_FROM))
        withStyle(SpanStyle(color = KitColors.muted)) { append(word.drop(LIGHTER_FROM)) }
    }
    BasicText(text, Modifier.padding(vertical = 6.dp).secret(), style = KitType.large)
}

/**
 * The words in insert view (docs/mobile-apps.md, step 10; swb's "On screen"; the Pi's step 8), a
 * Protected screen behind the privacy gate: one insert a page, its position and device, the word
 * large with its letters past the fourth lighter, its SeedBook number, faces 1-5 (Drawing.kt's braille
 * faces: the dots numbered, blank faces "leave blank", mirror-pair letters "mirror", face 5 lighter)
 * and face 6, the sequence number engraved on it. Previous and Next page through the inserts (the
 * system Back is Previous), Overview shows four words a page, and the last insert starts the
 * read-back. A mismatch's insert, shown from its read-back, offers only the way back to it.
 */
@Composable
fun WordsInsert(
    state: UiState,
    testRegistry: Boolean,
    passGate: () -> Unit,
    onPrevious: () -> Unit,
    onNext: () -> Unit,
    onOverview: () -> Unit,
    onReadback: () -> Unit,
    onBackToReadback: () -> Unit,
) {
    Protected(state, testRegistry, passGate) {
        val insert = state.insert
        if (insert != null) {
            val last = state.page + 1 == insert.count
            KitScreen(
                screenId(Screen.Words),
                testRegistry,
                actions = {
                    if (state.reviewing) {
                        KitButton("Back to the read-back", "back_to_readback", onClick = onBackToReadback)
                    } else {
                        Row {
                            KitButton("Previous", "previous", enabled = state.page > 0, modifier = Modifier.weight(1f).padding(end = 6.dp), onClick = onPrevious)
                            KitButton("Next", "next", enabled = !last, modifier = Modifier.weight(1f).padding(start = 6.dp), onClick = onNext)
                        }
                        KitButton("Overview", "overview", onClick = onOverview)
                        if (last) {
                            KitButton("Start the read-back", "start_readback", onClick = onReadback)
                        }
                    }
                },
            ) {
                Heading("Seed words")
                KitText(insertHeader(insert), KitType.small, tag = "insert_header")
                InsertWord(insert)
                BasicText(seedbookText(insert.seedbook), Modifier.padding(vertical = 6.dp).secret(), style = KitType.body)
                Row(Modifier.fillMaxWidth()) {
                    for (face in 1..5) BrailleFace(insert.face(face), Modifier.weight(1f))
                }
                KitText(faceSixText(insert.sequence), KitType.small, tag = "face_six")
                if (state.reviewing) {
                    KitText(REVIEWING, KitType.small)
                }
            }
        }
    }
}

/**
 * The overview (swb's "An overview of four words per page is available for the paper copy"; the Pi's
 * step 8), a Protected screen: four words a page, each with its position and SeedBook number, under the
 * page's word range and device. Previous and Next page (the system Back is Previous), and Insert view
 * shows the page's first insert.
 */
@Composable
fun WordsOverview(
    state: UiState,
    testRegistry: Boolean,
    passGate: () -> Unit,
    onPrevious: () -> Unit,
    onNext: () -> Unit,
    onInsertView: () -> Unit,
) {
    Protected(state, testRegistry, passGate) {
        val inserts = state.overview.orEmpty()
        if (inserts.isNotEmpty()) {
            val more = (state.page + 1) * OVERVIEW_WORDS < inserts.first().count
            KitScreen(
                screenId(Screen.WordsOverview),
                testRegistry,
                actions = {
                    Row {
                        KitButton("Previous", "previous", enabled = state.page > 0, modifier = Modifier.weight(1f).padding(end = 6.dp), onClick = onPrevious)
                        KitButton("Next", "next", enabled = more, modifier = Modifier.weight(1f).padding(start = 6.dp), onClick = onNext)
                    }
                    KitButton("Insert view", "insert_view", onClick = onInsertView)
                },
            ) {
                Heading("Seed words: overview")
                KitText(overviewHeader(inserts.first(), inserts.last()), KitType.small, tag = "overview_header")
                for (insert in inserts) {
                    BasicText(overviewLine(insert), Modifier.padding(vertical = 6.dp).secret(), style = KitType.hex)
                }
                KitText("For the paper copy: each word with its position and SeedBook number.", KitType.small)
            }
        }
    }
}

/**
 * The device swap (swb's "24-word seeds"; the Pi's device-swap), a Public screen, between a 24-word
 * seed's word 12 and word 13 when the pages go on: device 1 of 2 is closed and put away before
 * device 2 of 2 is opened. Continue shows word 13's page, in insert view or the overview, through the
 * privacy gate again.
 */
@Composable
fun DeviceSwap(testRegistry: Boolean, onContinue: () -> Unit) {
    KitScreen(
        screenId(Screen.DeviceSwap),
        testRegistry,
        actions = { KitButton("Continue", "continue", onClick = onContinue) },
    ) {
        Heading("Device swap")
        KitText("Words 13-24 go on device 2 of 2.", tag = "device_swap_text")
        KitText(DEVICE_SWAP, KitType.small)
    }
}

/**
 * The read-back entry (docs/mobile-apps.md, step 11; swb's "Read-back from the metal", mandatory; the
 * Pi's readback-entry), a Protected screen: the insert to read back, its position and device, and the
 * faces typed so far on the letter pad (Pads.kt's LetterPad, whose keys say only their role), with no
 * suggestion; Delete, and Done at three or four letters. After a match the whole word shows, and Next
 * goes on. The letters live in the model's PadEntry, not in Compose state: version redraws them when the
 * pad, Delete or Done change them.
 */
@Composable
fun ReadbackEntry(
    state: UiState,
    letters: PadEntry,
    testRegistry: Boolean,
    passGate: () -> Unit,
    onDone: () -> Unit,
    onNext: () -> Unit,
) {
    Protected(state, testRegistry, passGate) {
        val insert = state.insert
        if (insert != null) {
            var version by remember { mutableIntStateOf(0) }
            KitScreen(
                screenId(Screen.ReadbackEntry),
                testRegistry,
                actions = {
                    if (state.matched) {
                        KitButton("Next", "readback_next", onClick = onNext)
                    } else {
                        key(version) {
                            BasicText(
                                typedFaces(letters),
                                Modifier.padding(vertical = 6.dp).secret(),
                                style = KitType.large.copy(fontFamily = FontFamily.Monospace),
                            )
                            LetterPad(letters) { version += 1 }
                            Row {
                                KitButton(
                                    "Delete",
                                    "letters_delete",
                                    enabled = letters.length > 0,
                                    modifier = Modifier.weight(1f).padding(end = 6.dp),
                                ) {
                                    letters.delete()
                                    version += 1
                                }
                                KitButton(
                                    "Done",
                                    "letters_done",
                                    enabled = letters.length >= READBACK_MIN_LETTERS,
                                    modifier = Modifier.weight(1f).padding(start = 6.dp),
                                ) {
                                    onDone()
                                    version += 1
                                }
                            }
                        }
                    }
                },
            ) {
                Heading("Read-back")
                KitText(readbackHeader(insert), KitType.small, tag = "readback_header")
                if (state.matched) {
                    KitText(READBACK_MATCHED)
                    InsertWord(insert)
                } else {
                    KitText(READBACK_HOW, KitType.small)
                }
            }
        }
    }
}

/**
 * The read-back mismatch (the Pi's readback-mismatch), a Protected screen: the insert that does not
 * match, and each of faces 1-4's verdict, core's (a mirror-pair misread named as one), with the
 * Pi's advice. "Read it again" returns to its entry; "Show the insert" shows its page to compare with
 * the metal.
 */
@Composable
fun ReadbackMismatch(
    state: UiState,
    testRegistry: Boolean,
    passGate: () -> Unit,
    onAgain: () -> Unit,
    onShowInsert: () -> Unit,
) {
    Protected(state, testRegistry, passGate) {
        val insert = state.insert
        val mismatch = state.mismatch
        if (insert != null && mismatch != null) {
            KitScreen(
                screenId(Screen.ReadbackMismatch),
                testRegistry,
                actions = {
                    KitButton("Read it again", "readback_again", onClick = onAgain)
                    KitButton("Show the insert", "review_insert", onClick = onShowInsert)
                },
            ) {
                Heading("Read-back")
                KitText(mismatchHeader(insert), KitType.body.copy(color = KitColors.warning), tag = "mismatch_header")
                for (face in 1..4) {
                    BasicText(verdictLine(face, mismatch.face(face)), Modifier.padding(vertical = 4.dp).secret(), style = KitType.body)
                }
                KitText(MIRRORS, KitType.small)
            }
        }
    }
}

/** The read-back's end (the Pi's readback-done): every insert matched; Next shows the wallet summary. */
@Composable
fun ReadbackDone(testRegistry: Boolean, onNext: () -> Unit) {
    KitScreen(
        screenId(Screen.ReadbackDone),
        testRegistry,
        actions = { KitButton("Next", "show_summary", onClick = onNext) },
    ) {
        Heading("Read-back complete")
        KitText(READBACK_COMPLETE)
    }
}

/**
 * The wallet summary (docs/mobile-apps.md, step 12; the Pi's step 10), a Public screen as the Pi's
 * (Q29): the fingerprint and the first receive address, to compare after any restore.
 */
@Composable
fun WalletSummary(state: UiState, testRegistry: Boolean, onNext: () -> Unit) {
    val summary = state.summary ?: return
    KitScreen(
        screenId(Screen.Wallet),
        testRegistry,
        actions = { KitButton("Next", "summary_next", onClick = onNext) },
    ) {
        Heading("Wallet summary")
        KitText("Fingerprint", KitType.small)
        KitText(fingerprintHex(summary.fingerprint), KitType.hex, tag = "fingerprint")
        KitText("First receive address", KitType.small)
        KitText(summary.firstAddress, tag = "first_address")
        KitText(COMPARE_AFTER_RESTORE, KitType.small)
    }
}

/**
 * Finish (docs/mobile-apps.md, step 17; swb's "Before you walk away"; the Pi's checklist), a Public
 * screen: the SeedBook checklist, which device holds words 1-12 for a 24-word seed, and the SeedBook's
 * safety rules; Finish ends the session and returns Home.
 */
@Composable
fun Checklist(state: UiState, testRegistry: Boolean, onFinish: () -> Unit) {
    KitScreen(
        screenId(Screen.Checklist),
        testRegistry,
        actions = { KitButton("Finish", "finish", onClick = onFinish) },
    ) {
        Heading("Before you walk away")
        for (item in CHECKLIST) {
            KitText(item)
        }
        if (state.twoDevices) {
            KitText(TWO_DEVICES, tag = "two_devices")
        }
        Gap(8)
        KitText(SEEDBOOK_RULES, KitType.small)
        KitText("Finish wipes the session and returns Home.", KitType.small)
    }
}
