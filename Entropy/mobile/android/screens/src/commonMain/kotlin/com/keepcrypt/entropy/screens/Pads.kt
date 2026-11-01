package com.keepcrypt.entropy.screens

import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.keepcrypt.entropy.ffi.Secret

// The in-app pads (tasks/todo.md, M5 group 14; docs/mobile-apps.md, "Text entry"; Q57 (a)): the system
// keyboard never opens. Each pad's keys come in a fixed order, and each press goes to the model (padKey,
// U3e), which types it into a PadEntry, never a String, that hands it to Core as a Secret. On Protected
// screens (the letter pad's read-back and backup-passphrase entry, the ASCII pad's BIP39 passphrase) a
// key's semantics hold its role alone: nothing about which key was pressed reaches an accessibility
// event. The dice pad and the go-ahead code's pad are on Public screens.

/** The dice pad's keys: the faces 1 to 6. */
const val DICE_KEYS = "123456"

/** The letter pad's keys: a to z, for the first four letters of a word, which core completes. */
const val LETTER_KEYS = "abcdefghijklmnopqrstuvwxyz"

/** The go-ahead code's keys: the 32 Crockford base32 symbols, in their order (no I, L, O or U). */
const val CROCKFORD_KEYS = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

/** The BIP39 passphrase's keys: printable ASCII, 0x20 (space) to 0x7E, in code order. */
val ASCII_KEYS: String = buildString {
    for (code in 0x20..0x7E) append(Char(code))
}

/** The ASCII pad shows its keys in pages of this many (8 x 4, as the Pi's three pages). */
const val ASCII_PAGE_KEYS = 32

/** The ASCII pad's pages. */
const val ASCII_PAGES = 3

/** The longest BIP39 passphrase the pad takes (docs/pi-firmware.md, step 12). */
const val ASCII_CAPACITY = 100

/** The keys on page (0-2) of the ASCII pad. */
fun asciiPage(page: Int): String {
    check(page in 0 until ASCII_PAGES)
    val first = page * ASCII_PAGE_KEYS
    return ASCII_KEYS.substring(first, minOf(first + ASCII_PAGE_KEYS, ASCII_KEYS.length))
}

/**
 * What a pad has typed (rule 5): up to capacity of the pad's keys, as ASCII bytes in a buffer this
 * object owns and zeroes (a key deleted, the entry taken or wiped), never a String. take hands the
 * entry over as a Secret of exactly its length, for Core, and leaves this empty. No toString shows it.
 * Its length is Compose snapshot state (U3f), so a screen redraws only what reads the entry (the keys
 * typed, an enabled Delete or Done) when a key, Delete, take or wipe changes it, never the pad's keys.
 */
class PadEntry(val keys: String, val capacity: Int) {
    private val bytes = ByteArray(capacity)

    /**
     * How many keys are typed: snapshot state, which keyAt reads too, so every change redraws what reads
     * the entry; a dice face that replaces another writes it twice (the wipe's 0, then 1), so that change
     * redraws it as well. Only the count is state; the keys stay in the buffer.
     */
    var length: Int by mutableIntStateOf(0)
        private set

    val isFull: Boolean get() = length == capacity

    /** Types key, when it is one of the pad's keys and there is room; false otherwise (nothing changes). */
    fun type(key: Char): Boolean {
        if (key !in keys || length == capacity) return false
        bytes[length] = key.code.toByte()
        length += 1
        return true
    }

    /** The entry becomes key alone (the dice pad's pick); false, and nothing changes, for another key. */
    fun replace(key: Char): Boolean {
        if (key !in keys) return false
        wipe()
        return type(key)
    }

    /** Deletes the last key typed and zeroes its byte. */
    fun delete() {
        if (length == 0) return
        length -= 1
        bytes[length] = 0
    }

    /** The key typed at index, for the screen that shows the entry. */
    fun keyAt(index: Int): Char {
        check(index in 0 until length)
        return Char(bytes[index].toInt() and 0xFF)
    }

    /** The entry as a Secret of its own, exactly length bytes; this entry is wiped. */
    fun take(): Secret {
        val secret = Secret(bytes.copyOf(length))
        wipe()
        return secret
    }

    /**
     * The entry handed to use as take's Secret, which is wiped once use returns or throws (a finally:
     * the model's call catches KcHalt alone, so anything else use throws still passes through here),
     * so no copy of the keys typed outlives the call it was made for (rule 5); this entry is wiped.
     * use's result is returned, and what it throws goes on, unchanged.
     */
    fun <T> handOver(use: (Secret) -> T): T {
        val secret = take()
        try {
            return use(secret)
        } finally {
            secret.wipe()
        }
    }

    /** Zeroes every byte; nothing is typed. */
    fun wipe() {
        bytes.fill(0)
        length = 0
    }

    /** Every byte past what is typed is zero (rule 5): PadsTest's check of delete, take and wipe. */
    internal fun zeroPastLength(): Boolean = (length until capacity).all { bytes[it] == 0.toByte() }

    override fun toString(): String = "PadEntry"
}

/** A pick on the dice pad: one face, until it is confirmed (and pushed) or picked again. */
fun dicePadEntry(): PadEntry = PadEntry(DICE_KEYS, 1)

/** A word's first four letters (a three-letter word's three) on the letter pad. */
fun letterPadEntry(): PadEntry = PadEntry(LETTER_KEYS, 4)

/** The go-ahead code: eight Crockford symbols. */
fun crockfordPadEntry(): PadEntry = PadEntry(CROCKFORD_KEYS, 8)

/** A BIP39 passphrase: up to 100 printable ASCII characters. */
fun asciiPadEntry(): PadEntry = PadEntry(ASCII_KEYS, ASCII_CAPACITY)

/**
 * The dice pad (a Public screen): a face's press goes to onKey, the model's padKey, which replaces the
 * pick. Disabled at 256 rolls by its screen. Its six keys fill their share of the row (lead decision
 * M5-72 (e)), a third each.
 */
@Composable
fun DicePad(enabled: Boolean, onKey: (Char) -> Unit) {
    KeyGrid(DICE_KEYS, DICE_COLUMNS, enabled = enabled, sensitive = false, press = onKey)
}

/** The letter pad (Protected screens): a letter's press goes to onKey, the model's padKey. */
@Composable
fun LetterPad(onKey: (Char) -> Unit) {
    KeyGrid(LETTER_KEYS, LETTER_COLUMNS, enabled = true, sensitive = true, press = onKey)
}

/** The go-ahead code's pad (a Public screen: the code is no secret): a symbol's press goes to onKey, the model's padKey. */
@Composable
fun CrockfordPad(onKey: (Char) -> Unit) {
    KeyGrid(CROCKFORD_KEYS, CROCKFORD_COLUMNS, enabled = true, sensitive = false, press = onKey)
}

/**
 * The ASCII pad (a Protected screen), page (the model's) of its keys: a character's press goes to onKey,
 * the model's padKey.
 */
@Composable
fun AsciiPad(page: Int, onKey: (Char) -> Unit) {
    KeyGrid(asciiPage(page), ASCII_COLUMNS, enabled = true, sensitive = true, press = onKey)
}

/** Each pad's columns: at most NARROWEST_ROW_DP / KEY_DP, so a key is KEY_DP wide or more on any phone (M5-83). */
const val DICE_COLUMNS = 3
const val LETTER_COLUMNS = 6
const val CROCKFORD_COLUMNS = 6
const val ASCII_COLUMNS = 6

/** The narrowest row a pad is given: a 360 dp phone inside the kit's 24 dp margins. */
const val NARROWEST_ROW_DP = 312

/**
 * A key's least touch target each way: Android's and Material's accessibility minimum (CaptureTest's
 * assertLaidOut checks it on the device), and a key's height.
 */
const val KEY_DP = 48

/** The gap drawn between keys' frames: inside each key's touch target, so targets meet and none is cut. */
private const val KEY_GAP_DP = 3

/**
 * keys in rows of columns, in their order, each key an equal share of the row wide and at least KEY_DP high
 * (taller if its label needs it, under a large font). A short last row keeps the columns of the rows above it.
 * The key's whole cell is its touch target and its semantics node; its frame is drawn KEY_GAP_DP inside the
 * cell, so the gaps between frames are still keys. Before M5-83 the gap sat outside a 40 dp key: rows 46 dp
 * apart, Compose's 48 dp touch targets overlapping and cut to 46 and 40 dp (run 41279169126), and rows of
 * seven and eight keys narrower than 48 dp on a 360 dp phone.
 */
@Composable
private fun KeyGrid(keys: String, columns: Int, enabled: Boolean, sensitive: Boolean, press: (Char) -> Unit) {
    Column {
        for (start in keys.indices step columns) {
            Row(Modifier.fillMaxWidth()) {
                for (index in start until start + columns) {
                    if (index < keys.length) {
                        val key = keys[index]
                        Key(keyLabel(key), enabled, sensitive) { press(key) }
                    } else {
                        Spacer(Modifier.weight(1f))
                    }
                }
            }
        }
    }
}

/** A key's label: the space key says so. */
fun keyLabel(key: Char): String = if (key == ' ') "space" else key.toString()

@Composable
private fun RowScope.Key(label: String, enabled: Boolean, sensitive: Boolean, press: () -> Unit) {
    val cell = Modifier.weight(1f).heightIn(min = KEY_DP.dp)
    // Sensitive: the key's semantics are its role alone, so its press says nothing about the key. A
    // Public key (the dice and the go-ahead code) has its label as its TalkBack label, the button role
    // and a test tag, key_ and its label, for UI Automator (group 15's flow tests).
    val described = if (sensitive) {
        cell.clearAndSetSemantics { role = Role.Button }
    } else {
        cell.semantics { role = Role.Button }.testTag("key_$label")
    }
    val framed = described
        .clickable(enabled = enabled, onClick = press)
        .padding(KEY_GAP_DP.dp)
        .border(1.dp, if (enabled) Color.White else Color.Gray)
    Box(framed, contentAlignment = Alignment.Center) {
        BasicText(label, style = TextStyle(color = if (enabled) Color.White else Color.Gray, fontSize = 18.sp))
    }
}
