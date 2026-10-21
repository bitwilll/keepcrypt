package com.keepcrypt.entropy.screens

import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
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
// keyboard never opens. Each pad's keys come in a fixed order, and what it types goes into a PadEntry,
// never a String, which hands it to Core as a Secret. On Protected screens (the letter pad's read-back
// and backup-passphrase entry, the ASCII pad's BIP39 passphrase) a key's semantics hold its role alone:
// nothing about which key was pressed reaches an accessibility event. The dice pad and the go-ahead
// code's pad are on Public screens.

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
 */
class PadEntry(val keys: String, val capacity: Int) {
    private val bytes = ByteArray(capacity)

    /** How many keys are typed. */
    var length: Int = 0
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

/** The dice pad (a Public screen): a face replaces the pick. Disabled at 256 rolls by its screen. */
@Composable
fun DicePad(entry: PadEntry, enabled: Boolean, changed: () -> Unit) {
    KeyGrid(DICE_KEYS, columns = 3, enabled = enabled, sensitive = false) { key ->
        if (entry.replace(key)) changed()
    }
}

/** The letter pad (Protected screens). */
@Composable
fun LetterPad(entry: PadEntry, changed: () -> Unit) {
    KeyGrid(LETTER_KEYS, columns = 7, enabled = true, sensitive = true) { key ->
        if (entry.type(key)) changed()
    }
}

/** The go-ahead code's pad (a Public screen: the code is no secret). */
@Composable
fun CrockfordPad(entry: PadEntry, changed: () -> Unit) {
    KeyGrid(CROCKFORD_KEYS, columns = 8, enabled = true, sensitive = false) { key ->
        if (entry.type(key)) changed()
    }
}

/** The ASCII pad (a Protected screen), one page of its keys at a time; its screen keeps the page index. */
@Composable
fun AsciiPad(entry: PadEntry, page: Int, changed: () -> Unit) {
    KeyGrid(asciiPage(page), columns = 8, enabled = true, sensitive = true) { key ->
        if (entry.type(key)) changed()
    }
}

/**
 * keys in rows of columns, in their order. Each row is the width it is given and each key a square of
 * at most KEY_DP: a row of eight (the go-ahead code's) is 368 dp at full size, wider than a 360 dp
 * phone, so every column takes an equal share of the row and a key shrinks to its share where that is
 * smaller; a short last row keeps the columns of the rows above it.
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
                        Spacer(Modifier.weight(1f, fill = false))
                    }
                }
            }
        }
    }
}

/** A key's side at most: its side wherever its row has room for it. */
private const val KEY_DP = 40

/** A key's label: the space key says so. */
fun keyLabel(key: Char): String = if (key == ' ') "space" else key.toString()

@Composable
private fun RowScope.Key(label: String, enabled: Boolean, sensitive: Boolean, press: () -> Unit) {
    val framed = Modifier
        .weight(1f, fill = false)
        .padding(3.dp)
        .widthIn(max = KEY_DP.dp)
        .aspectRatio(1f)
        .border(1.dp, if (enabled) Color.White else Color.Gray)
    // Sensitive: the key's semantics are its role alone, so its press says nothing about the key. A
    // Public key (the dice and the go-ahead code) has its label as its TalkBack label, the button role
    // and a test tag, key_ and its label, for UI Automator (group 15's flow tests).
    val described = if (sensitive) {
        framed.clearAndSetSemantics { role = Role.Button }
    } else {
        framed.semantics { role = Role.Button }.testTag("key_$label")
    }
    Box(described.clickable(enabled = enabled, onClick = press), contentAlignment = Alignment.Center) {
        BasicText(label, style = TextStyle(color = if (enabled) Color.White else Color.Gray, fontSize = 18.sp))
    }
}
