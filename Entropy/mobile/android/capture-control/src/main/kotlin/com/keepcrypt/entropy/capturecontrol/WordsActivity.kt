package com.keepcrypt.entropy.capturecontrol

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import com.keepcrypt.entropy.ffi.Secret
import com.keepcrypt.entropy.ffi.WordPage
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.screens.UiState
import com.keepcrypt.entropy.screens.WordsInsert

/**
 * The capture tests' positive control on the words page (tasks/todo.md, M5 group 6; lead decision
 * M5-68 (f)): the first words page of dice-99-words12, vectors/kcr.json's public gate seed, drawn by
 * the app's own words composable (WordsInsert, past its privacy gate) as the test-registry APK draws
 * it, under the TEST REGISTRY strip, whose yellow is the capture tests' known colour, in a plain
 * activity with no FLAG_SECURE, so a capture of it must show its pixels. Test tags are resource ids,
 * as in the app, so ControlTest finds the secret nodes by their tag; its buttons do nothing. The page
 * is a public vector held in the APK, so nothing here is wiped. ControlTest checks that it draws
 * exactly what core's page for the seed's rolls gives. CI only, never released.
 */
class WordsActivity : ComponentActivity() {
    @OptIn(ExperimentalComposeUiApi::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val state = UiState(Screen.Words, insert = WordPage(Secret(dice99Insert1())))
        setContent {
            Box(Modifier.semantics { testTagsAsResourceId = true }) {
                WordsInsert(
                    state,
                    testRegistry = true,
                    passGate = {},
                    onPrevious = {},
                    onNext = {},
                    onOverview = {},
                    onReadback = {},
                    onBackToReadback = {},
                    onBackupDone = {},
                )
            }
        }
    }
}

/**
 * dice-99-words12's insert 1 as core gives it, in the word page's layout (ffi/src/wire.rs, "Word
 * page"; Core.kt's WordPage reads it), from vectors/braille.json's entry for the seed's first word
 * (kcr.json's mnemonic): its SeedBook number, its letters, the cells of faces 1-5, face 5 lighter and
 * the mirror partners of faces 3 and 4.
 */
private fun dice99Insert1(): ByteArray {
    val word = "various"
    val head = byteArrayOf(
        1, 12, 1, 1, 1, // insert 01 of a 12-word seed, device 1 of 1, face 6's engraved number 01
        0x07, 0x8D.toByte(), // SeedBook 1933, big-endian
        word.length.toByte(),
    )
    // Faces 1-5, four bytes each: the letter, its dots (its cell minus U+2800: dot d at bit d - 1),
    // the lighter flag (the letter on face 5) and the mirror partner (0 for none).
    val faces = byteArrayOf(
        'v'.code.toByte(), 0x27, 0, 0,
        'a'.code.toByte(), 0x01, 0, 0,
        'r'.code.toByte(), 0x17, 0, 'w'.code.toByte(),
        'i'.code.toByte(), 0x0A, 0, 'e'.code.toByte(),
        'o'.code.toByte(), 0x15, 1, 0,
    )
    return head + word.encodeToByteArray() + faces
}
