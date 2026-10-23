package com.keepcrypt.entropy.ffi

import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Group 11's vectors again, through Kotlin and the bridge (tasks/todo.md, M5 group 13): each gate
 * seed's dice-only ceremony gives kcr.json's Seal ID, its seal card's grid and colour from kcr.json's
 * T and its Seal ID in braille by braille.json's text rule; after Skip, its words are kcr.json's
 * mnemonic and every page is braille.json's insert (the SeedBook number, faces 1-5 with their dots,
 * blanks, the lighter face and mirror partners, the device and sequence); every insert reads back
 * from its own first four letters. The go-ahead code a checker computes from the drawn check request
 * reveals the same words in QrRoundTripTest (the request is a QR matrix, read with ZXing on the JVM).
 */
class DiceVectorsTest {
    @BeforeTest
    fun home() {
        done(Core.wipeAll())
    }

    @Test
    fun eachGateSeedGivesItsSealCardWordsAndBraille() {
        for (name in listOf("dice-50-words12", "dice-99-words12", "dice-99-words24")) {
            sealed(name)
            val card = done(Core.seal())
            assertEquals(seed(name, "seal_id"), card.sealId, name)
            val tag = hexBytes(seed(name, "seal_tag_hex"))
            assertEquals((tag[0].toInt() and 0xFF) % 8, card.colourIndex, name)
            for (row in 0 until 8) {
                for (column in 0 until 8) assertEquals(gridFilled(tag, row, column), card.isFilled(row, column), name)
            }
            assertEquals(brailleText(card.sealId.lowercase()), card.sealIdBraille, name)
            done(Core.skipCheck())
            val mnemonic = seed(name, "mnemonic").split(" ")
            assertEquals(mnemonic, words(), name)
            val positions = braille()["positions"][if (mnemonic.size == 24) "words_24" else "words_12"].list
            assertEquals(mnemonic.size, positions.size)
            for ((at, word) in positions.zip(mnemonic)) {
                val page = done(Core.wordPage(at["position"].int))
                val entry = braille()["words"].list.first { it["word"].text == word }
                assertEquals(entry["number"].int, page.seedbook, word)
                assertEquals(mnemonic.size, page.count)
                assertEquals(at["device"].int, page.device)
                assertEquals(at["devices"].int, page.devices)
                assertEquals(at["sequence"].int, page.sequence)
                val lighter = entry["lighter_face"]
                for (n in 1..5) {
                    val face = page.face(n)
                    val letter = entry["faces"].list[n - 1].let { if (it.isNull) null else it.text[0] }
                    assertEquals(letter, face.letter, word)
                    assertEquals(letter == null, face.isBlank, word)
                    assertEquals(if (letter == null) 0 else dotsOf(letter), face.dots, word)
                    assertEquals(!lighter.isNull && lighter.int == n, face.isLighter, word)
                    val mirror = entry["mirror_partners"].list[n - 1].let { if (it.isNull) null else it.text[0] }
                    assertEquals(mirror, face.mirrorPartner, word)
                }
                page.wipe()
            }
            readBackAll()
            done(Core.end())
        }
    }

    /** The dice screen's counts over the bridge: after the first roll and after the last. */
    @Test
    fun theDiceCountsAndNoDeviceLegInDiceOnlyMode() {
        done(Core.start(Words.Twelve, Mode.DiceOnly))
        val device = done(Core.deviceProgress())
        assertEquals(listOf(0, 0), listOf(device.creditedBits, device.requiredBits))
        done(Core.commit())
        assertTrue(done(Core.commitment()) == null, "no C in dice-only mode")
        done(Core.startDice())
        val rolls = seed("dice-50-words12", "rolls")
        done(Core.pushRoll(rolls[0] - '0'))
        val first = done(Core.diceProgress())
        assertEquals(listOf(1, 50), listOf(first.rolls, first.minimum))
        assertEquals(2585L, first.millibits)
        for (roll in rolls.drop(1)) done(Core.pushRoll(roll - '0'))
        val last = done(Core.diceProgress())
        assertEquals(listOf(50, 50), listOf(last.rolls, last.minimum))
        assertEquals(50L * 2585, last.millibits)
        done(Core.finish())
        assertEquals(seed("dice-50-words12", "seal_id"), done(Core.seal()).sealId)
        done(Core.discard())
    }
}
