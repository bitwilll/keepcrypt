package com.keepcrypt.entropy.ffi

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** A reply body built field by field, as wire.rs lays fields out (big-endian; a text its length, then its bytes). */
internal class Body {
    private val bytes = ArrayList<Byte>()

    fun byte(value: Int): Body = also { bytes.add(value.toByte()) }

    fun u16(value: Int): Body = byte(value shr 8).byte(value)

    fun u32(value: Long): Body = also { for (shift in 24 downTo 0 step 8) byte((value shr shift).toInt()) }

    fun u64(value: Long): Body = also { for (shift in 56 downTo 0 step 8) byte((value shr shift).toInt()) }

    fun raw(value: ByteArray): Body = also { for (b in value) bytes.add(b) }

    fun text(value: String): Body = value.encodeToByteArray().let { byte(it.size).raw(it) }

    fun reader(): Reader = Reader(bytes.toByteArray(), 0)
}

/**
 * Wire.kt's decoders on bodies built here from wire.rs's layouts and the vectors (tasks/todo.md, M5
 * group 13): every layout a reply has, each read whole (Reader.end), with seal.json's vector 1 card
 * field for field and braille.json's abandon page; no call reaches the bridge. A body that is not
 * its layout halts, which WireMalformedTest proves in a process of its own.
 */
class WireTest {
    /** Core's status byte, before any layout: the replies WireMalformedTest's cases each break. */
    @Test
    fun aReplyIsItsStatusByteThenItsLayout() {
        assertEquals(5, done(Core.decode(byteArrayOf(0, 5)) { it.byte() }))
        done(Core.decode(byteArrayOf(0)) { })
        assertEquals(Refusal.WrongCode, refused(Core.decode(byteArrayOf(1, 2)) { }))
        assertIs<Reply.Discarded>(Core.decode(byteArrayOf(2)) { })
        assertFailsWith<KcHalt> { Core.decode(byteArrayOf(3)) { } }
    }

    @Test
    fun theSealCardIsSealJsonsVector1() {
        val vector = vector("seal.json")["vectors"].list[0]
        val rows = vector["grid"].list.map { row -> row.text.fold0() }
        val body = Body()
        for (row in rows) body.byte(row)
        body.byte(vector["colour_index"].int).raw(vector["seal_id"].text.encodeToByteArray()).text(vector["seal_id_braille"].text)
        val reader = body.reader()
        val card = reader.sealCard()
        reader.end()
        assertEquals("5E0G7J6X", card.sealId)
        assertEquals(vector["seal_id"].text, card.sealId)
        assertEquals(vector["colour_index"].int, card.colourIndex)
        assertEquals(vector["seal_id_braille"].text, card.sealIdBraille)
        val tag = vector["seal_tag_hex"].hex()
        for (row in 0 until 8) {
            for (column in 0 until 8) {
                assertEquals(vector["grid"].list[row].text[column] == '#', card.isFilled(row, column), "cell " + row + "," + column)
                assertEquals(gridFilled(tag, row, column), card.isFilled(row, column), "cell " + row + "," + column + " from T")
            }
        }
    }

    /** A grid row as its byte: '#' filled, most significant bit first. */
    private fun String.fold0(): Int {
        var byte = 0
        for (c in this) byte = (byte shl 1) or (if (c == '#') 1 else 0)
        return byte
    }

    @Test
    fun aQrMatrixIsItsSideThenItsBitsRowByRow() {
        val side = 21
        val bits = ByteArray((side * side + 7) / 8)
        val dark = setOf(0 to 0, 20 to 0, 0 to 20, 7 to 3, 20 to 20)
        for ((x, y) in dark) {
            val i = y * side + x
            bits[i / 8] = (bits[i / 8].toInt() or (0x80 shr (i % 8))).toByte()
        }
        val reader = Body().byte(side).raw(bits).reader()
        val matrix = reader.qrMatrix()
        reader.end()
        assertEquals(side, matrix.side)
        for (y in 0 until side) {
            for (x in 0 until side) assertEquals((x to y) in dark, matrix.isDark(x, y), "module " + x + "," + y)
        }
        matrix.wipe()
        assertTrue((0 until side).none { x -> (0 until side).any { y -> matrix.isDark(x, y) } }, "wiped")
    }

    @Test
    fun aRegistryHeaderAndTheGoAheadResults() {
        val header = Body().u64(4).u32(20260301).u32(7).byte(1)
        val read = header.reader().registry()
        assertEquals(4UL, read.number)
        assertEquals(20260301, read.date)
        assertEquals(7L, read.count)
        assertEquals(Freshness.Stale, read.freshness)
        val clear = Body().byte(0).byte(0).reader()
        val revealed = assertIs<Revealed.Clear>(clear.revealed())
        clear.end()
        assertNull(revealed.registry)
        val collision = Body().byte(1).byte(1).u64(2).u32(20260302).u32(0).byte(2).reader()
        val found = assertIs<Revealed.Collision>(collision.revealed())
        collision.end()
        assertEquals(2UL, found.registry?.number)
        assertEquals(20260302, found.registry?.date)
        assertEquals(0L, found.registry?.count)
        assertEquals(Freshness.Future, found.registry?.freshness)
        assertEquals(Freshness.Current, Body().u64(1).u32(1).u32(1).byte(0).reader().registry().freshness)
    }

    @Test
    fun aWordPageIsBrailleJsonsInsert() {
        val entry = braille()["words"].named0("abandon")
        val body = Body().byte(1).byte(12).byte(1).byte(1).byte(1).u16(entry["number"].int).text("abandon")
        for (n in 1..5) {
            val letter = entry["faces"].list[n - 1].let { if (it.isNull) 0 else it.text[0].code }
            val mirror = entry["mirror_partners"].list[n - 1].let { if (it.isNull) 0 else it.text[0].code }
            val dots = if (letter == 0) 0 else dotsOf(Char(letter))
            body.byte(letter).byte(dots).byte(if (entry["lighter_face"].isNull || entry["lighter_face"].int != n) 0 else 1).byte(mirror)
        }
        val reader = body.reader()
        val page = reader.wordPage()
        reader.end()
        assertEquals(1, page.position)
        assertEquals(12, page.count)
        assertEquals(1, page.device)
        assertEquals(1, page.devices)
        assertEquals(1, page.sequence)
        assertEquals(1, page.seedbook)
        assertEquals("abandon", asciiOf(page.word()))
        assertEquals("aband", (1..5).map { page.face(it).letter }.joinToString(""))
        assertEquals(dotsOf('n'), page.face(4).dots)
        assertTrue(page.face(5).isLighter && !page.face(4).isLighter)
        assertEquals('f', page.face(5).mirrorPartner)
        assertNull(page.face(1).mirrorPartner)
        assertTrue((1..5).none { page.face(it).isBlank })
        page.wipe()
        assertEquals(0, page.position)
    }

    /** The list's entry whose word is word. */
    private fun Json.named0(word: String): Json = list.first { it["word"].text == word }

    @Test
    fun theReadBackResults() {
        val match = assertIs<Readback.Match>(Body().byte(0).byte(1).reader().readback())
        assertTrue(match.complete)
        val reader = Body().byte(1).byte(0).byte(0).byte(0).byte(1).byte(0).byte(0).byte(2).byte(0).byte(0)
            .byte(4).byte(1).byte(2).reader()
        val mismatch = assertIs<Readback.Mismatch>(reader.readback())
        reader.end()
        assertEquals(listOf(Verdict.Ok, Verdict.MirrorMisread, Verdict.ShouldBeBlank, Verdict.WrongLetter), mismatch.faces.map { it.verdict })
        assertEquals(1, mismatch.faces[3].missingDots)
        assertEquals(2, mismatch.faces[3].extraDots)
        assertEquals(Verdict.ShouldHaveLetter, Body().byte(1).byte(3).byte(0).byte(0).raw(ByteArray(9)).reader().readback().let { (it as Readback.Mismatch).faces[0].verdict })
    }

    @Test
    fun theSummaryTheExportAndCheckABackup() {
        val wallet = vector("watchonly.json")["wallets"].named("abandon")
        val summary = Body().raw(wallet["fingerprint"].hex()).text(wallet["first_receive_address"].text)
        val read = summary.reader().summary()
        assertContentEquals(hexBytes("73c5da0a"), read.fingerprint)
        assertEquals(wallet["first_receive_address"].text, read.firstAddress)
        val export = Body().raw(wallet["fingerprint"].hex()).text(wallet["first_receive_address"].text).byte(1)
            .byte(21).raw(ByteArray(56)).byte(25).raw(ByteArray(79)).reader()
        val watchOnly = export.watchOnly()
        export.end()
        assertTrue(watchOnly.passphraseUsed)
        assertEquals(21, watchOnly.account.side)
        assertEquals(25, watchOnly.descriptors.side)
        assertEquals(wallet["first_receive_address"].text, watchOnly.summary.firstAddress)
        val vector = vector("seal.json")["vectors"].list[0]
        val opened = Body().raw(wallet["fingerprint"].hex())
        for (row in vector["grid"].list) opened.byte(row.text.fold0())
        opened.byte(vector["colour_index"].int).raw(vector["seal_id"].text.encodeToByteArray()).text(vector["seal_id_braille"].text)
            .byte(29).raw(ByteArray((29 * 29 + 7) / 8))
        val reader = opened.reader()
        val backup = reader.openedBackup()
        reader.end()
        assertContentEquals(wallet["fingerprint"].hex(), backup.fingerprint)
        assertEquals(vector["seal_id"].text, backup.seal.sealId)
        assertEquals(29, backup.recheck.side)
    }

    @Test
    fun theBackupsPassphrasePagesConfirmAndFile() {
        val page = Body().text("fly fancy hollow control").reader().secretText()
        assertEquals("fly fancy hollow control", asciiOf(page))
        val body = Body().byte(3)
        for (choice in listOf("fly", "fancy", "hollow", "control")) body.text(choice)
        body.byte(8)
        for (choice in listOf("general", "vast", "million", "pipe")) body.text(choice)
        val reader = body.reader()
        val challenge = reader.challenge()
        reader.end()
        assertEquals(listOf(3, 8), challenge.questions.map { it.position })
        assertEquals("pipe", asciiOf(challenge.questions[1].choices[3]))
        challenge.wipe()
        assertEquals(0, challenge.questions[0].choices[0][0].toInt(), "wiped")
        val file = Body().text("keepcrypt-backup-x.age").raw(byteArrayOf(1, 2, 3)).reader().backupFile()
        assertEquals("keepcrypt-backup-x.age", file.name)
        assertContentEquals(byteArrayOf(1, 2, 3), file.bytes)
        assertTrue(Body().byte(1).reader().flag())
    }

    @Test
    fun theProgressCAndD() {
        val device = Body().u64(256).u64(256).reader().deviceProgress()
        assertEquals(256, device.creditedBits)
        assertEquals(256, device.requiredBits)
        val dice = Body().u16(1).u16(50).u32(2585).reader().diceProgress()
        assertEquals(listOf(1, 50), listOf(dice.rolls, dice.minimum))
        assertEquals(2585L, dice.millibits)
        assertNull(Body().reader().commitment())
        assertEquals(32, Body().raw(ByteArray(32) { it.toByte() }).reader().commitment()?.size)
        assertEquals(31, Body().raw(ByteArray(32) { it.toByte() }).reader().deviceLeg()[31].toInt())
    }
}
