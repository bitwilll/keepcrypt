package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Refusal
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Verdict
import com.keepcrypt.entropy.ffi.Words
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Every refusal table the screens show, against vectors/kcr.json and core's own verdicts (tasks/todo.md,
 * Stage U's U2g), over the real slot: every go-ahead QR text kcr.json carries (too long, a bad checksum,
 * multi-part, mixed case, another type, a non-shortest head, a trailing byte, and those core accepts:
 * another seal's bucket, a clear one, a collision) scanned on the check of its dice-50-words12 seed, each
 * refusal back on the scan screen with the same check and its one line, each verdict core gives as kcr.json
 * says; every snapshot kcr.json carries loaded through Home's Load registry snapshot, each refusal named
 * on the result with core's text, each accepted one loaded with its number, date and count. And the
 * metal read-back: every mirror pair the vector seeds' words reach typed on the face that holds its
 * partner (e and i, d and f both ways; h read as j and r read as w, since no vector word holds j or w in
 * its first four letters: core's every_mirror_flip_is_one_mirror_misread_and_names_the_279 checks every
 * flip), each a mirror misread on that face alone; and each insert read back with the next insert's
 * word (an insert punched in the wrong place), a mismatch whose Read it again then matches. The code
 * entry's, the confirm's, Check a backup's entry's and the BIP39 passphrase's refusals are their classes'
 * (CheckScreensTest, BackupScreensTest, CheckBackupScreensTest, ExportScreensTest). Each test leaves
 * the slot at home.
 */
class RefusalTablesTest {
    @AfterTest
    fun emptyTheSlot() {
        assertTrue(Core.wipeAll() is Reply.Done)
    }

    /** A fresh Rig on the scan screen of the check of kcr.json's dice-50-words12 (its rolls on the pad), no snapshot loaded. */
    private fun scanning(): Rig {
        val rig = Rig().toHome().begin(Mode.DiceOnly, Words.Twelve)
        for (face in kcrRolls(DICE_50)) {
            rig.press(face)
            rig.model.confirmRoll()
        }
        rig.model.diceDone()
        rig.worker.run()
        rig.model.checkNow()
        rig.model.showCheckQr()
        rig.model.scanQr()
        assertEquals(Screen.Scan, rig.screen)
        return rig
    }

    @Test
    fun everyGoAheadQrVectorOnTheScanScreen() {
        val vectors = kcrProofUrVectors()
        assertTrue(vectors.count { it.refusal != null } >= 7 && vectors.count { it.refusal == null } >= 5, "kcr.json's go-ahead QR texts")
        for (vector in vectors) {
            val what = vector.name
            val rig = scanning()
            val request = assertNotNull(rig.model.state.value.checkRequest)
            rig.model.onGoAheadText(vector.input)
            assertEquals(Screen.Working, rig.screen, "$what: core's check of the text, a long call")
            rig.worker.run()
            val state = rig.model.state.value
            val verdict = vector.refusal ?: vector.lookup(DICE_50)
            when (verdict) {
                "clear" -> {
                    assertEquals(Screen.CheckResult, state.screen, what)
                    assertTrue(state.proof, "$what: the result is the scanned proof's")
                }
                "collision" -> assertEquals(Screen.Collision, state.screen, what)
                else -> {
                    val refusal = if (verdict == "wrong_bucket") Refusal.WrongBucket else Refusal.valueOf(verdict)
                    assertEquals(Screen.Scan, state.screen, "$what: a refused text returns to the scan screen")
                    assertEquals(refusal, state.scanRefusal, what)
                    assertEquals(SCAN_NOT_ACCEPTED, scanLine(state), "$what: its line")
                    assertSame(request, state.checkRequest, "$what: the same check and nonce")
                    assertTrue(rig.model.held.value, "$what: the session stays")
                }
            }
            assertTrue(Core.wipeAll() is Reply.Done)
        }
    }

    @Test
    fun everySnapshotVectorThroughLoadRegistrySnapshot() {
        val vectors = kcrSnapshotVectors()
        assertTrue(vectors.count { it.refusal != null } >= 30 && vectors.count { it.refusal == null } >= 2, "kcr.json's snapshots")
        val rig = Rig().toHome()
        for (vector in vectors) {
            val what = vector.name
            val bytes = hexBytes(vector.input)
            rig.model.loadSnapshot(FakePickers())
            rig.model.snapshotPicked(FakeFile("$what.kcr", bytes.size.toLong(), bytes))
            rig.model.appResumed()
            rig.worker.run()
            val state = rig.model.state.value
            assertEquals(Screen.Snapshot, state.screen, what)
            val refusal = vector.refusal
            if (refusal == null) {
                assertNull(state.snapshotRefusal, "$what: core accepts it")
                val loaded = assertNotNull(state.loaded, "$what: loaded")
                assertEquals(vector.field("number").toULong(), loaded.number, "$what: its number")
                assertEquals(vector.field("date").toInt(), loaded.date, "$what: its date")
                assertEquals(vector.field("count").toLong(), loaded.count, "$what: its count")
            } else {
                assertEquals(Refusal.valueOf(refusal), state.snapshotRefusal, what)
                assertEquals(SNAPSHOT_REJECTED, snapshotRefusalText(Refusal.valueOf(refusal))?.take(SNAPSHOT_REJECTED.length), "$what: core's text")
            }
            rig.model.snapshotDone()
            assertEquals(Screen.Home, rig.screen, what)
        }
    }

    /** From Home: kcr.json's dice-99-words12 to its read-back's first entry, through its words. */
    private fun readingBack(): Rig {
        val rig = Rig().toHome().toSkippedResult(DICE_99).toWords()
        repeat(INSERTS_PER_DEVICE - 1) { rig.model.nextPage() }
        rig.model.startReadback()
        assertEquals(Screen.ReadbackEntry, rig.screen)
        return rig
    }

    /** On the entry: letters typed and Done; the verdicts on faces 1-4 of the mismatch that follows, or null for a match. */
    private fun readBack(rig: Rig, letters: String): List<Verdict>? {
        rig.press(letters)
        rig.model.readbackTyped()
        if (rig.screen == Screen.ReadbackEntry && rig.model.state.value.matched) return null
        assertEquals(Screen.ReadbackMismatch, rig.screen, "a read-back that does not match")
        val mismatch = assertNotNull(rig.model.state.value.mismatch)
        return (1..4).map { mismatch.face(it).verdict }
    }

    @Test
    fun everyMirrorPairAndAWrongInsertOnTheReadback() {
        val words = kcrWords(DICE_99)
        val rig = readingBack()
        val flipped = mutableSetOf<Char>()
        for ((index, word) in words.withIndex()) {
            val insert = index + 1
            val letters = word.take(4)
            for ((at, letter) in letters.withIndex()) {
                val mirror = MIRRORS[letter] ?: continue
                val misread = letters.substring(0, at) + mirror + letters.substring(at + 1)
                val verdicts = assertNotNull(readBack(rig, misread), "insert $insert: $letter read as $mirror matched")
                assertEquals(Verdict.MirrorMisread, verdicts[at], "insert $insert: $letter read as $mirror")
                assertTrue(verdicts.withIndex().all { (face, verdict) -> face == at || verdict == Verdict.Ok }, "insert $insert: the other faces")
                rig.model.readbackAgain()
                flipped.add(letter)
            }
            val next = words[insert % words.size].take(4)
            val wrong = assertNotNull(readBack(rig, next), "insert $insert read with the next insert's word matched")
            assertFalse(wrong.all { it == Verdict.Ok }, "insert $insert: the wrong insert's faces")
            rig.model.readbackAgain()
            assertEquals(Screen.ReadbackEntry, rig.screen, "insert $insert: Read it again")
            assertNull(readBack(rig, letters), "insert $insert: its own letters after the wrong ones")
            rig.model.readbackNext()
        }
        assertEquals(Screen.ReadbackDone, rig.screen, "every insert read back")
        assertEquals(setOf('e', 'i', 'd', 'f', 'h', 'r'), flipped, "the mirror flips the vector words reach")
    }

    private companion object {
        const val DICE_50 = "dice-50-words12"
        const val DICE_99 = "dice-99-words12"

        /** The mirror pairs (CLAUDE.md, Braille): each letter and the letter its cell mirrors to. */
        val MIRRORS = mapOf('e' to 'i', 'i' to 'e', 'd' to 'f', 'f' to 'd', 'h' to 'j', 'j' to 'h', 'r' to 'w', 'w' to 'r')
    }
}
