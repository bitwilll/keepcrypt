package com.keepcrypt.entropy.ffi

import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull

/**
 * Group 11's test-registry paths, through Kotlin and the bridge (tasks/todo.md, M5 group 13): the JVM
 * tests load the host library built with keepcrypt-core's test-registry feature
 * (scripts/android-rust.sh withTestRegistry), which pins the test key. with-dice-50 loaded, Stale at
 * an M5 date, catches dice-50-words12 before any word page: a collision with its header, and a
 * restart that needs 99 rolls, whose dice-99-words12 seed the same snapshot clears. kcr.json's two
 * go-ahead QR texts (its ur fields, lead decision M5-42): clear-empty-bucket's reveals
 * dice-99-words12's words, Stale at an M5 date; it is another bucket's for dice-50-words12, whose
 * check stays; collision-dice-50's gives a collision; text that is no UR is refused. A wrong typed
 * code is refused, and a malformed one.
 */
class RegistryTest {
    @BeforeTest
    fun home() {
        done(Core.wipeAll())
    }

    /** The header kcr.json gives for section's name (a snapshot's count is its seals, a proof's its bucket's k). */
    private fun assertHeader(section: String, name: String, freshness: Freshness, got: RegistryHeader?) {
        val expect = kcr()[section].named(name)["expect"]
        val header = assertNotNull(got, name)
        assertEquals(expect["number"].long.toULong(), header.number, name)
        assertEquals(expect["date"].int, header.date, name)
        assertEquals(expect[if (section == "snapshots") "count" else "k"].long, header.count, name)
        assertEquals(freshness, header.freshness, name)
    }

    private fun proofUr(name: String): String = kcr()["proofs"].named(name)["ur"].text

    @Test
    fun aLoadedSnapshotCatchesDice50AndClearsDice99() {
        // A refusal here (NoRegistryKey) is a host library without the test key: done names it.
        val loaded = done(Core.loadSnapshot(M5_DAY, kcr()["snapshots"].named("with-dice-50")["kcr_hex"].hex()))
        assertHeader("snapshots", "with-dice-50", Freshness.Stale, loaded)
        sealed("dice-50-words12")
        done(Core.startCheck())
        val caught = assertIs<Revealed.Collision>(done(Core.revealSnapshot(M5_DAY)))
        assertHeader("snapshots", "with-dice-50", Freshness.Stale, caught.registry)
        done(Core.start(Words.Twelve, Mode.DiceOnly))
        done(Core.commit())
        done(Core.startDice())
        assertEquals(99, done(Core.diceProgress()).minimum, "Add fresh entropy: 0 / 99")
        done(Core.discard())
        sealed("dice-99-words12")
        done(Core.startCheck())
        val clear = assertIs<Revealed.Clear>(done(Core.revealSnapshot(M5_DAY)))
        assertHeader("snapshots", "with-dice-50", Freshness.Stale, clear.registry)
        assertEquals(seed("dice-99-words12", "mnemonic").split(" "), words())
        done(Core.end())
    }

    @Test
    fun theGoAheadQrTextsRevealRefuseAndCatch() {
        sealed("dice-99-words12")
        done(Core.startCheck())
        assertEquals(Refusal.NotUr, refused(Core.revealProof(M5_DAY, "not a ur")))
        val clear = assertIs<Revealed.Clear>(done(Core.revealProof(M5_DAY, proofUr("clear-empty-bucket"))))
        assertHeader("proofs", "clear-empty-bucket", Freshness.Stale, clear.registry)
        assertEquals(seed("dice-99-words12", "mnemonic").split(" "), words())
        done(Core.end())

        sealed("dice-50-words12")
        done(Core.startCheck())
        assertEquals(Refusal.WrongBucket, refused(Core.revealProof(VECTOR_DAY, proofUr("clear-empty-bucket"))))
        val caught = assertIs<Revealed.Collision>(done(Core.revealProof(VECTOR_DAY, proofUr("collision-dice-50"))))
        assertHeader("proofs", "collision-dice-50", Freshness.Current, caught.registry)
    }

    /** The same two texts upper case, as the P4 PNGs carry them (alphanumeric QRs, M5-42 as amended), reveal alike. */
    @Test
    fun theUpperCaseGoAheadQrTextsRevealAndCatchAlike() {
        sealed("dice-99-words12")
        done(Core.startCheck())
        assertIs<Revealed.Clear>(done(Core.revealProof(M5_DAY, proofUr("clear-empty-bucket").uppercase())))
        assertEquals(seed("dice-99-words12", "mnemonic").split(" "), words())
        done(Core.end())

        sealed("dice-50-words12")
        done(Core.startCheck())
        assertIs<Revealed.Collision>(done(Core.revealProof(VECTOR_DAY, proofUr("collision-dice-50").uppercase())))
    }

    @Test
    fun aWrongOrMalformedTypedCodeIsRefusedAndTheCheckStays() {
        sealed("dice-50-words12")
        done(Core.startCheck())
        assertEquals(Refusal.WrongCode, refused(Core.revealCode(secretOf("ZZZZ-ZZZZ"))))
        assertEquals(Refusal.MalformedCode, refused(Core.revealCode(secretOf("0000"))))
        assertIs<Revealed.Collision>(done(Core.revealProof(VECTOR_DAY, proofUr("collision-dice-50"))), "the check stays")
    }
}
