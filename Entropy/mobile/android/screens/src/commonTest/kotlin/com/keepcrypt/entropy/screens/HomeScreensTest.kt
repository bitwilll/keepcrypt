package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Freshness
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Refusal
import com.keepcrypt.entropy.ffi.RefusalGroup
import com.keepcrypt.entropy.ffi.Reply
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
 * The CeremonyModel transitions of Home's Load registry snapshot and About (tasks/todo.md, M5 groups 15 and
 * 18; lead decision M5-48; docs/mobile-apps.md, step 4 and "Reading a snapshot"; the Pi's
 * snapshot-loaded, snapshot-failed and About), over the real slot through Core and the host library (the
 * test-registry build's, which trusts the test key): Load registry snapshot opening the open-document
 * picker under the picker rule; a file refused before any byte is read unless its name ends in .kcr (any
 * letter case) and its provider sizes it within core's limit, and after a read that fails or runs past
 * the limit (its bytes zeroed), Home saying why; the read on the worker behind "Working..." (lead
 * decision M5-70 (g)): a slow read holding no input and no second file, a leave or going online during
 * it zeroing what it read with nothing sent to core, and a file longer or shorter than its provider
 * reports read whole; kcr.json's with-dice-50 verified on the worker behind "Working...", its bytes
 * zeroed, its result showing its number, date and count, Current on kcr.json's date and Stale with its
 * warning on a later one, then Home naming it; a snapshot that does not verify refused with core's text,
 * the one loaded before kept; a discard during the load and wipeAll while it waits, each zeroing the
 * bytes read though core's load was never made; About's version (the app's versionName), flavour
 * and source address, Back to Home, and going online there; and the refusal texts, core's own
 * (core/src/error.rs) but the phone's line for a build with no registry key. Each test leaves the slot at
 * home.
 */
class HomeScreensTest {
    @AfterTest
    fun emptyTheSlot() {
        assertTrue(Core.wipeAll() is Reply.Done)
    }

    /** kcr.json's snapshot named name as the open-document picker gives a file: named name.kcr, its provider's size its own. */
    private fun kcrFile(name: String, bytes: ByteArray = kcrSnapshot(name)): FakeFile = FakeFile(name + ".kcr", bytes.size.toLong(), bytes)

    @Test
    fun homeOffersLoadRegistrySnapshotUnderThePickerRuleAndNamesNoSnapshotAtFirst() {
        val rig = Rig().toHome()
        val home = rig.model.state.value
        assertNull(home.loaded)
        assertEquals("No registry snapshot loaded", homeSnapshotLine(home.loaded))
        val pickers = FakePickers()
        rig.model.loadSnapshot(pickers)
        assertEquals(1, pickers.snapshotOpens, "Load registry snapshot opens the open-document picker")
        assertEquals(0, pickers.opens, "not Check a backup's")
        rig.model.appLeft()
        assertEquals(Screen.Home, rig.screen, "the picker over the app is no leaving (the picker rule)")
        assertNull(rig.model.state.value.overlay)
        rig.model.appReturned()
        rig.model.snapshotPicked(null)
        assertEquals(Screen.Home, rig.screen, "a picker left with no file: Home stays")
        assertNull(rig.model.state.value.fileRefusal)
    }

    @Test
    fun aFileIsRefusedByItsNameOrSizeBeforeAnyByteIsReadAndByAReadThatFailsOrRunsPastTheLimit() {
        val rig = Rig().toHome()
        val bytes = kcrSnapshot(WITH_DICE_50)
        val cases = listOf(
            FakeFile("with-dice-50.age", bytes.size.toLong(), bytes) to FileRefusal.NotKcr,
            FakeFile("with-dice-50.kcr.txt", bytes.size.toLong(), bytes) to FileRefusal.NotKcr,
            FakeFile(null, bytes.size.toLong(), bytes) to FileRefusal.NotKcr,
            FakeFile("with-dice-50.kcr", null, bytes) to FileRefusal.NoSize,
            FakeFile("with-dice-50.kcr", Core.SNAPSHOT_MAX_BYTES + 1L, bytes) to FileRefusal.SnapshotTooLarge,
            FakeFile("with-dice-50.kcr", -1L, bytes) to FileRefusal.SnapshotTooLarge,
        )
        for ((file, refusal) in cases) {
            rig.model.snapshotPicked(file)
            assertEquals(Screen.Home, rig.screen)
            assertEquals(refusal, rig.model.state.value.fileRefusal, refusal.name)
            assertEquals(0, file.reads, refusal.name + ": no byte of the file was read")
            assertEquals(0, rig.worker.waiting, refusal.name + ": no read waits on the worker")
        }
        assertTrue(fileRefusalText(FileRefusal.NotKcr).endsWith(" ends in .kcr."))
        val ran = rig.worker.ran
        val unreadable = FakeFile("with-dice-50.kcr", bytes.size.toLong(), null)
        rig.model.snapshotPicked(unreadable)
        rig.worker.run()
        assertEquals(Screen.Home, rig.screen)
        assertEquals(FileRefusal.Unreadable, rig.model.state.value.fileRefusal)
        assertEquals(Core.SNAPSHOT_MAX_BYTES, unreadable.readLimit, "the read stops one byte past core's limit")
        val sizedWrongly = object : PickedFile {
            override val name = "with-dice-50.kcr"
            override val size = bytes.size.toLong()
            var given: ByteArray? = null

            override fun read(limit: Int): ByteArray = ByteArray(limit + 1) { 1 }.also { given = it }
        }
        rig.model.snapshotPicked(sizedWrongly)
        rig.worker.run()
        assertEquals(FileRefusal.SnapshotTooLarge, rig.model.state.value.fileRefusal, "a provider that sized it wrongly is refused too")
        assertTrue(zeroed(sizedWrongly.given), "the bytes read past the limit were zeroed")
        assertEquals(ran + 2, rig.worker.ran, "the two reads ran on the worker, and nothing reached core")
        assertNull(rig.model.state.value.loaded)
    }

    /**
     * A picked snapshot is read on the worker behind "Working...", never on the main thread (lead decision
     * M5-70 (g)): while a slow read lasts, Home's choices and a second file do nothing; a leave or going
     * online during it zeroes what it read, sends nothing to core and ends on the start screen saying why,
     * as any long call's discard does.
     */
    @Test
    fun theReadRunsOnTheWorkerAndADiscardDuringItZeroesWhatItReadAndSendsNothingToCore() {
        val bytes = kcrSnapshot(WITH_DICE_50)
        val rig = Rig().toHome()
        var during: Screen? = null
        val slow = FakeFile(WITH_DICE_50 + ".kcr", bytes.size.toLong(), bytes) { during = rig.screen }
        rig.model.snapshotPicked(slow)
        assertEquals(Screen.Working, rig.screen, "the file is read behind Working...")
        assertEquals(0, slow.reads, "the main thread returned before any byte was read")
        assertEquals(1, rig.worker.waiting, "the read waits on the worker")
        rig.model.about()
        rig.model.back()
        val second = kcrFile(WITH_DICE_50)
        rig.model.snapshotPicked(second)
        assertEquals(Screen.Working, rig.screen, "Home's choices do nothing while the read runs")
        assertEquals(0, second.reads, "a second file picked while the read runs is never read")
        rig.worker.runNext()
        assertEquals(Screen.Working, during, "the read ran while Working... showed")
        assertEquals(1, slow.reads)
        assertEquals(Screen.Working, rig.screen, "core's load follows the read behind Working...")
        assertEquals(1, rig.worker.waiting, "on the worker")
        rig.worker.run()
        assertEquals(Screen.Snapshot, rig.screen)
        assertNotNull(rig.model.state.value.loaded)
        assertTrue(zeroed(slow.given))

        val discards = listOf(
            Notice.Left to { away: Rig -> away.model.appLeft() },
            Notice.Offline to { away: Rig -> away.offline.set(false) },
        )
        for ((notice, discard) in discards) {
            val away = Rig().toHome()
            val ran = away.worker.ran
            val file = FakeFile(WITH_DICE_50 + ".kcr", bytes.size.toLong(), bytes) { discard(away) }
            away.model.snapshotPicked(file)
            away.worker.run()
            assertEquals(1, file.reads, notice.name)
            assertTrue(zeroed(file.given), notice.name + ": what the read gave was zeroed")
            assertEquals(ran + 1, away.worker.ran, notice.name + ": the read alone ran, so nothing reached core")
            away.assertDiscarded(notice, notice.name)
            assertNull(away.model.state.value.loaded, notice.name + ": nothing was loaded")
        }
    }

    /**
     * A file its provider sized wrongly but within core's limit (longer than reported, or shorter) is read
     * whole on the worker, so the snapshot loads; the read's buffer itself is Documents.kt's (ReadUpToTest).
     */
    @Test
    fun aFileLongerOrShorterThanItsProviderReportsIsReadWholeAndLoads() {
        val bytes = kcrSnapshot(WITH_DICE_50)
        val rig = Rig().toHome()
        for ((what, size) in listOf("longer than reported" to 10L, "shorter than reported" to bytes.size + 1000L)) {
            val file = FakeFile(WITH_DICE_50 + ".kcr", size, bytes)
            rig.model.snapshotPicked(file)
            rig.worker.run()
            assertEquals(Screen.Snapshot, rig.screen, what)
            assertNull(rig.model.state.value.snapshotRefusal, what)
            assertEquals(7L, assertNotNull(rig.model.state.value.loaded, what).count, what)
            assertTrue(zeroed(file.given), what + ": the bytes were zeroed once core had them")
            rig.model.snapshotDone()
        }
    }

    @Test
    fun aVerifiedSnapshotLoadsOnTheWorkerItsResultShowsItsHeaderThenHomeNamesIt() {
        val rig = Rig().toHome()
        val bytes = kcrSnapshot(WITH_DICE_50)
        val upper = FakeFile(WITH_DICE_50 + ".KCR", bytes.size.toLong(), bytes)
        rig.model.snapshotPicked(upper)
        assertEquals(Screen.Working, rig.screen, "the file is read behind Working...")
        assertEquals(0, upper.reads, "on the worker")
        rig.worker.runNext()
        assertEquals(1, upper.reads, "a name ending in .KCR, any letter case, as the Pi lists them")
        assertEquals(Screen.Working, rig.screen, "core verifies it behind Working...")
        assertEquals(1, rig.worker.waiting, "on the worker")
        assertFalse(zeroed(upper.given), "the bytes read wait for core")
        rig.worker.run()
        val result = rig.model.state.value
        assertEquals(Screen.Snapshot, result.screen)
        assertFalse(isProtected(Screen.Snapshot))
        assertNull(result.snapshotRefusal)
        val loaded = assertNotNull(result.loaded)
        assertEquals(4UL, loaded.number)
        assertEquals(20260301, loaded.date)
        assertEquals(7L, loaded.count)
        assertEquals(Freshness.Current, loaded.freshness, "on kcr.json's own date")
        assertEquals("Snapshot No. 4, dated 2026-03-01, 7 entries.", snapshotLine(loaded))
        assertTrue(zeroed(upper.given), "the file's bytes were zeroed once core had them")
        rig.model.back()
        assertEquals(Screen.Home, rig.screen, "Back on the result is Home")
        assertSame(loaded, rig.model.state.value.loaded, "Home names the snapshot loaded")
        assertEquals("Snapshot No. 4, dated 2026-03-01", homeSnapshotLine(rig.model.state.value.loaded))
        // A later date: the same snapshot loaded again is Stale, with its warning (swb:120, from day 31).
        rig.date.day = 20260401
        rig.model.snapshotPicked(kcrFile(WITH_DICE_50))
        rig.worker.run()
        val stale = assertNotNull(rig.model.state.value.loaded)
        assertEquals(Freshness.Stale, stale.freshness)
        assertEquals(STALE_WARNING, freshnessWarning(stale.freshness))
        rig.model.snapshotDone()
        assertEquals(Screen.Home, rig.screen)
        assertSame(stale, rig.model.state.value.loaded, "the new load replaced the first")
    }

    @Test
    fun aSnapshotThatDoesNotVerifyIsRefusedWithCoresTextAndTheOneLoadedBeforeStays() {
        val rig = Rig().toHome().loadSnapshot(WITH_DICE_50)
        val before = assertNotNull(rig.model.state.value.loaded)
        val damaged = kcrSnapshot(WITH_DICE_50)
        damaged[60] = (damaged[60] + 1).toByte()
        rig.model.snapshotPicked(kcrFile(WITH_DICE_50, damaged))
        rig.worker.run()
        val result = rig.model.state.value
        assertEquals(Screen.Snapshot, result.screen)
        assertEquals(Refusal.BadSignature, result.snapshotRefusal, "a changed signature does not verify")
        assertEquals("registry snapshot or proof rejected: bad signature", snapshotRefusalText(Refusal.BadSignature))
        assertSame(before, result.loaded, "the snapshot loaded before stays")
        rig.model.snapshotDone()
        assertSame(before, rig.model.state.value.loaded)
        assertNull(rig.model.state.value.snapshotRefusal, "Home says nothing of the refusal")
        // The slot kept it too: a check against it runs, so the model and the slot agree.
        rig.begin(Mode.DiceOnly, Words.Twelve)
        for (face in kcrRolls("dice-50-words12")) {
            rig.model.dicePick.replace(face)
            rig.model.confirmRoll()
        }
        rig.model.diceDone()
        rig.worker.run()
        rig.model.checkNow()
        assertEquals(Screen.Collision, rig.screen, "the snapshot kept found dice-50-words12's seal")
        assertTrue(Core.collisionReport() is Reply.Done)
    }

    @Test
    fun aDiscardDuringTheLoadReturnsToTheStartScreenAndALateFileDoesNothing() {
        val rig = Rig().toHome()
        rig.model.appReturned()
        val file = kcrFile(WITH_DICE_50)
        rig.model.snapshotPicked(file)
        rig.worker.runNext()
        assertEquals(Screen.Working, rig.screen)
        assertEquals(1, rig.worker.waiting, "the read done, core's load waits")
        rig.model.appLeft()
        rig.worker.run()
        rig.assertDiscarded(Notice.Left)
        assertNull(rig.model.state.value.loaded, "a load discarded is not the model's")
        assertTrue(zeroed(file.given), "the bytes read were zeroed, though the discard came before core's load was made")
        rig.model.appReturned()
        val late = kcrFile(WITH_DICE_50)
        rig.model.snapshotPicked(late)
        rig.assertDiscarded(Notice.Left, "a file after Home has gone does nothing")
        assertEquals(0, late.reads)
    }

    /** The holder's end (wipeAll) while core's load waits on the worker: the bytes read are zeroed at once, and the load is never made. */
    @Test
    fun wipeAllDuringTheLoadZeroesTheBytesRead() {
        val rig = Rig().toHome()
        val file = kcrFile(WITH_DICE_50)
        rig.model.snapshotPicked(file)
        rig.worker.runNext()
        assertEquals(1, rig.worker.waiting, "the read done, core's load waits")
        assertFalse(zeroed(file.given), "the bytes read wait for core")
        rig.model.wipeAll()
        assertTrue(zeroed(file.given), "wipeAll zeroed the bytes read")
        rig.worker.run()
        assertNull(rig.model.state.value.loaded, "a load after wipeAll is not the model's")
    }

    @Test
    fun aboutShowsTheVersionTheFlavourAndTheSourceAndBackReturnsHome() {
        val rig = Rig().toHome()
        rig.model.about()
        val about = rig.model.state.value
        assertEquals(Screen.About, about.screen)
        assertFalse(isProtected(Screen.About))
        assertTrue(rig.model.testRegistry)
        assertTrue(flavourText(true).contains("TEST REGISTRY"), "the test-registry APK says so")
        assertFalse(flavourText(false).contains("TEST"), "the shipping APK does not")
        assertTrue(SOURCE_ADDRESS.startsWith("https://github.com/bitwilll/keepcrypt"))
        assertEquals(APP_VERSION + " development build: do not use for real funds.", DEVELOPMENT_BUILD)
        rig.model.back()
        assertEquals(Screen.Home, rig.screen, "Back on About is Home")
        rig.model.about()
        rig.offline.set(false)
        assertEquals(Screen.GoOffline, rig.screen, "About needs the phone offline, as every screen from Home on")
        assertNull(rig.model.state.value.notice, "nothing was held")
    }

    /** About's version is the app's own versionName (app/build.gradle.kts), so a version changed there fails here. */
    @Test
    fun theAboutVersionIsTheAppsVersionName() {
        val found = entropyFile("mobile/android/app/build.gradle.kts").lines().filter { it.trim().startsWith("versionName = ") }
        assertEquals(1, found.size, "one versionName in app/build.gradle.kts")
        assertEquals("versionName = \"" + APP_VERSION + "\"", found[0].trim())
    }

    /**
     * The snapshot result's refusal texts are core's Display texts (core/src/error.rs's #[error(...)]
     * attribute over each variant), "registry snapshot or proof rejected: " (CoreError::Snapshot's) before
     * each SnapshotError's, as the Pi shows them; a build with no registry key has the phone's own line,
     * as the scan screen's; every other refusal, a go-ahead QR's UR errors among them, has none.
     */
    @Test
    fun theSnapshotRefusalTextsAreCoresOwn() {
        val source = entropyFile("core/src/error.rs")
        fun text(variant: String): String {
            val found = Regex("#\\[error\\(\"([^\"]*)\"\\)\\]\\s*" + Regex.escape(variant) + "[,(]").findAll(source).toList()
            assertEquals(1, found.size, "core/src/error.rs's " + variant)
            return found[0].groupValues[1]
        }
        assertEquals("registry snapshot or proof rejected: {0}", text("Snapshot"))
        assertEquals(text("Snapshot").replace("{0}", ""), SNAPSHOT_REJECTED)
        assertEquals(SNAPSHOT_NO_REGISTRY_KEY, snapshotRefusalText(Refusal.NoRegistryKey))
        assertTrue(SNAPSHOT_NO_REGISTRY_KEY.startsWith("This build trusts no registry key yet"))
        for (refusal in Refusal.entries) {
            val shown = snapshotRefusalText(refusal)
            when {
                refusal.group == RefusalGroup.Snapshot -> {
                    assertEquals(SNAPSHOT_REJECTED + text(refusal.name), shown, refusal.name)
                    assertTrue(isSnapshotRefusal(refusal), refusal.name)
                }
                refusal == Refusal.NoRegistryKey -> assertTrue(isSnapshotRefusal(refusal))
                else -> {
                    assertNull(shown, refusal.name)
                    assertFalse(isSnapshotRefusal(refusal), refusal.name)
                }
            }
        }
    }

    private companion object {
        /** kcr.json's snapshot holding dice-50-words12's seal: No. 4, dated 2026-03-01, 7 entries. */
        const val WITH_DICE_50 = "with-dice-50"
    }
}
