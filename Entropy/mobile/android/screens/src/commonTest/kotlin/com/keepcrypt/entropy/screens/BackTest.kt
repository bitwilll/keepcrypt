package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Reply
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Back on every screen of the walk (tasks/todo.md, Stage U's U2b), over the real slot: the system Back
 * once and twice from each of the 48 screens but the stop screen, landing only where nothing is lost.
 * Where it lands is this class's own table, from the docs, not the model's backTo: docs/pi-firmware.md's
 * buttons table ("back, only where nothing is lost" on menus and offers; on the go-ahead code, Check a
 * backup's and the BIP39 passphrase's entry; on About, the re-check QR; the words' and the QR pages'
 * previous page) and its entry grids line, and docs/mobile-apps.md:34 (Back never ends a session). The
 * session, the check and its nonce are held where Back stays in the ceremony, a typed code or passphrase
 * is wiped by the Back that leaves its entry, and Check a backup's file goes with its entry; the paged
 * screens' Back is their previous page. Under a privacy gate, the privacy cover and the idle warning, Back
 * does nothing. Each screen's walk leaves the slot at home (wipeAll after it).
 */
class BackTest {
    @AfterTest
    fun emptyTheSlot() {
        assertTrue(Core.wipeAll() is Reply.Done)
    }

    /**
     * Where Back lands from each screen it leaves; every screen not named stays where it is. Go offline,
     * Home and Length, before any session; Skip's confirm, before the check starts; the check QR to the
     * seal card, and the scan screen, the code entry and the one-way choices' confirms to the check QR,
     * the check and its nonce kept (PF: KEY2 on the code entry goes back to the actions page); the BIP39
     * passphrase's entry to its question, the descriptor QR to the account QR; Check a backup's entry
     * Home, its re-check QR to its result; Load registry snapshot's result and About Home.
     */
    private val landing: Map<Screen, Screen> = mapOf(
        Screen.GoOffline to Screen.FirstLaunch,
        Screen.Home to Screen.GoOffline,
        Screen.Length to Screen.Home,
        Screen.SkipConfirm to Screen.CheckPrompt,
        Screen.CheckQr to Screen.SealCard,
        Screen.Scan to Screen.CheckQr,
        Screen.CodeEntry to Screen.CheckQr,
        Screen.MatchFoundConfirm to Screen.CheckQr,
        Screen.CannotCheckConfirm to Screen.CheckQr,
        Screen.Bip39Entry to Screen.Bip39Ask,
        Screen.WatchDescriptorQr to Screen.WatchAccountQr,
        Screen.BackupCheckEntry to Screen.Home,
        Screen.BackupRecheck to Screen.BackupCheckResult,
        Screen.Snapshot to Screen.Home,
        Screen.About to Screen.Home,
    )

    private fun landsOn(screen: Screen): Screen = landing[screen] ?: screen

    /**
     * The pad a screen's Back leaves and wipes, and a key it shows: the code entry's, the BIP39
     * passphrase's (the ASCII pad's first page) and Check a backup's entry's.
     */
    private fun typedOn(rig: Rig): Pair<PadEntry, String>? = when (rig.screen) {
        Screen.CodeEntry -> rig.model.goAheadCode to "C"
        Screen.Bip39Entry -> rig.model.bip39Letters to "1"
        Screen.BackupCheckEntry -> rig.model.backupLetters to "a"
        else -> null
    }

    @Test
    fun backOnceAndTwiceLandsOnlyWhereNothingIsLost() {
        for (screen in Walk.screens) {
            val name = screenId(screen)
            val rig = Walk.to(screen)
            val (pad, key) = typedOn(rig) ?: (null to "")
            if (pad != null) {
                rig.press(key)
                assertEquals(1, pad.length, "$name: the key typed")
            }
            val before = rig.model.state.value
            val held = rig.model.held.value
            rig.model.back()
            val once = landsOn(screen)
            val after = rig.model.state.value
            assertEquals(once, after.screen, "$name: Back once")
            assertEquals(if (screen == Screen.BackupCheckEntry) false else held, rig.model.held.value, "$name: what is held after Back")
            assertNull(after.notice, "$name: Back said something was wiped")
            assertNull(after.overlay, "$name: Back covered the screen")
            if (pad != null) assertEquals(0, pad.length, "$name: Back left what was typed")
            if (once == screen) assertEquals(before.page, after.page, "$name: Back moved the page")
            if (once == Screen.CheckQr || once == Screen.SealCard) {
                assertSame(before.checkRequest, after.checkRequest, "$name: Back changed the check or its nonce")
                assertSame(before.seal, after.seal, "$name: Back changed the seal card")
            }
            rig.model.back()
            assertEquals(landsOn(once), rig.screen, "$name: Back twice")
            assertTrue(Core.wipeAll() is Reply.Done)
        }
    }

    @Test
    fun onThePagedScreensBackIsThePreviousPage() {
        for (screen in listOf(Screen.Words, Screen.WordsOverview, Screen.BackupPassphrase)) {
            val name = screenId(screen)
            val rig = Walk.to(screen)
            rig.model.nextPage()
            assertEquals(1, rig.model.state.value.page, "$name: the next page")
            rig.model.back()
            assertEquals(screen, rig.screen, name)
            assertEquals(0, rig.model.state.value.page, "$name: Back once is the page before")
            rig.model.back()
            assertEquals(screen, rig.screen, name)
            assertEquals(0, rig.model.state.value.page, "$name: Back on the first page does nothing")
            assertTrue(Core.wipeAll() is Reply.Done)
        }
    }

    @Test
    fun backDoesNothingUnderAPrivacyGateTheCoverOrTheWarning() {
        for (screen in Walk.gated) {
            val rig = Walk.to(screen, gate = true)
            rig.model.back()
            assertEquals(screen, rig.screen, screenId(screen) + ": Back on its privacy gate")
            assertTrue(rig.model.state.value.gate, screenId(screen) + ": Back passed its privacy gate")
            assertTrue(Core.wipeAll() is Reply.Done)
        }
        for (screen in Walk.screens.filterNot(::isWorking)) {
            val name = screenId(screen)
            val covered = Walk.to(screen)
            if (isProtected(screen)) {
                covered.clock.now += Timers.COVER_MILLIS
                covered.model.tick()
            } else {
                covered.model.appLeft()
                covered.clock.now += 1_000
                covered.model.appReturned()
            }
            assertBackDoesNothing(covered, Overlay.Cover, "$name under the cover")
            assertTrue(Core.wipeAll() is Reply.Done)
            val warned = Walk.to(screen)
            if (!warned.model.held.value) {
                assertTrue(Core.wipeAll() is Reply.Done)
                continue
            }
            warned.clock.now += Timers.WARN_MILLIS
            warned.model.tick()
            assertBackDoesNothing(warned, Overlay.Warning, "$name under the warning")
            assertTrue(Core.wipeAll() is Reply.Done)
        }
    }

    /** overlay shows over rig's screen, and Back leaves the screen, its page, the overlay and what is held as they were. */
    private fun assertBackDoesNothing(rig: Rig, overlay: Overlay, what: String) {
        val before = rig.model.state.value
        assertEquals(overlay, before.overlay, what)
        val held = rig.model.held.value
        rig.model.back()
        val after = rig.model.state.value
        assertEquals(before.screen, after.screen, what + ": Back moved")
        assertEquals(before.page, after.page, what + ": Back moved the page")
        assertEquals(overlay, after.overlay, what + ": Back took the overlay away")
        assertEquals(held, rig.model.held.value, what + ": Back changed what is held")
        assertFalse(after.notice != null && before.notice == null, what + ": Back wiped")
    }
}
