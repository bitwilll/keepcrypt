package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Reply
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A configuration change and going online on every screen of the walk (tasks/todo.md, Stage U's U2d),
 * over the real slot. A configuration change (a rotation, a font scale, a dark-mode switch) recreates the
 * activity: SecureActivity reports no leaving for its stop, and the new activity's start and resume reach
 * the model as a return and a resume while it is already in the foreground, so the screen, its page, its
 * privacy gate, the cover or warning over it, what is held and what a pad holds (a key typed on each
 * pad first) stay as they were, with no call made; in the words' states the walk's screens do not name
 * (Walk.states) too. Going online (docs/mobile-apps.md:125 and :34, Q57): before the start-up self-test passes
 * and on Go offline nothing goes; on Home, Length, Load registry snapshot's result and About, which hold
 * nothing, Go offline comes back with nothing to say; on every other screen the session, restart or
 * Check a backup's file or checked backup is discarded at once, with the Offline notice, every secret on
 * show and every pad's entry wiped and the slot at home ("Working..." once its call's reply comes). Each
 * screen's walk leaves the slot at home (wipeAll after it).
 */
class ConfigurationAndOnlineTest {
    @AfterTest
    fun emptyTheSlot() {
        assertTrue(Core.wipeAll() is Reply.Done)
    }

    /** The screens that hold nothing once the start-up self-test has passed: Go offline comes back when the phone goes online on these. */
    private val holdingNothing = setOf(Screen.Home, Screen.Length, Screen.Snapshot, Screen.About)

    /** The screens before Go offline needs anything: before the self-test passes, and Go offline itself. */
    private val beforeOffline = setOf(Screen.FirstLaunch, Screen.SelfTest, Screen.GoOffline)

    /** A configuration change: the recreated activity's start and resume, with no leaving before them. */
    private fun recreate(rig: Rig) {
        rig.model.appReturned()
        rig.model.appResumed()
    }

    /** A configuration change leaves rig's state, what it holds, its pads and its calls as they were. */
    private fun assertRecreationChangesNothing(rig: Rig, what: String) {
        val before = rig.model.state.value
        val held = rig.model.held.value
        val pads = rig.padLengths()
        val waiting = rig.worker.waiting
        val starts = rig.offline.starts
        recreate(rig)
        assertEquals(before, rig.model.state.value, "$what: the state changed")
        assertEquals(held, rig.model.held.value, "$what: what is held changed")
        assertEquals(pads, rig.padLengths(), "$what: a pad's entry changed")
        assertEquals(waiting, rig.worker.waiting, "$what: a call was made")
        assertEquals(starts, rig.offline.starts, "$what: the offline monitor started again")
    }

    @Test
    fun aConfigurationChangeOnEveryScreenChangesNothing() {
        for (screen in Walk.gated) {
            assertRecreationChangesNothing(Walk.to(screen, gate = true), screenId(screen) + " on its privacy gate")
            assertTrue(Core.wipeAll() is Reply.Done)
        }
        for (screen in Walk.screens) {
            val name = screenId(screen)
            val rig = Walk.to(screen)
            val key = PAD_KEYS[screen]
            if (key != null) {
                rig.press(key)
                assertTrue(rig.padLengths().sum() > 0, "$name: the key typed")
            }
            assertRecreationChangesNothing(rig, name)
            assertTrue(Core.wipeAll() is Reply.Done)
            if (isWorking(screen)) continue
            val covered = Walk.to(screen)
            if (screen in Walk.protected) {
                covered.clock.now += Timers.COVER_MILLIS
                covered.model.tick()
                assertEquals(Overlay.Cover, covered.model.state.value.overlay, name)
                assertRecreationChangesNothing(covered, "$name under the cover")
            } else if (covered.model.held.value) {
                covered.clock.now += Timers.WARN_MILLIS
                covered.model.tick()
                assertEquals(Overlay.Warning, covered.model.state.value.overlay, name)
                assertRecreationChangesNothing(covered, "$name under the warning")
            }
            assertTrue(Core.wipeAll() is Reply.Done)
        }
    }

    @Test
    fun aConfigurationChangeInTheWordsStatesTheWalksScreensDoNotNameChangesNothing() {
        for ((what, reach) in Walk.states) {
            assertRecreationChangesNothing(reach(), what)
            assertTrue(Core.wipeAll() is Reply.Done)
        }
    }

    @Test
    fun goingOnlineOnEveryScreenDiscardsWhatIsHeld() {
        for (screen in Walk.screens) {
            val name = screenId(screen)
            val rig = Walk.to(screen)
            val holds = screen !in holdingNothing && screen !in beforeOffline && !isWorking(screen)
            assertEquals(holds, rig.model.held.value, "$name: what is held before going online")
            rig.offline.set(false)
            when {
                screen in beforeOffline -> {
                    assertEquals(screen, rig.screen, "$name: going online before Go offline is needed")
                    assertNull(rig.model.state.value.notice, name)
                }
                screen in holdingNothing -> {
                    assertEquals(Screen.GoOffline, rig.screen, "$name: going online, nothing held")
                    assertNull(rig.model.state.value.notice, "$name: nothing was held, so nothing was wiped")
                }
                else -> {
                    if (screen == Screen.Working) {
                        assertEquals(Screen.Working, rig.screen, "$name: until the call's reply")
                        rig.worker.run()
                    }
                    rig.assertDiscarded(Notice.Offline, "$name: going online")
                    rig.assertNothingSecretShown(name)
                    assertTrue(Core.selfTest() is Reply.Done, "$name: going online left something in core")
                }
            }
            rig.offline.set(true)
            if (rig.screen == Screen.GoOffline) {
                rig.model.startOffline()
                assertEquals(Screen.Home, rig.screen, "$name: offline again, Start reaches Home")
            }
            assertTrue(Core.wipeAll() is Reply.Done)
        }
    }

    private companion object {
        /** A key each pad screen of the walk shows (the ASCII pad's first page on the BIP39 entry), typed before its recreation. */
        val PAD_KEYS = mapOf(
            Screen.Dice to "3", Screen.CodeEntry to "C", Screen.ReadbackEntry to "a", Screen.BackupConfirm to "a",
            Screen.Bip39Entry to "1", Screen.BackupCheckEntry to "a",
        )
    }
}
