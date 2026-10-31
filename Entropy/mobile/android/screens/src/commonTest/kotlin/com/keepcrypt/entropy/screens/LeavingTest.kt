package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Reply
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Leaving the app on every screen of the walk (tasks/todo.md, Stage U's U2e; docs/mobile-apps.md:34, Q57,
 * Q75), over the real slot. On a Protected screen and during a long call, leaving discards at once, with
 * the Left notice ("Working..." once its call's reply comes; the start-up self-test, which holds no
 * session, back to First launch with nothing to say). On a Public screen the privacy cover goes up and
 * the background time starts: 59 s away keeps everything, and the return keeps the cover until a tap,
 * which only uncovers; 61 s away wipes what is held, with the Background notice, whether the timers ran
 * while away or the process was frozen and the wipe comes at the return, before anything shows; a Public
 * screen that holds nothing keeps its place however long the app is away. Each screen's walk leaves the
 * slot at home (wipeAll after it).
 */
class LeavingTest {
    @AfterTest
    fun emptyTheSlot() {
        assertTrue(Core.wipeAll() is Reply.Done)
    }

    @Test
    fun leavingAProtectedScreenOrALongCallDiscardsAtOnceAndAPublicOneIsCovered() {
        for (screen in Walk.screens) {
            val name = screenId(screen)
            val rig = Walk.to(screen)
            val held = rig.model.held.value
            rig.model.appLeft()
            when {
                screen == Screen.SelfTest -> {
                    assertEquals(Screen.SelfTest, rig.screen, "$name: until the self-test's reply")
                    rig.worker.run()
                    assertEquals(Screen.FirstLaunch, rig.screen, "$name: the self-test left runs again from First launch")
                    assertNull(rig.model.state.value.notice, "$name: no session was held")
                }
                screen == Screen.Working -> {
                    assertEquals(Screen.Working, rig.screen, "$name: until the call's reply")
                    rig.worker.run()
                    rig.assertDiscarded(Notice.Left, name)
                    assertTrue(Core.selfTest() is Reply.Done, "$name: the call left something in core")
                }
                isProtected(screen) -> {
                    rig.assertDiscarded(Notice.Left, "$name: leaving a Protected screen")
                    rig.assertNothingSecretShown(name)
                    assertTrue(Core.selfTest() is Reply.Done, "$name: leaving left something in core")
                }
                else -> {
                    val state = rig.model.state.value
                    assertEquals(screen, state.screen, "$name: leaving a Public screen")
                    assertEquals(Overlay.Cover, state.overlay, "$name: the privacy cover")
                    assertNull(state.notice, name)
                    assertEquals(held, rig.model.held.value, "$name: leaving a Public screen kept what is held")
                }
            }
            assertTrue(Core.wipeAll() is Reply.Done)
        }
    }

    @Test
    fun sixtySecondsAwayFromAPublicScreenWipesWhatIsHeldAndFiftyNineKeepIt() {
        for (screen in Walk.screens.filterNot { isProtected(it) || isWorking(it) }) {
            val name = screenId(screen)
            val kept = Walk.to(screen)
            val held = kept.model.held.value
            val page = kept.model.state.value.page
            kept.model.appLeft()
            kept.clock.now += Timers.BACKGROUND_MILLIS - 1_000
            kept.model.tick()
            kept.model.appReturned()
            assertEquals(screen, kept.screen, "$name: 59 s away")
            assertEquals(held, kept.model.held.value, "$name: 59 s away kept what is held")
            assertEquals(Overlay.Cover, kept.model.state.value.overlay, "$name: back within 60 s, the cover stays")
            kept.model.dismissOverlay()
            assertEquals(screen, kept.screen, "$name: the tap only uncovers")
            assertNull(kept.model.state.value.overlay, "$name: the tap uncovered")
            assertEquals(page, kept.model.state.value.page, name)
            assertTrue(Core.wipeAll() is Reply.Done)

            for (frozen in listOf(false, true)) {
                val what = name + if (frozen) ": 61 s away, frozen" else ": 61 s away"
                val away = Walk.to(screen)
                away.model.appLeft()
                away.clock.now += Timers.BACKGROUND_MILLIS + 1_000
                if (!frozen) away.model.tick()
                away.model.appReturned()
                if (held) {
                    away.assertDiscarded(Notice.Background, what)
                    away.assertNothingSecretShown(what)
                    assertTrue(Core.selfTest() is Reply.Done, "$what: the wipe left something in core")
                } else {
                    assertEquals(screen, away.screen, "$what: nothing held, nothing to wipe")
                    assertNull(away.model.state.value.notice, what)
                    assertFalse(away.model.held.value, what)
                }
                assertTrue(Core.wipeAll() is Reply.Done)
            }
        }
    }
}
