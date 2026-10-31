package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Words
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The idle rules on every screen of the walk and the 99-roll minimum through every restart path
 * (tasks/todo.md, Stage U's U2f; docs/pi-firmware.md, "Protected screens and idle", adopted by
 * docs/mobile-apps.md:34), over the real slot and the fake clock. 30 s without input covers a Protected
 * screen alone, and a tap only uncovers it; 9 minutes bring the warning on any screen while something is
 * held, and a tap keeps everything; 10 minutes wipe what is held, with the Idle notice, and a loaded
 * snapshot survives; where nothing is held nothing comes, and during a long call the timers wait. After a
 * collision the next ceremony needs 99 rolls however the slot gets back to a start: Add fresh entropy,
 * and every discard (leaving the report, going online, 60 s away from the collision result, the idle
 * wipe) followed by a new 12-word seed from Home, whose minimum is otherwise 50; the restarted ceremony's
 * own discard keeps it too. Each walk leaves the slot at home (wipeAll after it).
 */
class IdleTest {
    @AfterTest
    fun emptyTheSlot() {
        assertTrue(Core.wipeAll() is Reply.Done)
    }

    /** The timers' step after ms more without input. */
    private fun idle(rig: Rig, ms: Long) {
        rig.clock.now += ms
        rig.model.tick()
    }

    @Test
    fun theCoverTheWarningAndTheWipeOnEveryScreen() {
        for (screen in Walk.screens) {
            val name = screenId(screen)
            val rig = Walk.to(screen)
            val held = rig.model.held.value
            if (isWorking(screen)) {
                idle(rig, Timers.WIPE_MILLIS)
                assertEquals(screen, rig.screen, "$name: the timers wait during a long call")
                assertNull(rig.model.state.value.overlay, name)
                assertTrue(Core.wipeAll() is Reply.Done)
                continue
            }
            idle(rig, Timers.COVER_MILLIS - 1)
            assertNull(rig.model.state.value.overlay, "$name: 29.999 s")
            idle(rig, 1)
            if (isProtected(screen)) {
                assertEquals(Overlay.Cover, rig.model.state.value.overlay, "$name: 30 s on a Protected screen")
                rig.model.dismissOverlay()
                assertNull(rig.model.state.value.overlay, "$name: the tap uncovered")
            } else {
                assertNull(rig.model.state.value.overlay, "$name: 30 s on a Public screen")
            }
            assertEquals(screen, rig.screen, name)
            assertEquals(held, rig.model.held.value, "$name: the cover kept what is held")
            idle(rig, Timers.WARN_MILLIS)
            if (held) {
                assertEquals(Overlay.Warning, rig.model.state.value.overlay, "$name: 9 minutes, something held")
                rig.model.dismissOverlay()
                assertNull(rig.model.state.value.overlay, "$name: the tap took the warning away")
                assertEquals(screen, rig.screen, name)
                assertTrue(rig.model.held.value, "$name: the tap kept everything")
            } else {
                assertNull(rig.model.state.value.overlay, "$name: 9 minutes, nothing held")
            }
            idle(rig, Timers.WIPE_MILLIS)
            if (held) {
                rig.assertDiscarded(Notice.Idle, "$name: 10 minutes")
                rig.assertNothingSecretShown(name)
                assertTrue(Core.selfTest() is Reply.Done, "$name: the idle wipe left something in core")
            } else {
                assertEquals(screen, rig.screen, "$name: 10 minutes, nothing held, nothing wiped")
                assertNull(rig.model.state.value.notice, name)
            }
            assertTrue(Core.wipeAll() is Reply.Done)
        }
    }

    @Test
    fun aLoadedSnapshotSurvivesTheIdleWipe() {
        val rig = Walk.to(Screen.Snapshot)
        val loaded = assertNotNull(rig.model.state.value.loaded)
        rig.model.snapshotDone()
        rig.begin(Mode.DiceOnly, Words.Twelve)
        idle(rig, Timers.WIPE_MILLIS)
        rig.assertDiscarded(Notice.Idle, "10 minutes on the dice")
        rig.model.startOffline()
        assertEquals(Screen.Home, rig.screen)
        assertEquals(loaded, rig.model.state.value.loaded, "the snapshot the idle wipe left")
        // And core still holds it: the next seed's Check now runs against it on its own. The snapshot
        // registers the seal of 50 rolls of the faces 1 to 6 in turn (kcr.json's dice-50-words12), the rolls
        // Rig.roll makes, so the check finds the collision there, by the snapshot.
        rig.begin(Mode.DiceOnly, Words.Twelve)
        rig.roll(50)
        rig.model.diceDone()
        rig.worker.run()
        rig.model.checkNow()
        assertEquals(Screen.Collision, rig.screen, "the next check ran against the snapshot core kept")
        assertNotNull(rig.model.state.value.registry, "the collision was found by the snapshot")
    }

    /** From Go offline after a discard: Start, then a new dice-only seed of 12 words; the dice's minimum. */
    private fun nextMinimum(rig: Rig, what: String): Int {
        rig.offline.set(true)
        rig.model.appReturned()
        rig.model.dismissOverlay()
        rig.model.startOffline()
        assertEquals(Screen.Home, rig.screen, what)
        rig.begin(Mode.DiceOnly, Words.Twelve)
        assertEquals(Screen.Dice, rig.screen, what)
        return assertNotNull(rig.model.state.value.dice, what).minimum
    }

    @Test
    fun the99RollMinimumAfterACollisionOutlivesEveryRestartPath() {
        val control = Walk.to(Screen.Home)
        control.begin(Mode.DiceOnly, Words.Twelve)
        assertEquals(50, assertNotNull(control.model.state.value.dice).minimum, "12 words with no collision before")
        assertTrue(Core.wipeAll() is Reply.Done)

        val fresh = Walk.to(Screen.CollisionReport)
        fresh.model.addFreshEntropy()
        fresh.worker.run()
        assertEquals(Screen.DeviceEntropy, fresh.screen, "Add fresh entropy: the same mode, Mixed")
        fresh.model.deviceEntropyDone()
        fresh.model.commitmentDone()
        assertEquals(99, assertNotNull(fresh.model.state.value.dice).minimum, "Add fresh entropy")
        assertTrue(Core.wipeAll() is Reply.Done)

        val discards: List<Pair<String, (Rig) -> Unit>> = listOf(
            "leaving the report" to { rig ->
                rig.model.showReport()
                rig.model.passGate()
                rig.model.appLeft()
            },
            "going online" to { rig -> rig.offline.set(false) },
            "60 s away" to { rig ->
                rig.model.appLeft()
                rig.clock.now += Timers.BACKGROUND_MILLIS
                rig.model.tick()
            },
            "the idle wipe" to { rig -> idle(rig, Timers.WIPE_MILLIS) },
        )
        for ((what, discard) in discards) {
            val rig = Walk.to(Screen.Collision)
            discard(rig)
            assertEquals(Screen.GoOffline, rig.screen, "$what after the collision")
            assertEquals(99, nextMinimum(rig, what), "$what after the collision, then a new seed")
            assertTrue(Core.wipeAll() is Reply.Done)
        }

        val restarted = Walk.to(Screen.CollisionReport)
        restarted.model.addFreshEntropy()
        restarted.worker.run()
        restarted.offline.set(false)
        assertEquals(99, nextMinimum(restarted, "the restart discarded"), "the restarted ceremony discarded, then a new seed")
    }
}
