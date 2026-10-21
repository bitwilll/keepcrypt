package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Words
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Every CeremonyModel transition the screens from the start to the dice add (tasks/todo.md, M5 group
 * 15), over the real slot through Core and the host library, long calls held on the test's worker:
 * First launch to Go offline to Home to Length; a new seed through Device entropy and Commitment to the
 * dice, and a dice-only seed straight to the dice; the dice pad, Confirm, Undo, the minimum and the
 * 256 cap; Back where nothing is lost and nowhere else; the offline gate; touches and motion into the
 * pool only on Device entropy; and C's hex groups and the dice line, as the Pi writes them. Whether
 * the slot holds a session, and in which stage, is read from the slot itself: the device leg's
 * progress is offered only while collecting, C only once committed, the dice counts only while rolling
 * and the self-test only at home, empty (each other call halts, which would fail every later check).
 * Each test leaves the slot at home (wipeAll after it).
 */
class StartScreensTest {
    @AfterTest
    fun emptyTheSlot() {
        assertTrue(Core.wipeAll() is Reply.Done)
    }

    private fun assertCollecting(message: String) {
        assertTrue(Core.deviceProgress() is Reply.Done, message)
    }

    private fun assertRolling(message: String) {
        assertTrue(Core.diceProgress() is Reply.Done, message)
    }

    private fun assertNoSession(message: String) {
        assertTrue(Core.selfTest() is Reply.Done, message)
    }

    private fun rolls(rig: Rig): Int? = rig.model.state.value.dice?.rolls

    @Test
    fun theStartGoesFromFirstLaunchThroughGoOfflineToHomeAndLength() {
        val rig = Rig().startUp()
        assertEquals(Screen.FirstLaunch, rig.screen)
        rig.model.firstLaunchDone()
        assertEquals(Screen.GoOffline, rig.screen)
        assertTrue(rig.model.state.value.airplaneMode)
        assertTrue(rig.model.state.value.wifiOff)
        rig.model.startOffline()
        assertEquals(Screen.Home, rig.screen)
        rig.model.chooseMode(Mode.Mixed)
        assertEquals(Screen.Length, rig.screen)
        assertEquals(0, rig.worker.waiting, "nothing starts before a length is chosen")
        assertNoSession("no session before Length")
        // A press left over from a screen that has gone does nothing.
        rig.model.firstLaunchDone()
        rig.model.startOffline()
        rig.model.chooseMode(Mode.DiceOnly)
        assertEquals(Screen.Length, rig.screen)
    }

    @Test
    fun aNewSeedGoesThroughDeviceEntropyAndCommitmentToTheDice() {
        val rig = Rig().toHome()
        rig.model.chooseMode(Mode.Mixed)
        rig.model.chooseLength(Words.Twelve)
        assertEquals(Screen.Working, rig.screen, "the start and its known-answer suite, a long call")
        rig.worker.run()
        assertEquals(Screen.DeviceEntropy, rig.screen)
        assertTrue(rig.motion.running, "the motion source runs on Device entropy")
        assertCollecting("Device entropy collects")
        rig.model.deviceEntropyDone()
        assertEquals(Screen.Commitment, rig.screen)
        assertFalse(rig.motion.running, "the motion source stops at the commitment")
        val shown = assertNotNull(rig.model.state.value.commitment)
        val c = when (val reply = Core.commitment()) {
            is Reply.Done -> assertNotNull(reply.value, "Mixed mode has C")
            else -> fail("C is offered once committed")
        }
        assertEquals(hexGroups(c), shown, "the screen shows core's C")
        val rows = shown.split('\n')
        assertEquals(4, rows.size, "four rows")
        for (row in rows) assertTrue(Regex("^[0-9a-f]{4}( [0-9a-f]{4}){3}$").matches(row), "four groups of four hex digits")
        rig.model.commitmentDone()
        assertEquals(Screen.Dice, rig.screen)
        val state = rig.model.state.value
        val dice = assertNotNull(state.dice)
        assertEquals("0 / 50 rolls, 0.0 bits", diceText(dice.rolls, dice.minimum, dice.millibits))
        assertFalse(state.diceOnly)
        assertNull(state.commitment, "C leaves with its screen")
        assertRolling("the dice")
    }

    @Test
    fun aDiceOnlySeedSkipsDeviceEntropyAndCommitment() {
        val rig = Rig().toHome()
        rig.model.chooseMode(Mode.DiceOnly)
        rig.model.chooseLength(Words.TwentyFour)
        rig.worker.run()
        assertEquals(Screen.Dice, rig.screen, "straight to the dice: committed and opened with no screen between")
        assertEquals(0, rig.motion.starts, "Device entropy never showed")
        val state = rig.model.state.value
        assertNull(state.commitment, "Commitment never showed")
        assertTrue(state.diceOnly)
        val dice = assertNotNull(state.dice)
        assertEquals("0 / 99 rolls, 0.0 bits", diceText(dice.rolls, dice.minimum, dice.millibits))
        assertRolling("the slot is rolling, so the dice-only commit and start_dice were made")
    }

    @Test
    fun theDicePadPicksConfirmPushesAndUndoTakesBack() {
        val rig = Rig().toHome().begin(Mode.DiceOnly, Words.Twelve)
        rig.model.confirmRoll()
        assertEquals(0, rolls(rig), "no face picked, nothing pushed")
        assertTrue(rig.model.dicePick.replace('3'))
        rig.model.confirmRoll()
        val one = assertNotNull(rig.model.state.value.dice)
        assertEquals("1 / 50 rolls, 2.5 bits", diceText(one.rolls, one.minimum, one.millibits))
        assertEquals(0, rig.model.dicePick.length, "the pick goes with the confirm")
        assertTrue(rig.model.dicePick.zeroPastLength(), "and its byte is zeroed")
        rig.model.dicePick.replace('4')
        rig.model.undoRoll()
        assertEquals(0, rolls(rig))
        assertEquals(1, rig.model.dicePick.length, "undo keeps the pick")
        rig.model.undoRoll()
        assertEquals(0, rolls(rig), "undo with no roll does nothing")
        rig.roll(49)
        assertEquals(49, rolls(rig))
        rig.roll(1)
        val dice = assertNotNull(rig.model.state.value.dice)
        assertEquals("50 / 50 rolls, 129.2 bits", diceText(dice.rolls, dice.minimum, dice.millibits))
        assertTrue(dice.rolls >= dice.minimum, "the minimum is reached")
        assertRolling("still rolling: Done comes with commit 17")
    }

    @Test
    fun confirmDoesNothingAt256Rolls() {
        val rig = Rig().toHome().begin(Mode.DiceOnly, Words.Twelve)
        rig.roll(MAX_ROLLS)
        assertEquals(MAX_ROLLS, rolls(rig))
        rig.model.dicePick.replace('1')
        rig.model.confirmRoll()
        assertEquals(MAX_ROLLS, rolls(rig), "no 257th roll")
        val progress = Core.diceProgress()
        assertTrue(progress is Reply.Done && progress.value.rolls == MAX_ROLLS, "the slot did not halt (core halts on a 257th)")
        rig.model.undoRoll()
        assertEquals(MAX_ROLLS - 1, rolls(rig), "undo still works")
    }

    @Test
    fun backGoesBackOnlyWhereNothingIsLost() {
        val rig = Rig()
        rig.model.back()
        assertEquals(Screen.SelfTest, rig.screen)
        rig.startUp()
        rig.model.back()
        assertEquals(Screen.FirstLaunch, rig.screen, "nothing before First launch")
        rig.model.firstLaunchDone()
        rig.model.back()
        assertEquals(Screen.FirstLaunch, rig.screen, "Go offline back to First launch")
        rig.model.firstLaunchDone()
        rig.model.startOffline()
        rig.model.back()
        assertEquals(Screen.GoOffline, rig.screen, "Home back to Go offline")
        rig.model.startOffline()
        rig.model.chooseMode(Mode.Mixed)
        rig.model.back()
        assertEquals(Screen.Home, rig.screen, "Length back to Home")
        // Covered, Back reaches nothing.
        rig.model.chooseMode(Mode.Mixed)
        rig.model.appLeft()
        rig.model.appReturned()
        assertEquals(Overlay.Cover, rig.model.state.value.overlay)
        rig.model.back()
        assertEquals(Screen.Length, rig.screen, "the cover takes the press")
        rig.model.dismissOverlay()
        // From the start on, Back loses nothing because it does nothing.
        rig.model.chooseLength(Words.Twelve)
        rig.model.back()
        assertEquals(Screen.Working, rig.screen, "nothing leaves Working but its reply")
        rig.worker.run()
        rig.model.back()
        assertEquals(Screen.DeviceEntropy, rig.screen)
        assertCollecting("Back kept the session")
        rig.model.deviceEntropyDone()
        rig.model.back()
        assertEquals(Screen.Commitment, rig.screen)
        rig.model.commitmentDone()
        rig.roll(1)
        rig.model.back()
        assertEquals(Screen.Dice, rig.screen)
        assertEquals(1, rolls(rig), "Back kept the roll")
    }

    @Test
    fun startStaysOffUntilAirplaneModeIsOnAndWifiOff() {
        val rig = Rig()
        rig.offline.offline = false
        rig.startUp()
        rig.model.firstLaunchDone()
        assertEquals(Screen.GoOffline, rig.screen)
        assertFalse(rig.model.state.value.offline)
        rig.model.startOffline()
        assertEquals(Screen.GoOffline, rig.screen, "online, Start does nothing")
        rig.offline.set(airplaneMode = true, wifiOff = false)
        assertTrue(rig.model.state.value.airplaneMode)
        assertFalse(rig.model.state.value.wifiOff)
        rig.model.startOffline()
        assertEquals(Screen.GoOffline, rig.screen, "Wi-Fi on inside airplane mode is online")
        rig.offline.set(airplaneMode = false, wifiOff = true)
        rig.model.startOffline()
        assertEquals(Screen.GoOffline, rig.screen, "Wi-Fi off without airplane mode is online")
        rig.offline.set(airplaneMode = true, wifiOff = true)
        assertTrue(rig.model.state.value.offline)
        assertEquals(Screen.GoOffline, rig.screen, "going offline does not press Start")
        rig.model.startOffline()
        assertEquals(Screen.Home, rig.screen)
    }

    @Test
    fun goingOnlineWithNothingHeldReturnsToGoOfflineWithNoNotice() {
        val rig = Rig().startUp()
        rig.offline.set(false)
        assertEquals(Screen.FirstLaunch, rig.screen, "First launch needs no offline")
        rig.offline.set(true)
        rig.model.firstLaunchDone()
        rig.model.startOffline()
        rig.offline.set(false)
        assertEquals(Screen.GoOffline, rig.screen, "Home needs the phone offline")
        assertNull(rig.model.state.value.notice, "nothing was held, so nothing was wiped")
        rig.offline.set(true)
        assertEquals(Screen.GoOffline, rig.screen)
        rig.model.startOffline()
        rig.model.chooseMode(Mode.DiceOnly)
        rig.offline.set(false)
        assertEquals(Screen.GoOffline, rig.screen, "Length needs the phone offline")
        assertNull(rig.model.state.value.notice)
        assertNoSession("no session")
    }

    @Test
    fun goingOnlineOnTheDiceWipesTheSessionAndReturnsToGoOffline() {
        val rig = Rig().toHome().begin(Mode.DiceOnly, Words.Twelve)
        rig.roll(3)
        rig.model.dicePick.replace('5')
        rig.offline.set(airplaneMode = true, wifiOff = false)
        val state = rig.model.state.value
        assertEquals(Screen.GoOffline, state.screen)
        assertEquals(Notice.Offline, state.notice)
        assertNull(state.dice)
        assertEquals(0, rig.model.dicePick.length, "the pick was wiped with its screen")
        assertTrue(rig.model.dicePick.zeroPastLength())
        assertNoSession("Wi-Fi on wiped the session")
    }

    @Test
    fun touchesAndMotionReachThePoolOnlyOnDeviceEntropy() {
        val rig = Rig().toHome()
        rig.model.chooseMode(Mode.Mixed)
        // No session yet: a touch goes nowhere (core's add_extra at home would halt the slot).
        rig.model.touched(1)
        rig.model.chooseLength(Words.Twelve)
        rig.worker.run()
        assertEquals(Screen.DeviceEntropy, rig.screen)
        rig.model.touched(2)
        val sample = ByteArray(20) { 7 }
        assertTrue(rig.motion.sample(sample))
        assertTrue(sample.all { it == 0.toByte() }, "the sample is zeroed once core has it")
        assertCollecting("both extras went into the collecting session")
        rig.model.deviceEntropyDone()
        assertEquals(Screen.Commitment, rig.screen)
        val late = ByteArray(20) { 9 }
        assertFalse(rig.motion.sample(ByteArray(20)), "the model stopped listening at the commitment")
        rig.motion.late(late)
        assertTrue(late.all { it == 0.toByte() }, "a late sample is zeroed and goes nowhere")
        rig.model.touched(3)
        assertTrue(Core.commitment() is Reply.Done, "nothing reached core after the commitment")
        rig.model.commitmentDone()
        rig.model.touched(4)
        rig.motion.late(ByteArray(20))
        assertRolling("nothing reached core on the dice")
        assertEquals(1, rig.motion.starts)
    }

    @Test
    fun hexGroupsAndTheDiceLineMatchThePi() {
        // pi/app's ui/hex.rs specimen, D = 00..1f.
        val specimen = ByteArray(32) { it.toByte() }
        assertEquals("0001 0203 0405 0607\n0809 0a0b 0c0d 0e0f\n1011 1213 1415 1617\n1819 1a1b 1c1d 1e1f", hexGroups(specimen))
        assertEquals("ffff ffff ffff ffff\nffff ffff ffff ffff\nffff ffff ffff ffff\nffff ffff ffff ffff", hexGroups(ByteArray(32) { -1 }))
        assertFailsWith<IllegalStateException> { hexGroups(ByteArray(31)) }
        // pi-firmware.md's example, and the ends of the dice's range.
        assertEquals("37 / 50 rolls, 95.6 bits", diceText(37, 50, 37 * 2_585L))
        assertEquals("0 / 50 rolls, 0.0 bits", diceText(0, 50, 0))
        assertEquals("99 / 99 rolls, 255.9 bits", diceText(99, 99, 99 * 2_585L))
        assertEquals("256 / 99 rolls, 661.7 bits", diceText(256, 99, 256 * 2_585L))
    }
}
