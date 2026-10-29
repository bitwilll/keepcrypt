package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.HaltReason
import com.keepcrypt.entropy.ffi.KcHalt
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Refusal
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Words
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel

/**
 * Every CeremonyModel transition of commit 15 (tasks/todo.md, M5 group 14), over the real slot through
 * Core and the host library, with the long calls held on the test's worker so the test acts while
 * "Working..." shows; the screens' own transitions (group 15) are StartScreensTest's. Whether the slot
 * holds a session is read from the slot itself: the dice counts are offered only while one is
 * rolling, and the self-test only at home, empty (each other call halts). First launch is the first
 * screen and its Continue runs the start-up self-test (lead decision M5-50); a discard's start screen
 * is Go offline once that has passed, First launch before. The held state the phone keeps its screen on
 * by (lead decision M5-72 (b)) follows a session from its start's reply to Finish's end, and each discard,
 * a halt and wipeAll end it. Each test leaves the slot at home (wipeAll after it). A halt of the real slot latches it for the process, so that test is CeremonyModelHaltTest,
 * in a JVM of its own (and NoCoreCallBeforeContinueTest, which halts it first).
 */
class CeremonyModelTest {
    @AfterTest
    fun emptyTheSlot() {
        assertTrue(Core.wipeAll() is Reply.Done)
    }

    /** The slot holds a session, rolling. */
    private fun assertSessionHeld(message: String) {
        assertTrue(Core.diceProgress() is Reply.Done, message)
    }

    /** The slot is at home and empty: no session. */
    private fun assertNoSession(message: String) {
        assertTrue(Core.selfTest() is Reply.Done, message)
    }

    /** A model at Home, with a dice-only session started from Length by its own long call: the dice. */
    private fun withSession(): Rig {
        val rig = Rig().toHome().begin(Mode.DiceOnly, Words.Twelve)
        assertEquals(Screen.Dice, rig.screen, "a dice-only start opens the dice")
        assertSessionHeld("the start's session")
        return rig
    }

    @Test
    fun firstLaunchComesFirstAndItsContinueRunsTheSelfTestBeforeGoOffline() {
        val rig = Rig()
        assertEquals(Screen.FirstLaunch, rig.screen)
        rig.model.appReturned()
        assertEquals(Screen.FirstLaunch, rig.screen, "First launch is the first screen of every start")
        assertEquals(0, rig.worker.waiting, "no long call before First launch's Continue")
        assertTrue(rig.model.state.value.offline, "the offline monitor is read on the start")
        rig.model.firstLaunchDone()
        assertEquals(Screen.SelfTest, rig.screen)
        assertEquals(1, rig.worker.waiting, "the self-test, a long call")
        rig.worker.run()
        assertEquals(Screen.GoOffline, rig.screen)
        assertNull(rig.model.state.value.notice)
        assertNull(rig.model.state.value.overlay)
        assertTrue(rig.model.testRegistry)
        assertNoSession("a self-test holds no session")
    }

    @Test
    fun aPressDuringWorkingGoesNowhere() {
        val rig = withSession()
        rig.model.work({ Core.undoRoll() }) {}
        assertEquals(Screen.Working, rig.screen)
        assertEquals(1, rig.worker.waiting)
        rig.clock.now = Timers.WIPE_MILLIS
        rig.model.input()
        rig.model.dismissOverlay()
        rig.model.passGate()
        rig.model.back()
        rig.model.dicePick.replace('2')
        rig.model.confirmRoll()
        rig.model.tick()
        assertEquals(Screen.Working, rig.screen, "nothing leaves Working but its reply")
        assertNull(rig.model.state.value.overlay)
        rig.worker.run()
        assertEquals(Screen.Dice, rig.screen, "a long call that enters no screen returns to its own")
        assertEquals(0, rig.model.state.value.dice?.rolls, "the confirm during Working pushed nothing")
        // The presses reached no timer: 10 minutes after the last input, the idle wipe comes.
        rig.model.tick()
        assertEquals(Notice.Idle, rig.model.state.value.notice)
        assertNoSession("the idle wipe discarded the session")
    }

    @Test
    fun leavingDuringALongCallDiscardsAtOnceAndTheCallIsNeverMade() {
        val rig = withSession()
        rig.model.work({ Core.commit() }) { fail("a discarded call gives no value") }
        rig.model.appLeft()
        assertEquals(Screen.Working, rig.screen, "Working stays until the call's reply")
        assertTrue(rig.offline.started, "the offline monitor still reports while the app is away")
        // Core's discard came at once, before the call's turn on the worker.
        assertNoSession("the discard came at once")
        rig.worker.run()
        // The commit was never made (at home it would have halted the slot); the start screen says why.
        val state = rig.model.state.value
        assertEquals(Screen.GoOffline, state.screen)
        assertEquals(Notice.Left, state.notice)
        assertEquals(Overlay.Cover, state.overlay, "away from the app the cover stays up")
        assertNoSession("no call halted the slot")
    }

    @Test
    fun aDiscardedReplyReturnsTheUiToItsStartScreen() {
        val rig = withSession()
        // Going online while core runs the call: core drops what it made and answers discarded.
        rig.model.work<Unit>({
            rig.offline.set(false)
            Reply.Discarded
        }) { fail("a discarded call gives no value") }
        rig.worker.run()
        val state = rig.model.state.value
        assertEquals(Screen.GoOffline, state.screen)
        assertEquals(Notice.Offline, state.notice)
        assertFalse(state.offline)
        assertNull(state.overlay)
        assertNoSession("going online discarded the session")
    }

    @Test
    fun coresOwnDiscardedReplyReturnsTheUiToItsStartScreen() {
        val rig = Rig().toHome()
        // Discarded with no discard of the model's: the start screen, with no reason to give.
        rig.model.work<Unit>({ Reply.Discarded }) { fail("a discarded call gives no value") }
        rig.worker.run()
        assertEquals(Screen.GoOffline, rig.screen)
        assertNull(rig.model.state.value.notice)
    }

    @Test
    fun aCallThatReachedCoreAfterTheDiscardHasWhatItMadeDiscardedAgain() {
        val rig = Rig().toHome()
        var made = false
        // The app is left after the worker's look at the flag and before core takes the call: core
        // starts a session at home, which the model discards again on the worker.
        rig.model.work({
            rig.model.appLeft()
            Core.start(Words.Twelve, Mode.DiceOnly)
        }) { made = true }
        rig.worker.run()
        assertFalse(made, "a start after the discard is no ceremony")
        assertEquals(Screen.GoOffline, rig.screen)
        assertEquals(Notice.Left, rig.model.state.value.notice)
        assertNoSession("the late start's session was discarded again")
    }

    @Test
    fun aCallThatReachedCoreAfterWipeAllIsDiscardedThoughItsScopeIsCancelled() {
        val scope = CoroutineScope(Job() + Dispatchers.Unconfined)
        val rig = Rig(scope).startUp()
        var made = false
        // The holder's end (onCleared: the scope cancelled, then wipeAll) after the worker's look at
        // the flag and before core takes the call: core starts a session at home, and the cancelled
        // scope drops the reply, so only the worker can discard what the start made.
        rig.model.work({
            scope.cancel()
            rig.model.wipeAll()
            Core.start(Words.Twelve, Mode.DiceOnly)
        }) { made = true }
        rig.worker.run()
        assertFalse(made, "a start after wipeAll is no ceremony")
        assertNoSession("the late start's session was discarded on the worker")
    }

    @Test
    fun goingOnlineDuringALongCallDiscardsIt() {
        val rig = Rig().toHome()
        rig.model.chooseMode(Mode.DiceOnly)
        rig.model.chooseLength(Words.Twelve)
        rig.offline.set(false)
        assertEquals(Screen.Working, rig.screen)
        rig.worker.run()
        assertEquals(Screen.GoOffline, rig.screen)
        assertEquals(Notice.Offline, rig.model.state.value.notice)
        assertNoSession("the start was never made")
        // With no session the timers have nothing to wipe.
        rig.clock.now = Timers.WIPE_MILLIS
        rig.model.tick()
        assertEquals(Notice.Offline, rig.model.state.value.notice)
    }

    @Test
    fun goingOnlineBeforeTheSelfTestPassesOrWithNothingHeldWipesNothing() {
        val rig = Rig()
        rig.model.appReturned()
        rig.offline.set(false)
        assertEquals(Screen.FirstLaunch, rig.screen, "First launch needs no offline")
        rig.model.firstLaunchDone()
        rig.offline.set(true)
        rig.offline.set(false)
        assertEquals(Screen.SelfTest, rig.screen)
        rig.worker.run()
        assertEquals(Screen.GoOffline, rig.screen, "the self-test's reply was kept")
        assertEquals(1, rig.worker.ran, "one self-test: going online before it passed discarded nothing")
        assertNull(rig.model.state.value.notice)
        assertFalse(rig.model.state.value.offline)
        rig.offline.set(true)
        rig.offline.set(false)
        assertNull(rig.model.state.value.notice, "nothing held, nothing to wipe")
    }

    @Test
    fun goingOnlineWhileASessionIsHeldDiscardsItAtOnce() {
        val rig = withSession()
        rig.offline.set(false)
        val state = rig.model.state.value
        assertEquals(Screen.GoOffline, state.screen)
        assertEquals(Notice.Offline, state.notice)
        assertNull(state.overlay)
        assertNoSession("going online discarded the session")
        // The model holds nothing now: 9 minutes on, no warning comes.
        rig.offline.set(true)
        rig.clock.now = Timers.WARN_MILLIS
        rig.model.tick()
        assertNull(rig.model.state.value.overlay, "no session, so no idle warning")
    }

    @Test
    fun goingOnlineWhileTheAppIsAwayDiscardsTheSessionAtOnce() {
        val rig = withSession()
        rig.model.appLeft()
        assertSessionHeld("leaving a Public screen keeps the session")
        rig.offline.set(false)
        val state = rig.model.state.value
        assertEquals(Screen.GoOffline, state.screen)
        assertEquals(Notice.Offline, state.notice)
        assertEquals(Overlay.Cover, state.overlay, "away from the app the cover stays up")
        assertNoSession("going online away from the app discarded the session")
    }

    @Test
    fun aReturnWhileOnlineDiscardsTheSession() {
        val rig = withSession()
        rig.model.appLeft()
        // Online with no report while away (a frozen process gets none): the return reads it afresh.
        rig.offline.offline = false
        rig.clock.now = 30_000
        rig.model.appReturned()
        val state = rig.model.state.value
        assertEquals(Screen.GoOffline, state.screen)
        assertEquals(Notice.Offline, state.notice)
        assertFalse(state.offline)
        assertNoSession("the return read the phone online and discarded the session")
    }

    @Test
    fun leavingDuringTheStartUpSelfTestReturnsToFirstLaunchWhoseContinueRunsItAgain() {
        val rig = Rig().startUp()
        rig.model.firstLaunchDone()
        assertEquals(Screen.SelfTest, rig.screen)
        rig.model.appLeft()
        rig.worker.run()
        val away = rig.model.state.value
        assertEquals(Screen.FirstLaunch, away.screen, "the self-test's reply was discarded, so it has not passed")
        assertEquals(Overlay.Cover, away.overlay, "away from the app the cover stays up")
        assertNull(away.notice, "no session was held, so there is nothing to say")
        rig.model.appReturned()
        assertEquals(0, rig.worker.waiting, "a return runs nothing: First launch's Continue does")
        assertEquals(Screen.FirstLaunch, rig.screen)
        rig.model.firstLaunchDone()
        assertEquals(0, rig.worker.waiting, "the cover takes the press")
        rig.model.dismissOverlay()
        rig.model.firstLaunchDone()
        assertEquals(1, rig.worker.waiting, "the self-test again")
        rig.worker.run()
        assertEquals(Screen.GoOffline, rig.screen)
        assertNoSession("a self-test holds no session")
    }

    @Test
    fun leavingAPublicScreenCoversItAndSixtySecondsAwayWipesTheSession() {
        val rig = withSession()
        rig.clock.now = 1_000
        rig.model.appLeft()
        assertEquals(Screen.Dice, rig.screen)
        assertEquals(Overlay.Cover, rig.model.state.value.overlay)
        assertNull(rig.model.state.value.notice)
        assertSessionHeld("leaving a Public screen keeps the session")
        rig.clock.now = 60_999
        rig.model.tick()
        assertNull(rig.model.state.value.notice)
        assertSessionHeld("59.999 s away keeps it")
        rig.clock.now = 61_000
        rig.model.tick()
        assertEquals(Notice.Background, rig.model.state.value.notice)
        assertEquals(Overlay.Cover, rig.model.state.value.overlay, "still away: the cover stays")
        assertNoSession("60 s away wiped it")
    }

    @Test
    fun aReturnWithinSixtySecondsKeepsTheSessionAndTheCoverUntilATap() {
        val rig = withSession()
        rig.model.appLeft()
        rig.clock.now = 59_000
        rig.model.appReturned()
        assertEquals(Overlay.Cover, rig.model.state.value.overlay)
        assertEquals(2, rig.offline.starts, "the offline state is read again on the return")
        rig.model.dismissOverlay()
        assertNull(rig.model.state.value.overlay)
        rig.clock.now = 120_000
        rig.model.tick()
        assertNull(rig.model.state.value.notice)
        assertSessionHeld("back within 60 s, the session stays")
    }

    @Test
    fun theIdleWarningAndTheIdleWipe() {
        val rig = withSession()
        rig.clock.now = 539_999
        rig.model.tick()
        assertNull(rig.model.state.value.overlay)
        rig.clock.now = 540_000
        rig.model.tick()
        assertEquals(Overlay.Warning, rig.model.state.value.overlay)
        rig.model.dismissOverlay()
        assertNull(rig.model.state.value.overlay, "a tap keeps everything")
        rig.clock.now = 1_079_999
        rig.model.tick()
        assertNull(rig.model.state.value.overlay)
        assertSessionHeld("the tap started the idle time again")
        rig.clock.now = 1_080_000
        rig.model.tick()
        assertEquals(Overlay.Warning, rig.model.state.value.overlay)
        rig.clock.now = 1_140_000
        rig.model.tick()
        assertEquals(Notice.Idle, rig.model.state.value.notice)
        assertNull(rig.model.state.value.overlay)
        assertNoSession("10 minutes without input wiped it")
    }

    @Test
    fun aPickerTheAppOpenedIsNoLeavingButCountsUnderTheIdleRule() {
        val rig = withSession()
        rig.model.pickerOpened()
        rig.model.appLeft()
        assertNull(rig.model.state.value.overlay, "no cover for the app's own picker")
        assertTrue(rig.offline.started, "still offline-watched")
        rig.clock.now = 300_000
        rig.model.tick()
        assertSessionHeld("no background wipe under a picker")
        rig.clock.now = Timers.WIPE_MILLIS
        rig.model.tick()
        assertEquals(Notice.Idle, rig.model.state.value.notice, "the picker's time counted as foreground time")
        assertNoSession("the idle wipe")
        // Back from the picker, the next stop is leaving.
        rig.model.appReturned()
        rig.model.appLeft()
        assertEquals(Overlay.Cover, rig.model.state.value.overlay)
    }

    @Test
    fun aPickerOpenedThatNoStopFollowedEndsAtTheNextResume() {
        val rig = withSession()
        // A permission prompt only pauses the activity: pickerOpened, then a resume and no stop.
        rig.model.pickerOpened()
        rig.model.appResumed()
        rig.model.work({ Core.commit() }) { fail("a discarded call gives no value") }
        rig.model.appLeft()
        assertNoSession("the next stop was leaving: the discard came at once")
        rig.worker.run()
        assertEquals(Screen.GoOffline, rig.screen)
        assertEquals(Notice.Left, rig.model.state.value.notice)
    }

    @Test
    fun aRefusalReturnsToItsScreen() {
        val rig = Rig().startUp()
        var refusal: Refusal? = null
        rig.model.work<Unit>({ Reply.Refused(Refusal.WrongCode) }, refused = { refusal = it }) {
            fail("a refused call gives no value")
        }
        rig.worker.run()
        assertEquals(Screen.FirstLaunch, rig.screen)
        assertEquals(Refusal.WrongCode, refusal)
    }

    @Test
    fun aHaltEndsOnTheStopScreenWhichNothingLeaves() {
        val rig = Rig().startUp()
        rig.model.recordingChanged(true)
        // The halt status as Core throws it (this slot is left live: CeremonyModelHaltTest halts a real one).
        rig.model.work<Unit>({ throw KcHalt(HaltReason.HealthTest) }) { fail("a halted call gives no value") }
        rig.worker.run()
        assertEquals(Screen.Stop, rig.screen)
        assertEquals(HaltReason.HealthTest, rig.model.state.value.halt, "the stop screen keeps the halt's reason")
        assertTrue(rig.model.state.value.recording, "the stop screen keeps the recording flag")
        rig.model.appLeft()
        rig.model.appReturned()
        rig.offline.set(false)
        rig.model.input()
        rig.model.dismissOverlay()
        rig.model.back()
        rig.model.touched(1)
        rig.clock.now = 10 * Timers.WIPE_MILLIS
        rig.model.tick()
        assertEquals(Screen.Stop, rig.screen)
        assertEquals(HaltReason.HealthTest, rig.model.state.value.halt)
        assertNull(rig.model.state.value.overlay)
        assertNull(rig.model.state.value.notice)
    }

    /**
     * The stop screen names why the slot halted (M5 commit U3a; docs/mobile-apps.md, "When something
     * fails (Android)"): KcHalt's reason, as a long call's halt status carries it, reaches the model,
     * whose stop screen keeps it, and its line is that reason's fixed text, one per reason, none
     * another's; with no reason, internal's. The slot is left live (a fake throws).
     */
    @Test
    fun theStopScreenNamesEachHaltsReasonInItsOwnFixedLine() {
        val lines = mapOf(
            HaltReason.KnownAnswerTest to "A known-answer test failed.",
            HaltReason.EntropySource to "The entropy source failed.",
            HaltReason.HealthTest to "An entropy health test failed.",
            HaltReason.Internal to "An internal check failed.",
            HaltReason.ExportSelfCheck to "The watch-only export failed its self-check.",
            HaltReason.Panic to "The app's core stopped unexpectedly.",
        )
        assertEquals(HaltReason.entries.toSet(), lines.keys, "a line for every reason")
        assertEquals(lines.size, lines.values.toSet().size, "no line twice")
        for (reason in HaltReason.entries) {
            val rig = Rig().startUp()
            assertNull(rig.model.state.value.halt, "no reason before a halt")
            rig.model.work<Unit>({ throw KcHalt(reason) }) { fail("a halted call gives no value") }
            rig.worker.run()
            assertEquals(Screen.Stop, rig.screen, reason.name)
            assertEquals(reason, rig.model.state.value.halt, reason.name)
            assertEquals(lines.getValue(reason), stopLine(rig.model.state.value.halt), reason.name)
        }
        assertEquals(lines.getValue(HaltReason.Internal), stopLine(null), "no reason: internal's line")
    }

    @Test
    fun theRecordingFlagFollowsTheReports() {
        val rig = Rig().startUp()
        rig.model.recordingChanged(true)
        assertTrue(rig.model.state.value.recording)
        rig.model.start(Words.Twelve, Mode.DiceOnly)
        assertTrue(rig.model.state.value.recording, "a new screen keeps it")
        rig.worker.run()
        assertTrue(rig.model.state.value.recording)
        rig.model.recordingChanged(false)
        assertFalse(rig.model.state.value.recording)
    }

    @Test
    fun wipeAllEmptiesTheSlot() {
        val rig = withSession()
        assertTrue(rig.model.dicePick.replace('4'))
        rig.model.wipeAll()
        assertNoSession("wipeAll emptied it")
        assertEquals(0, rig.model.dicePick.length, "wipeAll wipes the dice pad's pick")
        assertTrue(rig.model.dicePick.zeroPastLength(), "and zeroes its byte")
        assertFalse(rig.offline.started, "the offline monitor stops at the model's end")
    }

    @Test
    fun wipeAllOnDeviceEntropyStopsTheMotionSource() {
        val rig = Rig().toHome().begin(Mode.Mixed, Words.Twelve)
        assertEquals(Screen.DeviceEntropy, rig.screen)
        assertTrue(rig.motion.running)
        rig.model.wipeAll()
        assertFalse(rig.motion.running, "the motion source stops at the model's end, whatever the screen")
        assertNoSession("wipeAll emptied it")
    }

    @Test
    fun aConfigurationChangeIsNoReturn() {
        val rig = Rig().startUp()
        rig.model.appReturned()
        rig.model.appReturned()
        assertEquals(1, rig.offline.starts)
        assertEquals(0, rig.worker.waiting)
        assertEquals(Screen.FirstLaunch, rig.screen)
    }

    /**
     * The held state the phone keeps its screen on by (lead decision M5-72 (b)), from the app's start to
     * Finish's end: nothing held on First launch, during the start-up self-test, on Go offline or on Home;
     * held from the start's reply through the dice, the seed's long call, Skip's result, the words past
     * the privacy gate, the read-back, the summary and the exports to the checklist; nothing held after
     * Finish's end.
     */
    @Test
    fun theHeldStateFollowsASessionFromItsStartToFinishsEnd() {
        val rig = Rig()
        assertFalse(rig.model.held.value, "the model made")
        rig.startUp()
        assertEquals(Screen.FirstLaunch, rig.screen)
        assertFalse(rig.model.held.value, "First launch")
        rig.model.firstLaunchDone()
        assertEquals(Screen.SelfTest, rig.screen)
        assertFalse(rig.model.held.value, "the start-up self-test")
        rig.worker.run()
        assertEquals(Screen.GoOffline, rig.screen)
        assertFalse(rig.model.held.value, "Go offline")
        rig.model.startOffline()
        assertEquals(Screen.Home, rig.screen)
        assertFalse(rig.model.held.value, "Home")
        rig.begin(Mode.DiceOnly, Words.Twelve)
        assertEquals(Screen.Dice, rig.screen)
        assertTrue(rig.model.held.value, "the dice")
        for (face in kcrRolls(DICE_50)) {
            rig.model.dicePick.replace(face)
            rig.model.confirmRoll()
        }
        rig.model.diceDone()
        assertEquals(Screen.Working, rig.screen)
        assertTrue(rig.model.held.value, "the seed's long call")
        rig.worker.run()
        rig.model.skip()
        rig.model.skipConfirmed()
        assertEquals(Screen.CheckResult, rig.screen)
        assertTrue(rig.model.held.value, "Skip's result")
        rig.toWords()
        assertEquals(Screen.Words, rig.screen)
        assertTrue(rig.model.held.value, "a words page, past the privacy gate")
        val words = kcrWords(DICE_50)
        repeat(words.size - 1) { rig.model.nextPage() }
        rig.model.startReadback()
        for (word in words) {
            for (letter in word.take(4)) rig.model.readbackLetters.type(letter)
            rig.model.readbackTyped()
            rig.model.readbackNext()
        }
        assertEquals(Screen.ReadbackDone, rig.screen)
        assertTrue(rig.model.held.value, "the read-back's end")
        rig.model.showSummary()
        rig.model.summaryDone()
        rig.model.skipBackup()
        rig.skipExports()
        assertEquals(Screen.Checklist, rig.screen)
        assertTrue(rig.model.held.value, "the checklist")
        rig.model.finishCeremony()
        assertEquals(Screen.Home, rig.screen)
        assertFalse(rig.model.held.value, "Finish's end")
        assertNoSession("Finish ended the session")
    }

    /**
     * Each new session is held from its start's reply, not before, and the held state ends with what is
     * held: going online, at once even during a long call (its screen stays until the reply), the idle
     * wipe (10 minutes without input, the timers' discard; their 9-minute warning keeps it), 60 s away
     * from a Public screen (held while away until then), leaving a Protected screen (a words page),
     * wipeAll and a halt (the fake's, so the slot stays live). Each case is a new model, from Home.
     */
    @Test
    fun eachDiscardWipeAllAndAHaltEndTheHeldState() {
        fun started(): Rig {
            val rig = Rig().toHome()
            rig.model.chooseMode(Mode.DiceOnly)
            rig.model.chooseLength(Words.Twelve)
            assertEquals(Screen.Working, rig.screen)
            assertFalse(rig.model.held.value, "the start's long call, before its reply")
            rig.worker.run()
            assertEquals(Screen.Dice, rig.screen)
            assertTrue(rig.model.held.value, "the start's reply: the dice")
            return rig
        }

        val online = started()
        online.offline.set(false)
        assertEquals(Notice.Offline, online.model.state.value.notice)
        assertFalse(online.model.held.value, "going online")

        val working = started()
        working.model.work({ Core.undoRoll() }) {}
        assertEquals(Screen.Working, working.screen)
        assertTrue(working.model.held.value, "a long call keeps what is held")
        working.offline.set(false)
        assertEquals(Screen.Working, working.screen, "the long call's screen stays until its reply")
        assertFalse(working.model.held.value, "going online during a long call, before its reply")
        working.worker.run()
        assertEquals(Notice.Offline, working.model.state.value.notice)
        assertFalse(working.model.held.value, "the long call's discarded reply")

        val idle = started()
        idle.clock.now += Timers.WARN_MILLIS
        idle.model.tick()
        assertEquals(Overlay.Warning, idle.model.state.value.overlay)
        assertTrue(idle.model.held.value, "the 9-minute warning keeps everything")
        idle.clock.now += Timers.WIPE_MILLIS - Timers.WARN_MILLIS
        idle.model.tick()
        assertEquals(Notice.Idle, idle.model.state.value.notice)
        assertFalse(idle.model.held.value, "the idle wipe")

        val away = started()
        away.model.appLeft()
        assertEquals(Overlay.Cover, away.model.state.value.overlay)
        assertTrue(away.model.held.value, "away from a Public screen, under 60 s")
        away.clock.now += Timers.BACKGROUND_MILLIS
        away.model.tick()
        assertEquals(Notice.Background, away.model.state.value.notice)
        assertFalse(away.model.held.value, "60 s away")

        val words = Rig().toHome().toSkippedResult(DICE_50).toWords()
        assertEquals(Screen.Words, words.screen)
        assertTrue(words.model.held.value, "a words page")
        words.model.appLeft()
        assertEquals(Notice.Left, words.model.state.value.notice)
        assertFalse(words.model.held.value, "leaving a words page")

        val wiped = started()
        wiped.model.wipeAll()
        assertFalse(wiped.model.held.value, "wipeAll")
        assertNoSession("wipeAll emptied the slot")

        val halted = started()
        halted.model.work<Unit>({ throw KcHalt(HaltReason.HealthTest) }) { fail("a halted call gives no value") }
        assertTrue(halted.model.held.value, "a long call keeps what is held")
        halted.worker.run()
        assertEquals(Screen.Stop, halted.screen)
        assertFalse(halted.model.held.value, "a halt")
    }

    private companion object {
        /** vectors/kcr.json's dice gate seed of 50 rolls and 12 words. */
        const val DICE_50 = "dice-50-words12"
    }
}
