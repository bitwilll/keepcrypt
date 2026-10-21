package com.keepcrypt.entropy

import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.launch
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Capture.probe
import com.keepcrypt.entropy.Capture.waitUntil
import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Words
import com.keepcrypt.entropy.screens.Screen
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The native library in the app's own process (tasks/todo.md, M5 group 6, the ARM and 16 KB leg):
 * scripts/android-emulator.sh runs it on the 16 KB-page image once for x86_64 and once for each ARM
 * ABI the image translates (the APK installed with adb install --abi). The app's own start shows
 * First launch with no core call; its Continue, pressed through the model as the button calls it
 * (lead decision M5-50), loads libkeepcrypt.so (System.loadLibrary, JNI_OnLoad) and passes the
 * self-test through the bridge, and Go offline shows; then the self-test is called again, and a
 * dice-only ceremony (start, commit, start_dice, dice-50-words12's rolls, finish, as Vectors.kt's
 * sealed runs it) gives its Seal ID through the bridge. The rolls and the Seal ID are
 * vectors/kcr.json's public gate seed (the JVM tests read the same values from that file).
 */
@RunWith(AndroidJUnit4::class)
class NativeTest {
    @Test
    fun theLibraryLoadsPassesTheSelfTestAndGivesTheDice50Vector() {
        probe("native library directory: " + Capture.instrumentation.targetContext.applicationInfo.nativeLibraryDir)
        val activity = launch()
        waitUntil("the first screen, First launch") { onMain { activity.shownScreen } == Screen.FirstLaunch }
        onMain { activity.model.firstLaunchDone() }
        val end = SystemClock.elapsedRealtime() + START_MS
        while (onMain { activity.shownScreen } != Screen.GoOffline) {
            if (onMain { activity.shownScreen } == Screen.Stop) fail("the start-up self-test halted: the stop screen")
            if (SystemClock.elapsedRealtime() > end) fail("no Go offline within 120 s of Continue: the start-up self-test did not pass")
            SystemClock.sleep(100)
        }
        finish(activity)
        assertTrue("self_test", Core.selfTest() is Reply.Done)
        assertTrue("start", Core.start(Words.Twelve, Mode.DiceOnly) is Reply.Done)
        assertTrue("commit", Core.commit() is Reply.Done)
        val commitment = Core.commitment()
        assertTrue("no C in dice-only mode", commitment is Reply.Done && commitment.value == null)
        assertTrue("start_dice", Core.startDice() is Reply.Done)
        for (roll in DICE_50_ROLLS) {
            assertTrue("a roll", Core.pushRoll(roll - '0') is Reply.Done)
        }
        assertTrue("finish", Core.finish() is Reply.Done)
        val sealId = when (val seal = Core.seal()) {
            is Reply.Done -> seal.value.sealId
            is Reply.Refused, Reply.Discarded -> null
        }
        assertEquals(DICE_50_SEAL_ID, sealId)
        assertTrue("wipe_all", Core.wipeAll() is Reply.Done)
        pass("native library: JNI_OnLoad, the start-up self-test, self_test again and dice-50-words12's Seal ID $DICE_50_SEAL_ID")
    }

    private companion object {
        /** A translated library is slower: two minutes for the start-up self-test. */
        const val START_MS = 120_000L

        /** vectors/kcr.json's dice-50-words12: 50 rolls, 123456 repeated, and its Seal ID. */
        const val DICE_50_ROLLS = "12345612345612345612345612345612345612345612345612"
        const val DICE_50_SEAL_ID = "YVM9CPP3"
    }
}
