package com.keepcrypt.entropy

import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.GateSeeds.DICE_99_ROLLS
import com.keepcrypt.entropy.Journeys.checkByTheDrawnCode
import com.keepcrypt.entropy.Journeys.checklistToFinish
import com.keepcrypt.entropy.Journeys.newSeedToDice
import com.keepcrypt.entropy.Journeys.registration
import com.keepcrypt.entropy.Journeys.revealDCommittingTo
import com.keepcrypt.entropy.Journeys.since
import com.keepcrypt.entropy.Journeys.summaryToWatchOffer
import com.keepcrypt.entropy.Journeys.wordsAndReadBack
import com.keepcrypt.entropy.Ui.START_SECONDS
import com.keepcrypt.entropy.Ui.awaitText
import com.keepcrypt.entropy.Ui.enabled
import com.keepcrypt.entropy.Ui.on
import com.keepcrypt.entropy.Ui.tap
import com.keepcrypt.entropy.Ui.tapRolls
import com.keepcrypt.entropy.Ui.toHome
import com.keepcrypt.entropy.screens.Screen
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith

/**
 * U1's last journey (tasks/todo.md, Stage U's U1h; lead decision M5-72 (a)): a new seed of 24 words mixed
 * with the phone's D, from First launch to Finish through the UI alone, on the shipping app in
 * android-emulator.sh's journeys part (M5-77 (a): its own class there, before the age: BackupTest, so the ui
 * part's job does not grow). Its stretches are Journeys' (JourneyTest's): Device entropy's sentence and
 * touches and C from the screen; 99 rolls tapped (Done disabled at 98); Check now's check QR and the code a
 * checker builds from it tapped: the check passed; the words (no vector's: read in-process, never printed)
 * on two devices with the device swap and its gate, all 24 read back by touches; the summary; the backup's
 * and watch-only's Skip; the registration QR, core's; Reveal D behind its gate, committing to C; the
 * checklist naming two devices; Finish: Home with the slot empty.
 */
@RunWith(AndroidJUnit4::class)
class MixedJourneyTest {
    @Test
    fun aMixedTwentyFourWordSeedIsCheckedByItsCodeAndReachesFinishOnTwoDevicesWithDThroughTheUiAlone() {
        Capture.whileOffline {
            val journey = SystemClock.elapsedRealtime()
            val activity = toHome()
            val c = newSeedToDice(activity, "words_24", 99)
            val rolls = SystemClock.elapsedRealtime()
            tapRolls(activity, 98, DICE_99_ROLLS)
            assertFalse("Done one roll below a 24-word seed's 99", enabled("dice_done"))
            tapRolls(activity, 1, DICE_99_ROLLS[98 % DICE_99_ROLLS.length].toString())
            val rollTime = since(rolls)
            awaitText("dice_count", "99 / 99 rolls, 255.9 bits")
            tap("dice_done")
            on(activity, Screen.CheckPrompt, START_SECONDS)
            tap("check_now")
            on(activity, Screen.SealCard)
            tap("show_check_qr")
            on(activity, Screen.CheckQr)
            checkByTheDrawnCode(activity)
            val readback = wordsAndReadBack(activity, null, 24)
            summaryToWatchOffer(activity)
            tap("skip_watch_only")
            on(activity, Screen.RegisterOffer)
            registration(activity, null)
            revealDCommittingTo(activity, c)
            checklistToFinish(activity, 2)
            pass(
                "the mixed 24-word journey through the UI alone: Device entropy's sentence and touches, C from the screen, " +
                    "99 rolls tapped ($rollTime), Done disabled at 98; the drawn check QR's code tapped: the check passed; " +
                    "the gate, 24 inserts by Next on two devices with the swap and its gate, 24 read back by touches " +
                    "($readback); the summary; the registration QR, core's; D behind its gate, committing to C; the " +
                    "checklist naming two devices, Finish: Home with the slot empty; the journey " + since(journey),
            )
            finish(activity)
        }
    }
}
