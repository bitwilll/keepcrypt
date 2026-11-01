package com.keepcrypt.entropy

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.uiautomator.Until
import com.keepcrypt.entropy.Capture.PERMISSION_PROMPT
import com.keepcrypt.entropy.Capture.PROMPT_DENY
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.launch
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Capture.probe
import com.keepcrypt.entropy.Capture.shellText
import com.keepcrypt.entropy.GateSeeds.DICE_50_ROLLS
import com.keepcrypt.entropy.Ui.await
import com.keepcrypt.entropy.Ui.awaitText
import com.keepcrypt.entropy.Ui.device
import com.keepcrypt.entropy.Ui.on
import com.keepcrypt.entropy.Ui.tap
import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Words
import com.keepcrypt.entropy.screens.SCAN_REFUSED
import com.keepcrypt.entropy.screens.Screen
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The camera denied twice (tasks/todo.md, Stage U's U2l), on the shipping app in android-emulator.sh's registry
 * part: CAMERA revoked and its user flags cleared first, so the system asks. From the check QR, Scan go-ahead QR
 * and the system's prompt, "Don't allow": the scan screen says SCAN_REFUSED; Back, Scan again, the second prompt,
 * "Don't allow" again, which the system keeps ("don't ask again" on Android 11 and later): SCAN_REFUSED; Back and
 * Scan a third time: no prompt shows, and the scan is refused at once. Through all three the check stays open:
 * Type go-ahead code reaches the code entry with the same check QR. CAMERA's state is put back (revoked, its flags
 * cleared) in a finally. Setup to the check QR goes through the model's entry points (an edge test, as
 * LifecycleTest's); the scans and the prompts are pressed on the screen. CaptureTest's walk denies the prompt once.
 */
@RunWith(AndroidJUnit4::class)
class ScanRefusedTest {
    private val pkg get() = Capture.instrumentation.targetContext.packageName

    @Test
    fun theCameraDeniedTwiceIsRefusedEachTimeThenAskedNoMoreAndTheCheckStaysOpen() {
        reset()
        try {
            Capture.whileOffline {
                val activity = toCheckQr()
                val drawn = Checker.read(onMain { activity.model.state.value.checkRequest } ?: throw AssertionError("no check QR"))
                for (time in 1..2) {
                    tap("scan_qr")
                    val deny = device.wait(Until.findObject(PROMPT_DENY), 10_000)
                        ?: throw AssertionError("scan " + time + ": the system's CAMERA prompt did not show")
                    Capture.denyPrompt(device, deny)
                    on(activity, Screen.Scan)
                    awaitText("scan_line", SCAN_REFUSED)
                    probe("scan $time: the prompt denied; CAMERA " + Capture.permission(pkg, CAMERA).state)
                    device.pressBack()
                    on(activity, Screen.CheckQr)
                }
                tap("scan_qr")
                on(activity, Screen.Scan)
                awaitText("scan_line", SCAN_REFUSED)
                assertTrue("a third Scan asked again after two denials", !device.hasObject(PERMISSION_PROMPT))
                device.pressBack()
                on(activity, Screen.CheckQr)
                val still = Checker.read(onMain { activity.model.state.value.checkRequest } ?: throw AssertionError("the check QR went"))
                assertTrue("the check QR changed across the refusals: the check did not stay open", still == drawn)
                tap("type_code")
                on(activity, Screen.CodeEntry)
                pass("the camera denied twice: SCAN_REFUSED each time, a third Scan refused with no prompt; the same check QR, Type code: the code entry")
                finish(activity)
            }
        } finally {
            reset()
        }
    }

    /** CAMERA revoked and its user-set and user-fixed flags cleared, so the next scan asks as on a fresh install. */
    private fun reset() {
        shellText("pm revoke $pkg $CAMERA")
        shellText("pm clear-permission-flags $pkg $CAMERA user-set user-fixed")
    }

    /** A new MainActivity through the self-test and Go offline to the check QR page of dice-50-words12, through the model. */
    private fun toCheckQr(): MainActivity {
        val activity = launch()
        await("First launch", 10) { onMain { activity.shownScreen } == Screen.FirstLaunch }
        onMain { activity.model.firstLaunchDone() }
        await("Go offline: the start-up self-test passed", Ui.START_SECONDS) { onMain { activity.shownScreen } == Screen.GoOffline }
        await("the app reads airplane mode on and Wi-Fi off", 30) { onMain { activity.model.state.value.offline } }
        onMain {
            activity.model.startOffline()
            activity.model.chooseMode(Mode.DiceOnly)
            activity.model.chooseLength(Words.Twelve)
        }
        await("the dice", Ui.START_SECONDS) { onMain { activity.model.state.value.screen } == Screen.Dice }
        onMain {
            for (roll in DICE_50_ROLLS.repeat(9).take(50)) {
                activity.model.dicePick.replace(roll)
                activity.model.confirmRoll()
            }
            activity.model.diceDone()
        }
        await("the check prompt", Ui.START_SECONDS) { onMain { activity.model.state.value.screen } == Screen.CheckPrompt }
        onMain { activity.model.checkNow() }
        await("the seal card", 10) { onMain { activity.model.state.value.screen } == Screen.SealCard }
        onMain { activity.model.showCheckQr() }
        on(activity, Screen.CheckQr)
        return activity
    }

    private companion object {
        const val CAMERA = "android.permission.CAMERA"
    }
}
