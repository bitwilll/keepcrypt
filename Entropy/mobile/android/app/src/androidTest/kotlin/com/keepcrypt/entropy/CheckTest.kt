package com.keepcrypt.entropy

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.uiautomator.By
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Ui.START_SECONDS
import com.keepcrypt.entropy.Ui.awaitText
import com.keepcrypt.entropy.Ui.device
import com.keepcrypt.entropy.Ui.enabled
import com.keepcrypt.entropy.Ui.find
import com.keepcrypt.entropy.Ui.on
import com.keepcrypt.entropy.Ui.roll
import com.keepcrypt.entropy.Ui.stays
import com.keepcrypt.entropy.Ui.tap
import com.keepcrypt.entropy.Ui.text
import com.keepcrypt.entropy.Ui.toHome
import com.keepcrypt.entropy.screens.CODE_REFUSED
import com.keepcrypt.entropy.screens.Screen
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The collision check without a snapshot on the phone (tasks/todo.md, M5 group 16), run by
 * scripts/android-instrument.sh on the shipping app in the API 31 and 36 legs, through UI Automator as
 * FlowTest is (Ui): a dice-only seed of vectors/kcr.json's public gate seed dice-50-words12, the dice's
 * Done at the minimum, the check prompt with its Seal ID, Skip confirmed on its own screen and Back
 * there, Check now's seal card, Match found's and Cannot check's confirms and Back, then the go-ahead
 * code: the check QR the screen drew is read in-process (Checker; captures of the app are black), a
 * wrong code typed on the Crockford pad is refused and the check, its nonce and the actions stay, and
 * the code a checker builds from that QR's T and nonce, typed on the pad, passes the check.
 */
@RunWith(AndroidJUnit4::class)
class CheckTest {
    /** The check QR on the seal card now, read in-process: its text. */
    private fun drawnRequest(activity: MainActivity): String {
        val matrix = onMain { activity.model.state.value.checkRequest } ?: throw AssertionError("the seal card has no check QR")
        return Checker.read(matrix)
    }

    /** Types code on the code entry's Crockford pad, key by key, and waits for it shown in two groups. */
    private fun type(code: String) {
        for (symbol in code) tap("key_" + symbol)
        awaitText("code", Checker.grouped(code))
    }

    @Test
    fun theCodeFromTheDrawnCheckRequestTypedOnThePadPassesAndAWrongOneKeepsTheCheck() {
        Capture.whileOffline {
            val activity = toHome()
            tap("dice_only_seed")
            on(activity, Screen.Length)
            tap("words_12")
            on(activity, Screen.Dice, START_SECONDS)
            assertFalse("Done with no roll", enabled("dice_done"))
            roll(activity, 49, DICE_50_ROLLS)
            awaitText("dice_count", "49 / 50 rolls, 126.6 bits")
            assertFalse("Done below the minimum", enabled("dice_done"))
            tap("key_2")
            awaitText("dice_pick", "2")
            tap("confirm")
            awaitText("dice_count", "50 / 50 rolls, 129.2 bits")
            assertTrue("Done at the minimum", enabled("dice_done"))
            tap("dice_done")
            on(activity, Screen.CheckPrompt, START_SECONDS)
            // The seal card the prompt draws, below its text (UI Automator sees only what is scrolled into view).
            assertEquals(DICE_50_SEAL_ID, onMain { activity.model.state.value.seal?.sealId })
            device.pressBack()
            stays(activity, Screen.CheckPrompt, "Back on the check prompt")
            // Skip, confirmed on its own screen, whose Back (its button, then the system's) keeps the prompt.
            tap("skip")
            on(activity, Screen.SkipConfirm)
            tap("back")
            on(activity, Screen.CheckPrompt)
            tap("skip")
            on(activity, Screen.SkipConfirm)
            device.pressBack()
            on(activity, Screen.CheckPrompt)
            tap("check_now")
            on(activity, Screen.SealCard)
            val first = drawnRequest(activity)
            val (tag, nonce) = Checker.request(first)
            assertEquals("the check QR's T is not dice-50-words12's seal tag", DICE_50_TAG, tag)
            device.pressBack()
            stays(activity, Screen.SealCard, "Back on the seal card (the check binds)")
            // Match found and Cannot check, each confirmed on its own screen; Back keeps the check.
            tap("match_found")
            on(activity, Screen.MatchFoundConfirm)
            tap("back")
            on(activity, Screen.SealCard)
            tap("cannot_check")
            on(activity, Screen.CannotCheckConfirm)
            device.pressBack()
            on(activity, Screen.SealCard)
            // A wrong code: refused; Back finds the same check QR (the same T and nonce) and its actions.
            val code = Checker.goAhead(tag, nonce)
            val wrong = Checker.wrong(code)
            tap("type_code")
            on(activity, Screen.CodeEntry)
            assertFalse("Done with no symbol", enabled("code_done"))
            type(wrong)
            tap("code_done")
            awaitText("code_refused", CODE_REFUSED)
            awaitText("code", "____-____")
            assertEquals(Screen.CodeEntry, onMain { activity.shownScreen })
            tap("back")
            on(activity, Screen.SealCard)
            assertEquals("the check request changed after the wrong code", first, drawnRequest(activity))
            for (action in listOf("type_code", "match_found", "cannot_check")) find(action)
            // The code the checker builds from the drawn QR, typed on the pad.
            tap("type_code")
            on(activity, Screen.CodeEntry)
            assertFalse("the refusal outlived the code entry", device.hasObject(By.res("code_refused")))
            type(code)
            tap("code_done")
            on(activity, Screen.CheckResult)
            assertEquals(
                "No collision for seal $DICE_50_SEAL_ID, as of the date your checker showed.",
                text("check_result_text"),
            )
            pass(
                "the check without a snapshot: Done at 50 rolls, the prompt's Seal ID $DICE_50_SEAL_ID, Skip, Match found " +
                    "and Cannot check confirmed on their own screens and Back there, a wrong code refused with the same " +
                    "check QR, the code from the drawn check QR's T and nonce typed on the pad: the check passed",
            )
            finish(activity)
        }
    }

    private companion object {
        /** vectors/kcr.json's dice-50-words12: 123456 repeated, its Seal ID and its seal tag T. */
        const val DICE_50_ROLLS = "123456"
        const val DICE_50_SEAL_ID = "YVM9CPP3"
        const val DICE_50_TAG = "f6e8965ac3e420f9061e7c1a7e9d829d9c7e8c17e433f4eed4094a5da599a256"
    }
}
