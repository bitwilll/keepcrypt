package com.keepcrypt.entropy

import android.view.View
import android.view.ViewGroup
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.platform.ViewRootForTest
import androidx.compose.ui.semantics.SemanticsNode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.uiautomator.By
import androidx.test.uiautomator.Until
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Ui.START_SECONDS
import com.keepcrypt.entropy.Ui.assertPublicPadLabelled
import com.keepcrypt.entropy.Ui.await
import com.keepcrypt.entropy.Ui.awaitPick
import com.keepcrypt.entropy.Ui.awaitText
import com.keepcrypt.entropy.Ui.device
import com.keepcrypt.entropy.Ui.enabled
import com.keepcrypt.entropy.Ui.find
import com.keepcrypt.entropy.Ui.on
import com.keepcrypt.entropy.Ui.pressFace
import com.keepcrypt.entropy.Ui.roll
import com.keepcrypt.entropy.Ui.shown
import com.keepcrypt.entropy.Ui.stays
import com.keepcrypt.entropy.Ui.tap
import com.keepcrypt.entropy.Ui.text
import com.keepcrypt.entropy.Ui.toHome
import com.keepcrypt.entropy.ffi.Refusal
import com.keepcrypt.entropy.screens.CHECK_PROMPT
import com.keepcrypt.entropy.screens.CHECK_QUESTION
import com.keepcrypt.entropy.screens.CODE_REFUSED
import com.keepcrypt.entropy.screens.CROCKFORD_KEYS
import com.keepcrypt.entropy.screens.QR_SIDE_DP
import com.keepcrypt.entropy.screens.SNAPSHOT_NO_REGISTRY_KEY
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.screens.screenId
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The collision check without a snapshot on the phone (tasks/todo.md, M5 group 16), run by
 * scripts/android-instrument.sh on the shipping app in the API 31 and 36 legs, through UI Automator as
 * FlowTest is (Ui): a dice-only seed of vectors/kcr.json's public gate seed dice-50-words12, the
 * dice's Done at the minimum, the check prompt all on screen with no Seal ID (lead decision M5-55),
 * Skip confirmed on its own screen and Back there, Check now's seal card with the Seal ID drawn, its next
 * page the check QR, wholly inside its text column's viewport as it opens (read in-process, Stage U's
 * U3d), Back between the two keeping the same check QR, and the check QR's four actions, "Scan go-ahead
 * QR" among them (drawn, not pressed: the shipping app's camera prompt is
 * CaptureTest's, and a scanned go-ahead QR SnapshotDrillTest's, since only the test-registry app trusts
 * the test key), Match found's and Cannot check's confirms and Back, then the go-ahead code: the check
 * QR the screen drew is read in-process (Checker; captures of the app are black), a code through every
 * column and row of the Crockford pad types and Delete takes it back, a wrong code typed on the pad is
 * refused and the check, its nonce and the actions stay, and the code a checker builds from that QR's T
 * and nonce, typed on the pad, passes the check; the pad's 32 keys keep their labels (lead decision
 * M5-46: a Public pad), and the result's Show words leads through the privacy gate to the first insert
 * (group 17; the words themselves are FlowTest's). Home's Load registry snapshot (group 18): the shipping
 * app trusts no registry key yet, so vectors/kcr.json's with-dice-50, picked from Downloads through the
 * system's picker, is refused with that line, nothing loaded, and Back returns Home, which names none
 * (SnapshotDrillTest loads it in the test-registry app).
 */
@RunWith(AndroidJUnit4::class)
class CheckTest {
    /** The check QR the seal card holds now, read in-process: its text. */
    private fun drawnRequest(activity: MainActivity): String {
        val matrix = onMain { activity.model.state.value.checkRequest } ?: throw AssertionError("the seal card has no check QR")
        return Checker.read(matrix)
    }

    /** The node tagged tag under node (itself included), or null: a walk of the window's semantics, in-process. */
    private fun tagged(node: SemanticsNode, tag: String): SemanticsNode? {
        if (SemanticsProperties.TestTag in node.config && node.config[SemanticsProperties.TestTag] == tag) return node
        for (child in node.children) tagged(child, tag)?.let { return it }
        return null
    }

    /** The Compose root under view, or null. */
    private fun composeRoot(view: View): ViewRootForTest? {
        if (view is ViewRootForTest) return view
        if (view is ViewGroup) for (index in 0 until view.childCount) composeRoot(view.getChildAt(index))?.let { return it }
        return null
    }

    /**
     * The check QR's drawn square and the viewport of the text column it scrolls in, both in the root's
     * pixels, read in-process from the window's semantics (no UI Automator selector, and nothing of the
     * QR's text): the square unclipped (its position and size), the viewport the scrolling column's own
     * bounds.
     */
    private fun qrInColumn(activity: MainActivity): Pair<Rect, Rect> = onMain {
        val root = composeRoot(activity.window.decorView) ?: throw AssertionError("no Compose root in the window")
        val screen = tagged(root.semanticsOwner.unmergedRootSemanticsNode, screenId(Screen.CheckQr))
            ?: throw AssertionError("the check QR page is not drawn")
        val qr = tagged(screen, QR_TAG) ?: throw AssertionError("the check QR page draws no check QR")
        var column = qr.parent
        while (column != null && SemanticsProperties.VerticalScrollAxisRange !in column.config) column = column.parent
        if (column == null) throw AssertionError("the check QR is in no scrolling column")
        val at = qr.positionInRoot
        Rect(at.x, at.y, at.x + qr.size.width, at.y + qr.size.height) to column.boundsInRoot
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
            pressFace('2')
            awaitPick('2')
            tap("confirm")
            awaitText("dice_count", "50 / 50 rolls, 129.2 bits")
            assertTrue("Done at the minimum", enabled("dice_done"))
            tap("dice_done")
            on(activity, Screen.CheckPrompt, START_SECONDS)
            // The prompt draws no seal card (lead decision M5-55): all of it on screen, its question and why
            // and its two actions, and no text the seed's Seal ID, its text column scanned to the end.
            for (part in listOf(CHECK_HEADING, CHECK_QUESTION, CHECK_PROMPT)) {
                assertTrue("the check prompt does not show: $part", device.wait(Until.hasObject(By.text(part)), 10_000) == true)
            }
            find("check_now")
            find("skip")
            assertFalse("the check prompt draws the seed's Seal ID", shown(Screen.CheckPrompt, DICE_50_SEAL_ID))
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
            // From Check now on the Seal ID shows: on the seal card, under its grid, scrolled into view.
            assertTrue("the seal card does not draw the seed's Seal ID", shown(Screen.SealCard, DICE_50_SEAL_ID))
            val first = drawnRequest(activity)
            val (tag, nonce) = Checker.request(first)
            assertEquals("the check QR's T is not dice-50-words12's seal tag", DICE_50_TAG, tag)
            device.pressBack()
            stays(activity, Screen.SealCard, "Back on the seal card (the check binds)")
            // The seal card's next page: the check QR, wholly in its column's viewport as it opens (the Pi's
            // check QR page), with the four actions under it; Back between the two keeps the same check QR.
            tap("show_check_qr")
            on(activity, Screen.CheckQr)
            val (square, viewport) = qrInColumn(activity)
            val window = onMain { "${activity.window.decorView.width}x${activity.window.decorView.height}" }
            val scale = onMain { activity.resources.configuration.fontScale }
            val inside = square.left >= viewport.left && square.top >= viewport.top && square.right <= viewport.right &&
                square.bottom <= viewport.bottom
            assertTrue("the check QR $square is not wholly inside its column's viewport $viewport (window $window, font scale $scale)", inside)
            val side = QR_SIDE_DP * onMain { activity.resources.displayMetrics.density }
            assertEquals("the check QR is not drawn at its $QR_SIDE_DP dp side", side, square.width, 1f)
            for (action in listOf("scan_qr", "type_code", "match_found", "cannot_check")) find(action)
            assertEquals("the check QR page changed the check request", first, drawnRequest(activity))
            device.pressBack()
            on(activity, Screen.SealCard)
            assertEquals("Back to the seal card changed the check request", first, drawnRequest(activity))
            tap("show_check_qr")
            on(activity, Screen.CheckQr)
            assertEquals("the check QR changed between the pages", first, drawnRequest(activity))
            // Match found and Cannot check, each confirmed on its own screen; Back keeps the check.
            tap("match_found")
            on(activity, Screen.MatchFoundConfirm)
            tap("back")
            on(activity, Screen.CheckQr)
            tap("cannot_check")
            on(activity, Screen.CannotCheckConfirm)
            device.pressBack()
            on(activity, Screen.CheckQr)
            // A wrong code: refused; Back finds the same check QR (the same T and nonce) and its actions.
            val code = Checker.goAhead(tag, nonce)
            val wrong = Checker.wrong(code)
            tap("type_code")
            on(activity, Screen.CodeEntry)
            assertFalse("Done with no symbol", enabled("code_done"))
            assertFalse("Delete with no symbol", enabled("code_delete"))
            assertPublicPadLabelled("the go-ahead code's pad", CROCKFORD_KEYS)
            // Every column and every row of the pad types: one key from each column, the rows in turn (0, 9,
            // J, V, 4, D, P, Z). Before commit 17 a row of eight 46 dp keys was wider than the 312 dp the
            // screen's margins leave, which left the last columns no width, so a tap there reached the key
            // drawn over it. A key's bounds cannot show this: UI Automator gives a Compose key its touch
            // target, at least 48 dp and cut by the targets drawn after it (run 39673248591: key 7, the one
            // with no neighbour to its right, 96 x 78 px), never the drawn square. Delete takes it all back.
            val rows = CROCKFORD_KEYS.length / CODE_SYMBOLS
            val diagonal = (0 until CODE_SYMBOLS).map { column -> CROCKFORD_KEYS[(column % rows) * CODE_SYMBOLS + column] }
                .joinToString("")
            type(diagonal)
            repeat(CODE_SYMBOLS) { tap("code_delete") }
            awaitText("code", "____-____")
            assertFalse("Delete with no symbol left", enabled("code_delete"))
            type(wrong)
            tap("code_done")
            awaitText("code_refused", CODE_REFUSED)
            awaitText("code", "____-____")
            assertEquals(Screen.CodeEntry, onMain { activity.shownScreen })
            tap("back")
            on(activity, Screen.CheckQr)
            assertEquals("the check request changed after the wrong code", first, drawnRequest(activity))
            for (action in listOf("scan_qr", "type_code", "match_found", "cannot_check")) find(action)
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
            tap("show_words")
            find("privacy_gate")
            assertTrue("the words showed before the privacy gate", onMain { activity.model.state.value.gate })
            tap("pass_gate")
            await("past the gate", 10) { !onMain { activity.model.state.value.gate } }
            on(activity, Screen.Words)
            val atFirst = onMain { activity.model.state.value.insert?.let { it.position == 1 && it.count == 12 } }
            assertTrue("the words do not start at insert 1 of 12", atFirst == true)
            pass(
                "the check without a snapshot: Done at 50 rolls, the prompt with no Seal ID, Skip, the seal card's Seal ID " +
                    "$DICE_50_SEAL_ID, its check QR page with the QR wholly in view (window $window, font scale $scale) and " +
                    "its four actions (Scan go-ahead QR drawn), Back between them with the same check QR, Match found and " +
                    "Cannot check confirmed on their own screens and Back there, a wrong code " +
                    "refused with the same check QR, the code from the drawn check QR's T and nonce typed on the pad: the check " +
                    "passed; the pad's 32 keys labelled (M5-46); Show words through the gate to insert 1 of 12",
            )
            finish(activity)
        }
    }

    @Test
    fun aSnapshotPickedOnHomeIsRefusedInTheShippingAppWhichTrustsNoRegistryKeyYet() {
        Capture.whileOffline {
            Picker.putInDownloads(Checker.WITH_DICE_50_FILE, Checker.bytes(Checker.WITH_DICE_50_KCR))
            try {
                val activity = toHome()
                awaitText("home_snapshot", "No registry snapshot loaded")
                tap("load_snapshot")
                Picker.pick(Checker.WITH_DICE_50_FILE)
                on(activity, Screen.Snapshot, START_SECONDS)
                awaitText("snapshot_result", "Snapshot not loaded")
                awaitText("snapshot_refusal", SNAPSHOT_NO_REGISTRY_KEY)
                assertEquals(Refusal.NoRegistryKey, onMain { activity.model.state.value.snapshotRefusal })
                assertNull("the shipping app loaded a snapshot", onMain { activity.model.state.value.loaded })
                device.pressBack()
                on(activity, Screen.Home)
                awaitText("home_snapshot", "No registry snapshot loaded")
                pass(
                    "Load registry snapshot in the shipping app: with-dice-50.kcr picked from Downloads through DocumentsUI, " +
                        "refused: \"" + SNAPSHOT_NO_REGISTRY_KEY + "\"; nothing loaded; Back: Home, no snapshot named",
                )
                finish(activity)
            } finally {
                Picker.removeFromDownloads(Checker.WITH_DICE_50_FILE)
            }
        }
    }

    private companion object {
        /** vectors/kcr.json's dice-50-words12: 123456 repeated, its Seal ID and its seal tag T. */
        const val DICE_50_ROLLS = "123456"
        const val DICE_50_SEAL_ID = "YVM9CPP3"
        const val DICE_50_TAG = "f6e8965ac3e420f9061e7c1a7e9d829d9c7e8c17e433f4eed4094a5da599a256"

        /** The check QR's test tag on its page (CheckScreens.kt's CheckQrScreen). */
        const val QR_TAG = "check_request"

        /** The check prompt's heading (CheckScreens.kt's CheckPrompt). */
        const val CHECK_HEADING = "Check for collisions"

        /** The go-ahead code's symbols, as many as the Crockford pad has columns (crockfordPadEntry, CrockfordPad). */
        const val CODE_SYMBOLS = 8
    }
}
