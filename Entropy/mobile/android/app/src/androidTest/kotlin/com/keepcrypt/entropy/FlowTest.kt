package com.keepcrypt.entropy

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.runner.lifecycle.Stage
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.launch
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Capture.probe
import com.keepcrypt.entropy.Capture.shellText
import com.keepcrypt.entropy.Ui.BUTTON
import com.keepcrypt.entropy.Ui.DOT
import com.keepcrypt.entropy.Ui.START_SECONDS
import com.keepcrypt.entropy.Ui.assertInsert
import com.keepcrypt.entropy.Ui.assertPublicPadLabelled
import com.keepcrypt.entropy.Ui.await
import com.keepcrypt.entropy.Ui.awaitPick
import com.keepcrypt.entropy.Ui.awaitText
import com.keepcrypt.entropy.Ui.enabled
import com.keepcrypt.entropy.Ui.find
import com.keepcrypt.entropy.Ui.fresh
import com.keepcrypt.entropy.Ui.letterKeys
import com.keepcrypt.entropy.Ui.on
import com.keepcrypt.entropy.Ui.pressFace
import com.keepcrypt.entropy.Ui.read
import com.keepcrypt.entropy.Ui.roll
import com.keepcrypt.entropy.Ui.sameWord
import com.keepcrypt.entropy.Ui.shown
import com.keepcrypt.entropy.Ui.stage
import com.keepcrypt.entropy.Ui.stays
import com.keepcrypt.entropy.Ui.tap
import com.keepcrypt.entropy.Ui.text
import com.keepcrypt.entropy.Ui.toHome
import com.keepcrypt.entropy.Ui.two
import com.keepcrypt.entropy.Ui.typeLetters
import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.QrMatrix
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Secret
import com.keepcrypt.entropy.ffi.Verdict
import com.keepcrypt.entropy.screens.APP_VERSION
import com.keepcrypt.entropy.screens.ASCII_PAGES
import com.keepcrypt.entropy.screens.CHECKLIST
import com.keepcrypt.entropy.screens.DICE_KEYS
import com.keepcrypt.entropy.screens.DICE_ONLY
import com.keepcrypt.entropy.screens.HEADPHONES_WARNING
import com.keepcrypt.entropy.screens.INSERTS_PER_DEVICE
import com.keepcrypt.entropy.screens.MAX_ROLLS
import com.keepcrypt.entropy.screens.Notice
import com.keepcrypt.entropy.screens.OVERVIEW_WORDS
import com.keepcrypt.entropy.screens.PASSPHRASE_WALLET
import com.keepcrypt.entropy.screens.REVEAL_D
import com.keepcrypt.entropy.screens.SAFE_IF_EITHER
import com.keepcrypt.entropy.screens.SECRET_TAG
import com.keepcrypt.entropy.screens.SEEDBOOK_RULES
import com.keepcrypt.entropy.screens.SKIPPED
import com.keepcrypt.entropy.screens.SOURCE_ADDRESS
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.screens.TWO_DEVICES
import com.keepcrypt.entropy.screens.asciiPage
import com.keepcrypt.entropy.screens.deviceLegText
import com.keepcrypt.entropy.screens.fingerprintHex
import com.keepcrypt.entropy.screens.flavourText
import com.keepcrypt.entropy.screens.hexGroups
import com.keepcrypt.entropy.screens.screenId
import java.security.MessageDigest
import java.util.regex.Pattern
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The flows on the phone (tasks/todo.md, M5 groups 15, 17 and 18), run by scripts/android-instrument.sh
 * on the shipping app in the API 31 and 36 legs: the screens from the start to the dice, the words to
 * the end of the ceremony, the exports after the backup (the watch-only export with a BIP39 passphrase,
 * the registration and D) and Home's About. UI Automator taps the controls by their resource ids (Compose test tags,
 * group 6) as a user would, and reads what they show from the accessibility tree; the many rolls a
 * minimum takes go through the model's dice pick and confirmRoll, the entry points the pad and Confirm
 * call (group 6, "Driving"), with a few by tap around them (Ui, shared with CheckTest and
 * SnapshotDrillTest), and likewise most pages and read-backs go through the model's entry points their
 * buttons and the letter pad call, with taps on some. The words a page shows are read in-process from
 * the page the model holds (captures of the app are black) and compared with the gate seed's vector,
 * never printed. The rolls are vectors/kcr.json's public gate seeds' (the new seed's 50
 * dice-50-words12's, mixed with the phone's D; the dice-only seeds' dice-50-words12's and
 * dice-99-words24's, whose words the words' tests check). Each test puts the phone's airplane-mode and
 * Wi-Fi settings back as they were.
 */
@RunWith(AndroidJUnit4::class)
class FlowTest {
    private val device: UiDevice get() = UiDevice.getInstance(Capture.instrumentation)

    /**
     * New seed, 12 words: Home to Length and Back to Home (nothing is lost there), Length's 12 words,
     * Device entropy with MA's sentence (taps on it are touches for the pool) where Back does nothing,
     * Commitment's C as 16 groups of 4 hex digits, then the dice, with no dice-only line: Confirm and Undo
     * off at first, a face pressed on the pad (Ui.pressFace) and confirmed, undone, Back doing nothing,
     * and on to the minimum, 50 rolls. Then Wi-Fi comes on during the dice, airplane mode staying on: the
     * session is wiped, Go offline says why and shows the two states apart (airplane mode on, Wi-Fi on),
     * and Start is disabled.
     */
    @Test
    fun aNewSeedOfTwelveWordsReachesTheDiceMinimumAndWifiOnWipesIt() {
        Capture.whileOffline {
            val activity = toHome()
            tap("new_seed")
            on(activity, Screen.Length)
            device.pressBack()
            on(activity, Screen.Home)
            tap("new_seed")
            on(activity, Screen.Length)
            tap("words_12")
            on(activity, Screen.DeviceEntropy, START_SECONDS)
            assertEquals(SAFE_IF_EITHER, text("device_entropy_sentence"))
            repeat(3) { tap("device_entropy_sentence") }
            device.pressBack()
            stays(activity, Screen.DeviceEntropy, "Back on Device entropy, which holds a session")
            tap("continue")
            on(activity, Screen.Commitment)
            val c = text("commitment_hex")
            assertTrue("C is not 16 groups of 4 hex digits in four rows: " + c.length, HEX_GROUPS.matches(c))
            tap("continue")
            on(activity, Screen.Dice)
            assertEquals("0 / 50 rolls, 0.0 bits", text("dice_count"))
            assertFalse("the dice-only line in a new seed", device.hasObject(By.res("dice_only")))
            assertFalse("Confirm with no face picked", enabled("confirm"))
            assertFalse("Undo with no roll", enabled("undo"))
            pressFace('3')
            awaitPick('3')
            assertTrue("Confirm with a face picked", enabled("confirm"))
            tap("confirm")
            awaitText("dice_count", "1 / 50 rolls, 2.5 bits")
            assertTrue("the pick goes with the confirm", text("dice_pick") == "-")
            tap("undo")
            awaitText("dice_count", "0 / 50 rolls, 0.0 bits")
            device.pressBack()
            stays(activity, Screen.Dice, "Back on the dice")
            assertEquals("0 / 50 rolls, 0.0 bits", text("dice_count"))
            roll(activity, 49, DICE_50_ROLLS)
            awaitText("dice_count", "49 / 50 rolls, 126.6 bits")
            assertFalse("the minimum is not reached at 49 rolls", device.hasObject(By.res("dice_minimum")))
            pressFace('2')
            awaitPick('2')
            tap("confirm")
            awaitText("dice_count", "50 / 50 rolls, 129.2 bits")
            find("dice_minimum")
            shellText("cmd wifi set-wifi-enabled enabled")
            on(activity, Screen.GoOffline, 30)
            assertEquals(Notice.Offline, onMain { activity.model.state.value.notice })
            assertEquals("The session was wiped: the phone went online.", text("notice"))
            // The one mixed state the flows reach (airplane_mode_on 1, wifi_on 2): each state on its own line.
            awaitText("airplane_mode", "Airplane mode: on")
            awaitText("wifi", "Wi-Fi: on")
            assertFalse("Start with Wi-Fi on inside airplane mode", enabled("start"))
            assertTrue("the slot is not at home: the session was not wiped", Core.selfTest() is Reply.Done)
            pass(
                "new seed, 12 words: Back from Length, Device entropy, C in 16 groups, the dice's pick, confirm, " +
                    "undo and minimum (50 / 50 rolls, 129.2 bits); Wi-Fi on during the dice wiped it, back to Go offline " +
                    "(airplane mode on, Wi-Fi on, Start disabled)",
            )
            finish(activity)
        }
    }

    /**
     * Dice-only seed, 24 words: from Length straight to the dice, past Device entropy and Commitment
     * (each waits for a tap, and none comes), with the dice-only line; the minimum, 99 rolls; then 256,
     * where Confirm and the pad are disabled and the model refuses a 257th as well, so core, which
     * halts on one, holds 256 still; Back does nothing.
     */
    @Test
    fun aDiceOnlySeedOfTwentyFourWordsSkipsTwoScreensAndStopsAt256Rolls() {
        Capture.whileOffline {
            val activity = toHome()
            tap("dice_only_seed")
            on(activity, Screen.Length)
            tap("words_24")
            on(activity, Screen.Dice, START_SECONDS)
            assertEquals("0 / 99 rolls, 0.0 bits", text("dice_count"))
            assertEquals(DICE_ONLY, text("dice_only"))
            roll(activity, 98, DICE_99_ROLLS)
            awaitText("dice_count", "98 / 99 rolls, 253.3 bits")
            assertFalse("the minimum is not reached at 98 rolls", device.hasObject(By.res("dice_minimum")))
            pressFace('4')
            awaitPick('4')
            tap("confirm")
            awaitText("dice_count", "99 / 99 rolls, 255.9 bits")
            find("dice_minimum")
            roll(activity, MAX_ROLLS - 100, DICE_99_ROLLS)
            awaitText("dice_count", "255 / 99 rolls, 659.1 bits")
            pressFace('5')
            awaitPick('5')
            tap("confirm")
            awaitText("dice_count", "256 / 99 rolls, 661.7 bits")
            find("dice_cap")
            assertFalse("Confirm at 256 rolls", enabled("confirm"))
            assertFalse("the pad at 256 rolls", enabled("key_1"))
            tap("key_1")
            assertTrue("a disabled key picks nothing", text("dice_pick") == "-")
            onMain {
                activity.model.dicePick.replace('1')
                activity.model.confirmRoll()
            }
            val progress = Core.diceProgress()
            assertTrue("core does not hold 256 rolls", progress is Reply.Done && progress.value.rolls == MAX_ROLLS)
            device.pressBack()
            stays(activity, Screen.Dice, "Back on the dice")
            assertEquals("256 / 99 rolls, 661.7 bits", text("dice_count"))
            pass("dice-only seed, 24 words: straight to the dice, the dice-only line, the minimum (99), and no 257th roll")
            finish(activity)
        }
    }

    /**
     * Go offline online: both states shown, Start disabled and a tap on it doing nothing; the button
     * opens the system's airplane-mode settings over the app (Back returns, to the privacy cover, since
     * the app was left); offline, Start is enabled and leads Home; Wi-Fi on at Home, with nothing held,
     * returns to Go offline with nothing wiped.
     */
    @Test
    fun startStaysDisabledOnlineAndTheButtonOpensTheAirplaneModeSettings() {
        val airplane = Capture.globalSetting("airplane_mode_on")
        val wifi = Capture.globalSetting("wifi_on")
        probe("before the test: airplane_mode_on=$airplane, wifi_on=$wifi")
        try {
            shellText("cmd connectivity airplane-mode disable")
            shellText("cmd wifi set-wifi-enabled enabled")
            val activity = launch()
            on(activity, Screen.FirstLaunch)
            tap("first_launch_continue")
            on(activity, Screen.GoOffline, START_SECONDS)
            await("the app reads the phone online", 30) { !onMain { activity.model.state.value.offline } }
            awaitText("airplane_mode", "Airplane mode: off")
            awaitText("wifi", "Wi-Fi: on")
            assertFalse("Start online", enabled("start"))
            tap("start")
            stays(activity, Screen.GoOffline, "Start, disabled online")
            tap("airplane_settings")
            await("the settings over the app", 30) { stage(activity) == Stage.STOPPED }
            val focus = shellText("dumpsys window").lines().filter { it.contains("mCurrentFocus=") }.joinToString("; ") { it.trim() }
            probe("airplane-mode settings: $focus")
            assertTrue("the settings' window is not in focus: " + focus, focus.contains("com.android.settings"))
            device.pressBack()
            await("back in the app", 30) { stage(activity) == Stage.RESUMED }
            tap("cover")
            shellText("cmd connectivity airplane-mode enable")
            shellText("cmd wifi set-wifi-enabled disabled")
            await("the app reads the phone offline", 30) { onMain { activity.model.state.value.offline } }
            awaitText("airplane_mode", "Airplane mode: on")
            awaitText("wifi", "Wi-Fi: off")
            assertTrue("Start offline", enabled("start"))
            tap("start")
            on(activity, Screen.Home)
            shellText("cmd wifi set-wifi-enabled enabled")
            on(activity, Screen.GoOffline, 30)
            assertEquals("nothing was held, so nothing was wiped", null, onMain { activity.model.state.value.notice })
            pass("Go offline: Start disabled online, the airplane-mode settings opened and left, Start offline; Wi-Fi on at Home returns to Go offline")
            finish(activity)
        } finally {
            shellText("cmd connectivity airplane-mode " + (if (airplane == "1") "enable" else "disable"))
            shellText("cmd wifi set-wifi-enabled " + (if (wifi == "0" || wifi == "3") "disabled" else "enabled"))
        }
    }


    /** The overview's page shows words 4 x page + 1 to 4 x page + 4, read in-process, with its header from the screen. */
    private fun assertOverview(activity: MainActivity, words: List<String>, page: Int, device: Int, devices: Int) {
        await("overview page " + (page + 1), 10) {
            onMain { activity.model.state.value.let { it.screen == Screen.WordsOverview && it.page == page && !it.gate } }
        }
        val same = onMain {
            val inserts = checkNotNull(activity.model.state.value.overview)
            inserts.size == OVERVIEW_WORDS && inserts.withIndex().all { (at, insert) ->
                insert.position == page * OVERVIEW_WORDS + at + 1 && insert.device == device &&
                    sameWord(insert, words[page * OVERVIEW_WORDS + at])
            }
        }
        assertTrue("overview page " + (page + 1) + " is not the vector's words", same)
        val first = page * OVERVIEW_WORDS + 1
        awaitText("overview_header", "Words " + two(first) + "-" + two(first + 3) + DOT + "device " + device + " of " + devices)
    }

    /**
     * Whether a node of the app's tagged secret draws text, read in-process (Capture.nodes): a secret's
     * text goes into no UI Automator selector, which UI Automator logs (lead decision M5-68 (e)).
     */
    private fun drawsSecret(text: String): Boolean =
        Capture.nodes(Capture.instrumentation.targetContext.packageName).any { it.resourceName == SECRET_TAG && it.text == text }

    /** The read-back of insert index + 1 through the model's letter pad and Done, as the pad calls them, then Next. */
    private fun readBack(activity: MainActivity, words: List<String>, index: Int) {
        val matched = onMain {
            for (letter in words[index].take(4)) activity.model.readbackLetters.type(letter)
            activity.model.readbackTyped()
            activity.model.state.value.matched
        }
        assertTrue("insert " + (index + 1) + " did not read back", matched)
        onMain { activity.model.readbackNext() }
    }

    /**
     * From Home: a dice-only seed of the length length's button picks, with count rolls of pattern (the dice
     * pad's six keys labelled), Done, Skip and its confirm, then Show words and the privacy gate, its
     * SeedBook rules shown and Back doing nothing there, and "I'm alone, show words".
     */
    private fun toWords(activity: MainActivity, length: String, count: Int, pattern: String, diceLine: String) {
        tap("dice_only_seed")
        on(activity, Screen.Length)
        tap(length)
        on(activity, Screen.Dice, START_SECONDS)
        assertPublicPadLabelled("the dice pad", DICE_KEYS)
        roll(activity, count, pattern)
        awaitText("dice_count", diceLine)
        tap("dice_done")
        on(activity, Screen.CheckPrompt, START_SECONDS)
        tap("skip")
        on(activity, Screen.SkipConfirm)
        tap("confirm_action")
        on(activity, Screen.CheckResult)
        awaitText("check_result_text", SKIPPED)
        tap("show_words")
        find("privacy_gate")
        assertTrue("the words showed before the privacy gate", onMain { activity.model.state.value.gate })
        awaitText("seedbook_rules", SEEDBOOK_RULES)
        awaitText("headphones_warning", HEADPHONES_WARNING)
        device.pressBack()
        stays(activity, Screen.Words, "Back on the words' privacy gate")
        assertTrue("Back took the privacy gate away", onMain { activity.model.state.value.gate })
        tap("pass_gate")
        await("past the gate", 10) { !onMain { activity.model.state.value.gate } }
    }

    /**
     * The words to the end of the ceremony (group 17) for vectors/kcr.json's dice-50-words12, its check
     * skipped: Show words on Skip's result, the privacy gate with the SeedBook's safety rules (Back does
     * nothing there); each of the 12 insert pages paged by Next is the vector's word with its position
     * and device (read in-process, compared and never printed), Back on the fourth going to the third;
     * Next disabled on the last; the overview's three pages from there and Insert view back; on the last
     * insert, the read-back: the letter pad's 26 keys found with their button role alone and nothing on
     * the screen naming a letter (lead decision M5-46; the dice pad's six keep their labels), the first
     * inserts read back, then an e or an i among an insert's first four letters typed on the pad as its
     * mirror partner: the mismatch names that face a mirror misread; Show the insert, whose one way on is
     * back to the read-back; the insert typed on the pad correctly: a match, the whole word shown; the rest
     * read back; the read-back's end, the wallet summary (core's fingerprint and first address), the
     * encrypted backup's offer and its Skip (BackupTest saves one), the watch-only offer and its Skip, the
     * registration QR behind the privacy gate (read in-process: the seed's registration text, its seal code
     * kcr.json's), its Next leading straight to the checklist (a dice-only seed has no D), and Finish: Home,
     * with the slot empty.
     */
    @Test
    fun aDiceOnlySeedsWordsReadBackOnTheLetterPadToTheSummaryAndFinishHome() {
        Capture.whileOffline {
            val activity = toHome()
            toWords(activity, "words_12", 50, DICE_50_ROLLS, "50 / 50 rolls, 129.2 bits")
            val words = DICE_50_WORDS
            for (index in words.indices) {
                assertInsert(activity, words, index, 1, 1)
                if (index == 3) {
                    device.pressBack()
                    assertInsert(activity, words, 2, 1, 1)
                    tap("next")
                    assertInsert(activity, words, 3, 1, 1)
                }
                if (index + 1 < words.size) tap("next")
            }
            assertFalse("Next on the last insert", enabled("next"))
            tap("overview")
            assertOverview(activity, words, 2, 1, 1)
            tap("previous")
            assertOverview(activity, words, 1, 1, 1)
            tap("previous")
            assertOverview(activity, words, 0, 1, 1)
            tap("insert_view")
            assertInsert(activity, words, 0, 1, 1)
            onMain { repeat(words.size - 1) { activity.model.nextPage() } }
            assertInsert(activity, words, words.size - 1, 1, 1)
            tap("start_readback")
            on(activity, Screen.ReadbackEntry)
            assertFalse("a gate between the Protected words and the Protected read-back", onMain { activity.model.state.value.gate })
            awaitText("readback_header", "Read back insert 01" + DOT + "device 1 of 1")
            letterKeys(Screen.ReadbackEntry)
            val misread = words.indexOfFirst { word -> word.take(4).any { it == 'e' || it == 'i' } }
            assertTrue("the gate seed has an e or an i among a word's first four letters", misread >= 0)
            for (index in 0 until misread) readBack(activity, words, index)
            val face = words[misread].take(4).indexOfFirst { it == 'e' || it == 'i' } + 1
            val wrong = words[misread].take(4).let { it.substring(0, face - 1) + (if (it[face - 1] == 'e') 'i' else 'e') + it.substring(face) }
            awaitText("readback_header", "Read back insert " + two(misread + 1) + DOT + "device 1 of 1")
            typeLetters(activity, Screen.ReadbackEntry, wrong) { it.readbackLetters }
            tap("letters_done")
            on(activity, Screen.ReadbackMismatch)
            awaitText("mismatch_header", "Insert " + two(misread + 1) + " does not match" + DOT + "device 1 of 1")
            assertTrue("the mismatch does not name the e/i face a mirror misread", drawsSecret("Face " + face + ": mirror misread"))
            val named = onMain {
                val mismatch = checkNotNull(activity.model.state.value.mismatch)
                (1..4).all { (it == face) == (mismatch.face(it).verdict == Verdict.MirrorMisread) }
            }
            assertTrue("core's verdicts are not one mirror misread on the e/i face", named)
            tap("review_insert")
            await("the insert reviewed", 10) { onMain { activity.model.state.value.let { it.screen == Screen.Words && it.reviewing } } }
            find("back_to_readback")
            assertFalse("the reviewed insert offers Next", device.hasObject(By.res("next")))
            assertTrue("the reviewed insert is not the misread one", onMain { sameWord(checkNotNull(activity.model.state.value.insert), words[misread]) })
            tap("back_to_readback")
            on(activity, Screen.ReadbackEntry)
            typeLetters(activity, Screen.ReadbackEntry, words[misread].take(4)) { it.readbackLetters }
            tap("letters_done")
            await("the match", 10) { onMain { activity.model.state.value.matched } }
            assertTrue("the match does not show the insert's word", onMain { sameWord(checkNotNull(activity.model.state.value.insert), words[misread]) })
            find("readback_next")
            tap("readback_next")
            for (index in misread + 1 until words.size) readBack(activity, words, index)
            on(activity, Screen.ReadbackDone)
            tap("show_summary")
            on(activity, Screen.Wallet)
            val summary = onMain { checkNotNull(activity.model.state.value.summary) }
            val core = Core.summary()
            assertTrue("the summary is not core's", core is Reply.Done && core.value.firstAddress == summary.firstAddress)
            awaitText("fingerprint", fingerprintHex(summary.fingerprint))
            awaitText("first_address", summary.firstAddress)
            tap("summary_next")
            on(activity, Screen.BackupOffer)
            tap("skip_backup")
            on(activity, Screen.WatchOffer)
            tap("skip_watch_only")
            on(activity, Screen.RegisterOffer)
            tap("show_registration")
            find("privacy_gate")
            tap("pass_gate")
            await("past the registration QR's gate", 10) { onMain { activity.model.state.value.let { it.screen == Screen.RegisterQr && !it.gate } } }
            val registration = onMain { activity.model.state.value.registration } ?: throw AssertionError("no registration QR")
            assertTrue(
                "the registration QR is not dice-50-words12's register text (neither is printed)",
                Checker.read(registration) == Checker.ORIGIN + "/register#c=" + DICE_50_SEAL_CODE,
            )
            tap("registration_done")
            on(activity, Screen.Checklist)
            assertTrue("the registration QR was not wiped as the checklist came", blank(registration))
            assertTrue("the checklist does not show its first item", shown(Screen.Checklist, CHECKLIST[0]))
            assertFalse("a 12-word seed's checklist names two devices", device.hasObject(By.res("two_devices")))
            tap("finish")
            on(activity, Screen.Home)
            assertTrue("the slot is not at home: Finish did not end the session", Core.selfTest() is Reply.Done)
            pass(
                "dice-50-words12's words: the gate with the SeedBook rules, 12 insert pages equal to the vector's words " +
                    "(in-process), Back and the overview's three pages; the letter pad's 26 keys with the button role alone " +
                    "and the dice pad's six labelled (M5-46); an e/i misread named a mirror misread on its face, the " +
                    "insert reviewed and read again on the pad; 12 inserts read back, the summary, the registration QR " +
                    "(its seal code kcr.json's) and no D offer for a dice-only seed, the checklist, Finish: Home with the slot empty",
            )
            finish(activity)
        }
    }

    /**
     * A 24-word seed's pages (swb, "24-word seeds"), vectors/kcr.json's dice-99-words24, its check skipped:
     * words 1-12 marked device 1 of 2 and words 13-24 device 2 of 2 (each the vector's word, read
     * in-process), the device swap (Public) between them with the privacy gate again after it, none
     * paging back, the overview's swap too; the read-back names each insert's device, and the checklist
     * says which device holds words 1-12; Finish: Home.
     */
    @Test
    fun aTwentyFourWordSeedsPagesAreMarkedForTwoDevicesWithTheSwapBetween() {
        Capture.whileOffline {
            val activity = toHome()
            toWords(activity, "words_24", 99, DICE_99_ROLLS, "99 / 99 rolls, 255.9 bits")
            val words = DICE_99_24_WORDS
            for (index in words.indices) {
                assertInsert(activity, words, index, if (index < INSERTS_PER_DEVICE) 1 else 2, 2)
                if (index + 1 == INSERTS_PER_DEVICE) {
                    tap("next")
                    on(activity, Screen.DeviceSwap)
                    awaitText("device_swap_text", "Words 13-24 go on device 2 of 2.")
                    tap("continue")
                    find("privacy_gate")
                    tap("pass_gate")
                } else if (index + 1 < words.size) {
                    onMain { activity.model.nextPage() }
                }
            }
            onMain { repeat(words.size - INSERTS_PER_DEVICE - 1) { activity.model.previousPage() } }
            assertInsert(activity, words, INSERTS_PER_DEVICE, 2, 2)
            tap("previous")
            assertInsert(activity, words, INSERTS_PER_DEVICE - 1, 1, 2)
            tap("overview")
            assertOverview(activity, words, 2, 1, 2)
            tap("next")
            on(activity, Screen.DeviceSwap)
            tap("continue")
            find("privacy_gate")
            tap("pass_gate")
            assertOverview(activity, words, 3, 2, 2)
            tap("insert_view")
            assertInsert(activity, words, INSERTS_PER_DEVICE, 2, 2)
            onMain { repeat(words.size - INSERTS_PER_DEVICE - 1) { activity.model.nextPage() } }
            assertInsert(activity, words, words.size - 1, 2, 2)
            tap("start_readback")
            on(activity, Screen.ReadbackEntry)
            for (index in words.indices) {
                awaitText("readback_header", "Read back insert " + two(index + 1) + DOT + "device " + (if (index < INSERTS_PER_DEVICE) 1 else 2) + " of 2")
                readBack(activity, words, index)
            }
            on(activity, Screen.ReadbackDone)
            tap("show_summary")
            on(activity, Screen.Wallet)
            tap("summary_next")
            on(activity, Screen.BackupOffer)
            tap("skip_backup")
            on(activity, Screen.WatchOffer)
            tap("skip_watch_only")
            on(activity, Screen.RegisterOffer)
            tap("skip_registration")
            on(activity, Screen.Checklist)
            assertTrue("the checklist does not say which device holds words 1-12", shown(Screen.Checklist, TWO_DEVICES))
            tap("finish")
            on(activity, Screen.Home)
            assertTrue("the slot is not at home: Finish did not end the session", Core.selfTest() is Reply.Done)
            pass(
                "dice-99-words24's words: 1-12 on device 1 of 2 and 13-24 on device 2 of 2 (in-process), the device swap " +
                    "and the gate again before word 13, none paging back, the overview's swap; the read-back names each " +
                    "insert's device, the checklist which device holds words 1-12; Finish: Home",
            )
            finish(activity)
        }
    }

    /**
     * The exports (group 18; docs/mobile-apps.md, steps 14-16; docs/seal-watchonly-braille.md, "Watch-only
     * export" and "Registering a new seal") of a new seed, 12 words, mixed with the phone's D: its start
     * tapped to the dice, C read from the commitment screen (public), 50 rolls, Done, then Skip, the words and
     * their read-back through the model's entry points (each insert read from the page the state holds, its
     * copy wiped at once), the summary, the backup's offer skipped; the watch-only offer, the BIP39 question
     * and "I use a passphrase": its entry behind the privacy gate, the ASCII pad's three pages of keys each
     * with its button role alone (lead decision M5-46) and no node naming a key, paged by Next keys and
     * Previous keys, the passphrase typed into the model's PadEntry, as the pad types it (no passphrase goes
     * into a selector or a click's point, lead decision M5-68 (e)), the keys paged on and back so a frame
     * comes before Delete's state is read, Delete taking a character back, and Done: the summary says it is that passphrase's wallet, another fingerprint than the
     * wallet summary's; the account QR behind the gate and the descriptor QR, each read in-process equal to
     * core's own (Core.watchOnly with the same passphrase), the account a crypto-account UR and the
     * descriptors two lines under the summary's fingerprint, Back between them, Done wiping them; the
     * registration QR behind the gate, core's, a register text with a 26-symbol seal code; D's offer (Mixed
     * mode) with its warning, D behind the gate, drawn by a secret node, whose SHA-256 under "KCE/v1/commit"
     * is the C the commitment screen showed; Next wiping it, the checklist and Finish: Home. Every export's
     * text is compared in-process only and never printed.
     */
    @Test
    fun aNewSeedsExportsTheWatchOnlyQrsOfAPassphrasesWalletTheRegistrationAndD() {
        Capture.whileOffline {
            val activity = toHome()
            tap("new_seed")
            on(activity, Screen.Length)
            tap("words_12")
            on(activity, Screen.DeviceEntropy, START_SECONDS)
            tap("continue")
            on(activity, Screen.Commitment)
            val c = onMain { activity.model.state.value.commitment } ?: throw AssertionError("no C on the commitment screen")
            tap("continue")
            on(activity, Screen.Dice)
            roll(activity, 50, DICE_50_ROLLS)
            awaitText("dice_count", "50 / 50 rolls, 129.2 bits")
            tap("dice_done")
            on(activity, Screen.CheckPrompt, START_SECONDS)
            onMain {
                val model = activity.model
                model.skip()
                model.skipConfirmed()
                model.showWords()
                model.passGate()
                repeat(INSERTS_PER_DEVICE - 1) { model.nextPage() }
                model.startReadback()
                repeat(INSERTS_PER_DEVICE) {
                    val word = checkNotNull(model.state.value.insert).word()
                    for (index in 0 until minOf(4, word.size)) model.readbackLetters.type(Char(word[index].toInt()))
                    word.wipe()
                    model.readbackTyped()
                    model.readbackNext()
                }
                model.showSummary()
            }
            on(activity, Screen.Wallet)
            val wallet = onMain { checkNotNull(activity.model.state.value.summary) }
            tap("summary_next")
            on(activity, Screen.BackupOffer)
            tap("skip_backup")
            on(activity, Screen.WatchOffer)
            tap("show_watch_only")
            on(activity, Screen.Bip39Ask)
            tap("with_bip39_passphrase")
            find("privacy_gate")
            tap("pass_gate")
            await("past the BIP39 entry's gate", 10) { onMain { activity.model.state.value.let { it.screen == Screen.Bip39Entry && !it.gate } } }
            on(activity, Screen.Bip39Entry)
            for (page in 0 until ASCII_PAGES) {
                awaitText("keys_page", "Keys, page " + (page + 1) + " of " + ASCII_PAGES)
                asciiKeys(asciiPage(page).length)
                if (page + 1 < ASCII_PAGES) tap("keys_next")
            }
            assertFalse("Next keys on the last page", enabled("keys_next"))
            repeat(ASCII_PAGES - 1) { tap("keys_previous") }
            awaitText("keys_page", "Keys, page 1 of " + ASCII_PAGES)
            assertFalse("Done with nothing typed", enabled("bip39_done"))
            val typed = onMain {
                val letters = activity.model.bip39Letters
                for (key in PASSPHRASE + "!") letters.type(key)
                letters.length
            }
            assertEquals(PASSPHRASE.length + 1, typed)
            // Typed in-process: the entry's length is snapshot state (U3f), so it redraws at the next frame; a page of keys
            // on and back (each tap waits for the UI) lets that frame come before Delete's state is read.
            tap("keys_next")
            tap("keys_previous")
            assertTrue("Delete is not enabled with the passphrase typed", enabled("bip39_delete"))
            tap("bip39_delete")
            val held = onMain {
                val letters = activity.model.bip39Letters
                letters.length == PASSPHRASE.length && PASSPHRASE.indices.all { letters.keyAt(it) == PASSPHRASE[it] }
            }
            assertTrue("Delete did not take the last character back (none is printed)", held)
            tap("bip39_done")
            on(activity, Screen.WatchSummary)
            assertEquals(0, onMain { activity.model.bip39Letters.length })
            awaitText("passphrase_wallet", PASSPHRASE_WALLET)
            val watch = onMain { activity.model.state.value.watch } ?: throw AssertionError("no watch-only export")
            assertTrue("the export is not the passphrase's wallet", watch.passphraseUsed)
            assertFalse("the passphrase's wallet has the seed's own fingerprint", watch.summary.fingerprint.contentEquals(wallet.fingerprint))
            val fingerprint = fingerprintHex(watch.summary.fingerprint)
            awaitText("watch_fingerprint", fingerprint)
            awaitText("watch_first_address", watch.summary.firstAddress)
            val core = when (val made = Core.watchOnly(Secret(PASSPHRASE.encodeToByteArray()))) {
                is Reply.Done -> made.value
                is Reply.Refused, Reply.Discarded -> throw AssertionError("core made no export of the passphrase's wallet")
            }
            tap("watch_summary_next")
            find("privacy_gate")
            tap("pass_gate")
            await("past the account QR's gate", 10) { onMain { activity.model.state.value.let { it.screen == Screen.WatchAccountQr && !it.gate } } }
            on(activity, Screen.WatchAccountQr)
            val account = Checker.read(watch.account)
            assertTrue("the account QR drawn is not core's (neither is printed)", account == Checker.read(core.account))
            assertTrue("the account QR is not a crypto-account UR (it is not printed)", account.startsWith("UR:CRYPTO-ACCOUNT/"))
            tap("watch_next")
            on(activity, Screen.WatchDescriptorQr)
            val descriptors = Checker.read(watch.descriptors)
            assertTrue("the descriptor QR drawn is not core's (neither is printed)", descriptors == Checker.read(core.descriptors))
            val lines = descriptors.split("\n")
            val origin = "wpkh([" + fingerprint + "/84h/0h/0h]xpub"
            assertTrue(
                "the descriptor QR is not the receive and change descriptors under the summary's fingerprint (it is not printed)",
                lines.size == 2 && lines.all { it.startsWith(origin) } && lines[0].contains("/0/*)#") && lines[1].contains("/1/*)#"),
            )
            core.wipe()
            device.pressBack()
            on(activity, Screen.WatchAccountQr)
            tap("watch_next")
            on(activity, Screen.WatchDescriptorQr)
            tap("watch_done")
            on(activity, Screen.RegisterOffer)
            assertTrue("the export's QRs were not wiped as the registration's offer came", blank(watch.account) && blank(watch.descriptors))
            tap("show_registration")
            find("privacy_gate")
            tap("pass_gate")
            await("past the registration QR's gate", 10) { onMain { activity.model.state.value.let { it.screen == Screen.RegisterQr && !it.gate } } }
            val registration = onMain { activity.model.state.value.registration } ?: throw AssertionError("no registration QR")
            val text = Checker.read(registration)
            val ours = when (val made = Core.registration()) {
                is Reply.Done -> made.value
                is Reply.Refused, Reply.Discarded -> throw AssertionError("core made no registration QR")
            }
            assertTrue("the registration QR drawn is not core's (neither is printed)", text == Checker.read(ours))
            ours.wipe()
            assertTrue("the registration QR is not a register text with a seal code (it is not printed)", REGISTER.matches(text))
            tap("registration_done")
            on(activity, Screen.RevealDOffer)
            awaitText("reveal_d_warning", REVEAL_D)
            tap("show_d")
            find("privacy_gate")
            tap("pass_gate")
            await("past D's gate", 10) { onMain { activity.model.state.value.let { it.screen == Screen.RevealD && !it.gate } } }
            on(activity, Screen.RevealD)
            val (shownD, commits) = onMain {
                val leg = checkNotNull(activity.model.state.value.deviceLeg)
                val digest = MessageDigest.getInstance("SHA-256")
                digest.update("KCE/v1/commit".toByteArray(Charsets.US_ASCII))
                val d = ByteArray(leg.size) { leg[it] }
                digest.update(d)
                d.fill(0)
                Pair(deviceLegText(leg), hexGroups(digest.digest()) == c)
            }
            assertTrue("D is not drawn by a secret node (it is not printed)", drawsSecret(shownD))
            assertTrue("SHA-256(\"KCE/v1/commit\" || D) is not the C the commitment screen showed (neither is printed)", commits)
            val leg = onMain { checkNotNull(activity.model.state.value.deviceLeg) }
            tap("d_done")
            on(activity, Screen.Checklist)
            assertTrue("D was not wiped as the checklist came", (0 until leg.size).all { leg[it] == 0.toByte() })
            tap("finish")
            on(activity, Screen.Home)
            assertTrue("the slot is not at home: Finish did not end the session", Core.selfTest() is Reply.Done)
            pass(
                "a new seed's exports: the BIP39 passphrase's entry behind the gate, the ASCII pad's three pages of keys with " +
                    "their role alone, Delete; its wallet's summary (another fingerprint); the account QR (a crypto-account " +
                    "UR) and the descriptor QR (two descriptors under its fingerprint) equal to core's, in-process, then " +
                    "wiped; the registration QR, core's; D behind the gate, SHA-256 under KCE/v1/commit equal to C; the " +
                    "checklist, Finish: Home",
            )
            finish(activity)
        }
    }

    /**
     * Home's About (docs/mobile-apps.md, step 4): the version, the package's own versionName, this build's
     * flavour (the shipping app) and the source address, a plain text no tap opens; the system Back and its
     * Back button each return Home.
     */
    @Test
    fun homesAboutShowsTheVersionTheFlavourAndTheSourceAsPlainTextAndBackReturnsHome() {
        Capture.whileOffline {
            val activity = toHome()
            tap("show_about")
            on(activity, Screen.About)
            val context = Capture.instrumentation.targetContext
            val version = context.packageManager.getPackageInfo(context.packageName, 0).versionName
            awaitText("about_version", "Version " + version)
            assertEquals("About's version is not the package's", APP_VERSION, version)
            awaitText("about_flavour", flavourText(false))
            awaitText("about_source", SOURCE_ADDRESS)
            assertFalse("the source address is a link", read("about_source") { it.isClickable })
            device.pressBack()
            on(activity, Screen.Home)
            tap("show_about")
            on(activity, Screen.About)
            tap("back")
            on(activity, Screen.Home)
            pass("About: version $version, the shipping app's flavour, the source address as plain text; Back and the system Back: Home")
            finish(activity)
        }
    }

    /**
     * The ASCII pad's keys on the BIP39 passphrase's entry (lead decision M5-46: a Protected pad): the
     * screen's nodes with the button role and no text, description or resource id, which must be count, the
     * page's keys; and no node there has a text of one character or a Public key's id (key_ and a key), so
     * nothing names a key. Read again when a redraw replaced a node read (fresh).
     */
    private fun asciiKeys(count: Int) = fresh("the ASCII pad's keys") {
        device.waitForIdle()
        val root = find(screenId(Screen.Bip39Entry))
        val keys = root.findObjects(By.clazz(BUTTON)).filter {
            it.text.isNullOrEmpty() && it.contentDescription.isNullOrEmpty() && it.resourceName.isNullOrEmpty()
        }
        assertEquals("the ASCII pad's keys on its page, each with its button role alone", count, keys.size)
        assertFalse("a node on the BIP39 entry names a key", root.hasObject(By.text(Pattern.compile("."))))
        assertFalse("a key on the BIP39 entry has a Public key's id", root.hasObject(By.res(Pattern.compile("key_.*"))))
    }

    /** Whether a QR code's matrix was wiped: no dark module left. */
    private fun blank(matrix: QrMatrix): Boolean = (0 until matrix.side).all { y -> (0 until matrix.side).none { x -> matrix.isDark(x, y) } }

    private companion object {
        /** vectors/kcr.json's dice-50-words12: 123456 repeated. */
        const val DICE_50_ROLLS = "123456"

        /** vectors/kcr.json's dice-50-words12's seal code, as its registration text carries it (a public gate-seed vector). */
        const val DICE_50_SEAL_CODE = "B98KT954NNYSS6APNPZWCYY0VA"

        /** A BIP39 passphrase of watchonly.json's (abandon-trezor's), typed in-process and never printed or put in a selector. */
        const val PASSPHRASE = "TREZOR"

        /** The registration QR's text: the registry's register page and 26 Crockford symbols, the seal code. */
        val REGISTER = Regex("^" + Regex.escape(Checker.ORIGIN) + "/register#c=[0-9A-HJKMNP-TV-Z]{26}$")

        /** vectors/kcr.json's dice-99-words12 and dice-99-words24: 654321 repeated. */
        const val DICE_99_ROLLS = "654321"

        /**
         * vectors/kcr.json's dice-50-words12's and dice-99-words24's words (their mnemonic fields), public
         * gate-seed vectors the in-process checks compare each page with; no test prints or logs them.
         */
        val DICE_50_WORDS = listOf(
            "unveil", "nice", "picture", "region", "tragic", "fault", "cream", "strike", "tourist", "control",
            "recipe", "tourist",
        )
        val DICE_99_24_WORDS = listOf(
            "various", "tape", "mercy", "east", "hair", "tragic", "arrest", "together", "day", "tag", "afford",
            "obvious", "devote", "violin", "coil", "conduct", "salmon", "kidney", "anchor", "monkey", "cruel", "truth",
            "dash", "smart",
        )

        /** C as the commitment screen shows it: four rows of four groups of four lower-case hex digits. */
        val HEX_GROUPS = Regex("^[0-9a-f]{4}( [0-9a-f]{4}){3}(\n[0-9a-f]{4}( [0-9a-f]{4}){3}){3}$")
    }
}
