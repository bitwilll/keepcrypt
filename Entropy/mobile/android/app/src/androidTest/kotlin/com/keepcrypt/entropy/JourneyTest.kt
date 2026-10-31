package com.keepcrypt.entropy

import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.GateSeeds.DICE_50_ROLLS
import com.keepcrypt.entropy.GateSeeds.DICE_50_SEAL_CODE
import com.keepcrypt.entropy.GateSeeds.DICE_50_SEAL_ID
import com.keepcrypt.entropy.GateSeeds.DICE_50_WORDS
import com.keepcrypt.entropy.GateSeeds.DICE_99_24_SEAL_CODE
import com.keepcrypt.entropy.GateSeeds.DICE_99_24_WORDS
import com.keepcrypt.entropy.GateSeeds.DICE_99_ROLLS
import com.keepcrypt.entropy.GateSeeds.DICE_99_SEAL_CODE
import com.keepcrypt.entropy.GateSeeds.DICE_99_SEAL_ID
import com.keepcrypt.entropy.GateSeeds.DICE_99_TAG
import com.keepcrypt.entropy.GateSeeds.DICE_99_WORDS
import com.keepcrypt.entropy.Journeys.checklistToFinish
import com.keepcrypt.entropy.Journeys.registration
import com.keepcrypt.entropy.Journeys.since
import com.keepcrypt.entropy.Journeys.summaryToBackupOffer
import com.keepcrypt.entropy.Journeys.summaryToWatchOffer
import com.keepcrypt.entropy.Journeys.wordsAndReadBack
import com.keepcrypt.entropy.Journeys.wordsToFinish
import com.keepcrypt.entropy.Ui.START_SECONDS
import com.keepcrypt.entropy.Ui.assertInsert
import com.keepcrypt.entropy.Ui.await
import com.keepcrypt.entropy.Ui.awaitText
import com.keepcrypt.entropy.Ui.device
import com.keepcrypt.entropy.Ui.enabled
import com.keepcrypt.entropy.Ui.find
import com.keepcrypt.entropy.Ui.grantCamera
import com.keepcrypt.entropy.Ui.on
import com.keepcrypt.entropy.Ui.shown
import com.keepcrypt.entropy.Ui.stays
import com.keepcrypt.entropy.Ui.tap
import com.keepcrypt.entropy.Ui.tapCode
import com.keepcrypt.entropy.Ui.tapRolls
import com.keepcrypt.entropy.Ui.text
import com.keepcrypt.entropy.Ui.toHome
import com.keepcrypt.entropy.Ui.typeAscii
import com.keepcrypt.entropy.Ui.typeLetters
import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Refusal
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Secret
import com.keepcrypt.entropy.screens.COLLISION_FOUND
import com.keepcrypt.entropy.screens.PASSPHRASE_WORDS
import com.keepcrypt.entropy.screens.PASSPHRASE_WALLET
import com.keepcrypt.entropy.screens.REVEAL_D
import com.keepcrypt.entropy.screens.SAFE_IF_EITHER
import com.keepcrypt.entropy.screens.SCAN_MISSING
import com.keepcrypt.entropy.screens.SCAN_NO_REGISTRY_KEY
import com.keepcrypt.entropy.screens.SKIPPED
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.screens.fingerprintHex
import com.keepcrypt.entropy.screens.hexGroups
import java.nio.CharBuffer
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * U1's journeys from First launch to Finish through the UI alone (tasks/todo.md, Stage U's U1 and its
 * commit plan's U-4; lead decision M5-72 (a)), run by scripts/android-instrument.sh on the shipping app in
 * the API 31 and 36 ui jobs (android-emulator.sh's ui part, M5-76 (g)). Every input is the user's, made on the screen: UI Automator taps the
 * Public controls by their resource ids, the dice faces are pressed on the Public pad by their
 * accessibility click and confirmed by tap (Ui.tapRolls), the go-ahead code is tapped on the Crockford pad
 * (Ui.tapCode) and the read-back's letters are touched on the Protected letter pad (Ui.typeLetters), so
 * no model call stands in for a press. State is read in-process only to observe it: the check QR the seal
 * card drew (Checker; captures of the app are black), the collision report and registration QRs, and each
 * insert's word, compared with the vector and never printed. Every seed is a vectors/kcr.json gate seed's,
 * its rolls those of the vector. Each journey's pass line names its path and the time each part took,
 * which sizes the journeys jobs' budget (M5-30) and the rest of U-4's plan.
 */
@RunWith(AndroidJUnit4::class)
class JourneyTest {
    /**
     * Match found to Add fresh entropy, then the new seed to Finish (Stage U's U1b; the Pi's step 7,
     * docs/pi-firmware.md:93, and swb's Stop): a dice-only seed of dice-50-words12 by its 50 rolls tapped,
     * Check now's seal card with its Seal ID, the check QR's Match found and its confirm, the collision
     * result with the destroyed seed's Seal ID drawn, the report behind the privacy gate (its QR
     * dice-50-words12's register text), and Add fresh entropy, whose dice need 99 rolls; dice-99-words12's
     * 99 rolls tapped, Check now's seal card with its Seal ID, the go-ahead code a checker builds from the
     * drawn check QR's T and nonce tapped on the pad, the check passed, Show words through the gate, the 12
     * inserts by Next (each the vector's word with its position), the read-back of every insert's first
     * four letters touched on the letter pad, each a match, the summary (core's), the backup's and
     * watch-only's Skip, the registration QR behind its gate (dice-99-words12's register text), the
     * checklist and Finish: Home, with the slot empty.
     */
    @Test
    fun matchFoundRestartsAt99RollsAndTheNewSeedReachesFinishThroughTheUiAlone() {
        Capture.whileOffline {
            val journey = SystemClock.elapsedRealtime()
            val activity = toHome()
            tap("dice_only_seed")
            on(activity, Screen.Length)
            tap("words_12")
            on(activity, Screen.Dice, START_SECONDS)
            val first = SystemClock.elapsedRealtime()
            tapRolls(activity, 50, DICE_50_ROLLS)
            val firstRolls = since(first)
            awaitText("dice_count", "50 / 50 rolls, 129.2 bits")
            tap("dice_done")
            on(activity, Screen.CheckPrompt, START_SECONDS)
            tap("check_now")
            on(activity, Screen.SealCard)
            assertTrue("the seal card does not draw dice-50-words12's Seal ID", shown(Screen.SealCard, DICE_50_SEAL_ID))
            tap("show_check_qr")
            on(activity, Screen.CheckQr)
            tap("match_found")
            on(activity, Screen.MatchFoundConfirm)
            tap("confirm_action")
            on(activity, Screen.Collision)
            awaitText("collision_text", COLLISION_FOUND)
            assertTrue("the collision result does not draw the destroyed seed's Seal ID", shown(Screen.Collision, DICE_50_SEAL_ID))
            tap("show_report")
            find("privacy_gate")
            assertTrue("the report showed before the privacy gate", onMain { activity.model.state.value.gate })
            tap("pass_gate")
            await("past the report's gate", 10) { !onMain { activity.model.state.value.gate } }
            on(activity, Screen.CollisionReport)
            val report = onMain { activity.model.state.value.report } ?: throw AssertionError("no collision-report QR")
            assertTrue(
                "the collision-report QR is not dice-50-words12's register text (neither is printed)",
                Checker.read(report) == Checker.ORIGIN + "/register#c=" + DICE_50_SEAL_CODE,
            )
            tap("add_fresh_entropy")
            on(activity, Screen.Dice, START_SECONDS)
            awaitText("dice_count", "0 / 99 rolls, 0.0 bits")
            val second = SystemClock.elapsedRealtime()
            tapRolls(activity, 98, DICE_99_ROLLS)
            assertFalse("Done one roll below the 99 after a collision", enabled("dice_done"))
            tapRolls(activity, 1, DICE_99_ROLLS[98 % DICE_99_ROLLS.length].toString())
            val secondRolls = since(second)
            awaitText("dice_count", "99 / 99 rolls, 255.9 bits")
            tap("dice_done")
            on(activity, Screen.CheckPrompt, START_SECONDS)
            tap("check_now")
            on(activity, Screen.SealCard)
            assertTrue("the seal card does not draw dice-99-words12's Seal ID", shown(Screen.SealCard, DICE_99_SEAL_ID))
            val request = onMain { activity.model.state.value.checkRequest } ?: throw AssertionError("the seal card has no check QR")
            val (tag, nonce) = Checker.request(Checker.read(request))
            assertEquals("the check QR's T is not dice-99-words12's seal tag", DICE_99_TAG, tag)
            tap("show_check_qr")
            on(activity, Screen.CheckQr)
            tap("type_code")
            on(activity, Screen.CodeEntry)
            tapCode(Checker.goAhead(tag, nonce))
            tap("code_done")
            on(activity, Screen.CheckResult, START_SECONDS)
            awaitText("check_result_text", "No collision for seal $DICE_99_SEAL_ID, as of the date your checker showed.")
            val (readback, _) = wordsToFinish(activity, DICE_99_WORDS, DICE_99_SEAL_CODE)
            pass(
                "the Match found journey through the UI alone: dice-50-words12's 50 rolls tapped ($firstRolls), its seal card " +
                    "($DICE_50_SEAL_ID), Match found confirmed, the collision with its Seal ID, the report QR behind the gate " +
                    "(its register text), Add fresh entropy at 0 / 99, Done disabled at 98; dice-99-words12's 99 rolls tapped " +
                    "($secondRolls), its seal card ($DICE_99_SEAL_ID), the drawn check QR's code tapped: the check passed; the " +
                    "gate, 12 inserts by Next equal to the vector's words, 12 read back by touches on the letter pad " +
                    "($readback), the summary, the registration QR (its register text), the checklist, Finish: Home with " +
                    "the slot empty; the journey " + since(journey),
            )
            finish(activity)
        }
    }

    /**
     * A dice-only seed of 24 words to Finish with its check skipped (Stage U's U1c; swb's "24-word seeds"):
     * dice-99-words24's 99 rolls tapped (Done disabled at 98), Skip and its confirm, the result saying the
     * check was skipped, then the 24 words on two devices with the swap and its second gate between them,
     * all 24 read back by touches with each insert's device named, the summary, the registration QR
     * (dice-99-words24's register text), the checklist saying which device holds words 1-12, and Finish.
     */
    @Test
    fun aDiceOnlyTwentyFourWordSeedSkipsItsCheckAndReachesFinishOnTwoDevicesThroughTheUiAlone() {
        Capture.whileOffline {
            val journey = SystemClock.elapsedRealtime()
            val activity = toHome()
            tap("dice_only_seed")
            on(activity, Screen.Length)
            tap("words_24")
            on(activity, Screen.Dice, START_SECONDS)
            awaitText("dice_count", "0 / 99 rolls, 0.0 bits")
            val rolls = SystemClock.elapsedRealtime()
            tapRolls(activity, 98, DICE_99_ROLLS)
            assertFalse("Done one roll below a 24-word seed's 99", enabled("dice_done"))
            tapRolls(activity, 1, DICE_99_ROLLS[98 % DICE_99_ROLLS.length].toString())
            val rollTime = since(rolls)
            awaitText("dice_count", "99 / 99 rolls, 255.9 bits")
            tap("dice_done")
            on(activity, Screen.CheckPrompt, START_SECONDS)
            tap("skip")
            on(activity, Screen.SkipConfirm)
            tap("confirm_action")
            on(activity, Screen.CheckResult)
            awaitText("check_result_text", SKIPPED)
            val (readback, rest) = wordsToFinish(activity, DICE_99_24_WORDS, DICE_99_24_SEAL_CODE)
            pass(
                "the dice-only 24-word journey through the UI alone: dice-99-words24's 99 rolls tapped ($rollTime), Done " +
                    "disabled at 98, Skip confirmed; the gate, 24 inserts by Next equal to the vector's words with the device " +
                    "swap and its gate after insert 12, 24 read back by touches with each insert's device ($readback), the " +
                    "summary, the registration QR (its register text), the checklist naming two devices, Finish: Home with " +
                    "the slot empty ($rest from Show words); the journey " + since(journey),
            )
            finish(activity)
        }
    }

    /**
     * A new seed of 12 words, mixed with the phone's D, checked by its go-ahead code and taken through every
     * export to Finish (Stage U's U1d; docs/mobile-apps.md, steps 5-16): the device entropy screen's
     * sentence and three touches on it, the commitment's C read from the screen, 50 tapped rolls of
     * dice-50-words12's faces, Check now's seal card and check QR; the check QR's Scan go-ahead QR with
     * CAMERA granted, where the emulator has no camera, and a scanned go-ahead QR (kcr.json's
     * clear-empty-bucket, fed to onGoAheadText as the scanner would, M5-72 (a)) refused, since the shipping
     * app trusts no registry key, the check and its nonce kept; Back, and the code a checker builds from the
     * drawn check QR tapped on the pad: the check passed; the words (no vector's, read in-process) and the
     * read-back of all 12 by touches; the summary; the watch-only offer with a BIP39 passphrase (watchonly.json's
     * TREZOR) touched on the ASCII pad, its wallet's summary another fingerprint, its account and descriptor
     * QRs equal to core's; the registration QR, core's; Reveal D behind its gate, SHA-256 under KCE/v1/commit
     * equal to the C the screen showed; the checklist and Finish: Home with the slot empty.
     */
    @Test
    fun aMixedTwelveWordSeedIsCheckedByItsCodeAndTakenThroughEveryExportToFinishThroughTheUiAlone() {
        Capture.whileOffline {
            grantCamera()
            val journey = SystemClock.elapsedRealtime()
            val activity = toHome()
            tap("new_seed")
            on(activity, Screen.Length)
            tap("words_12")
            on(activity, Screen.DeviceEntropy, START_SECONDS)
            assertEquals(SAFE_IF_EITHER, text("device_entropy_sentence"))
            repeat(3) { tap("device_entropy_sentence") }
            tap("continue")
            on(activity, Screen.Commitment)
            val c = text("commitment_hex")
            tap("continue")
            on(activity, Screen.Dice)
            awaitText("dice_count", "0 / 50 rolls, 0.0 bits")
            val rolls = SystemClock.elapsedRealtime()
            tapRolls(activity, 50, DICE_50_ROLLS)
            val rollTime = since(rolls)
            awaitText("dice_count", "50 / 50 rolls, 129.2 bits")
            tap("dice_done")
            on(activity, Screen.CheckPrompt, START_SECONDS)
            tap("check_now")
            on(activity, Screen.SealCard)
            val drawn = Checker.read(onMain { activity.model.state.value.checkRequest } ?: throw AssertionError("the seal card has no check QR"))
            val (tag, nonce) = Checker.request(drawn)
            tap("show_check_qr")
            on(activity, Screen.CheckQr)
            tap("scan_qr")
            on(activity, Screen.Scan)
            awaitText("scan_line", SCAN_MISSING)
            onMain { activity.model.onGoAheadText(Checker.CLEAR_EMPTY_BUCKET_UR.uppercase()) }
            await("the scanned go-ahead QR refused", START_SECONDS) {
                onMain { activity.model.state.value.let { it.screen == Screen.Scan && it.scanRefusal == Refusal.NoRegistryKey } }
            }
            awaitText("scan_line", SCAN_NO_REGISTRY_KEY)
            assertEquals(
                "the refused scan changed the check request",
                drawn,
                Checker.read(onMain { activity.model.state.value.checkRequest } ?: throw AssertionError("the check request is gone")),
            )
            device.pressBack()
            on(activity, Screen.CheckQr)
            tap("type_code")
            on(activity, Screen.CodeEntry)
            tapCode(Checker.goAhead(tag, nonce))
            tap("code_done")
            on(activity, Screen.CheckResult, START_SECONDS)
            assertTrue("the check did not pass", text("check_result_text").startsWith("No collision for seal "))
            val readback = wordsAndReadBack(activity, null, 12)
            val wallet = summaryToWatchOffer(activity)
            tap("show_watch_only")
            on(activity, Screen.Bip39Ask)
            tap("with_bip39_passphrase")
            find("privacy_gate")
            tap("pass_gate")
            await("past the BIP39 entry's gate", 10) { onMain { activity.model.state.value.let { it.screen == Screen.Bip39Entry && !it.gate } } }
            on(activity, Screen.Bip39Entry)
            typeAscii(activity, PASSPHRASE)
            tap("bip39_done")
            on(activity, Screen.WatchSummary)
            assertEquals("the BIP39 entry was not emptied", 0, onMain { activity.model.bip39Letters.length })
            awaitText("passphrase_wallet", PASSPHRASE_WALLET)
            val watch = onMain { activity.model.state.value.watch } ?: throw AssertionError("no watch-only export")
            assertTrue("the export is not the passphrase's wallet", watch.passphraseUsed)
            assertFalse("the passphrase's wallet has the seed's own fingerprint", watch.summary.fingerprint.contentEquals(wallet.fingerprint))
            val core = when (val made = Core.watchOnly(Secret(PASSPHRASE.encodeToByteArray()))) {
                is Reply.Done -> made.value
                is Reply.Refused, Reply.Discarded -> throw AssertionError("core made no export of the passphrase's wallet")
            }
            tap("watch_summary_next")
            find("privacy_gate")
            tap("pass_gate")
            await("past the account QR's gate", 10) { onMain { activity.model.state.value.let { it.screen == Screen.WatchAccountQr && !it.gate } } }
            assertTrue("the account QR drawn is not core's (neither is printed)", Checker.read(watch.account) == Checker.read(core.account))
            tap("watch_next")
            on(activity, Screen.WatchDescriptorQr)
            assertTrue("the descriptor QR drawn is not core's (neither is printed)", Checker.read(watch.descriptors) == Checker.read(core.descriptors))
            core.wipe()
            tap("watch_done")
            on(activity, Screen.RegisterOffer)
            registration(activity, null)
            on(activity, Screen.RevealDOffer)
            awaitText("reveal_d_warning", REVEAL_D)
            tap("show_d")
            find("privacy_gate")
            tap("pass_gate")
            await("past D's gate", 10) { onMain { activity.model.state.value.let { it.screen == Screen.RevealD && !it.gate } } }
            val commits = onMain {
                val leg = checkNotNull(activity.model.state.value.deviceLeg)
                val digest = MessageDigest.getInstance("SHA-256")
                digest.update("KCE/v1/commit".toByteArray(Charsets.US_ASCII))
                val d = ByteArray(leg.size) { leg[it] }
                digest.update(d)
                d.fill(0)
                hexGroups(digest.digest()) == c
            }
            assertTrue("SHA-256(\"KCE/v1/commit\" || D) is not the C the commitment screen showed (neither is printed)", commits)
            tap("d_done")
            checklistToFinish(activity, 1)
            pass(
                "the mixed 12-word journey through the UI alone: Device entropy's sentence and touches, C from the screen, " +
                    "50 rolls tapped ($rollTime), the seal card and check QR; Scan go-ahead QR with no camera, a scanned " +
                    "go-ahead QR refused (no registry key) with the same check QR; the drawn check QR's code tapped: the " +
                    "check passed; the gate, 12 inserts by Next, 12 read back by touches ($readback); the summary; the " +
                    "watch-only export with a BIP39 passphrase touched on the ASCII pad (another fingerprint, its account " +
                    "and descriptor QRs core's); the registration QR, core's; D behind its gate, committing to C; the " +
                    "checklist, Finish: Home with the slot empty; the journey " + since(journey),
            )
            finish(activity)
        }
    }

    /**
     * The backup passphrase's page now on screen, read in-process from the state's Secret (Protected
     * screen; observed, never printed): its words, each its own array. Main thread only.
     */
    private fun passphrasePage(activity: MainActivity): List<ByteArray> {
        val text = checkNotNull(activity.model.state.value.passphrase)
        val words = ArrayList<ByteArray>()
        var start = 0
        for (at in 0..text.size) {
            if (at == text.size || text[at] == ' '.code.toByte()) {
                words.add(ByteArray(at - start) { text[start + it] })
                start = at + 1
            }
        }
        return words
    }

    /**
     * word's first four letters (a three-letter word's three) touched on screen's letter pad into the
     * backup's entry, through an array zeroed once typed (never a String, never printed).
     */
    private fun typeFirstLetters(activity: MainActivity, screen: Screen, word: ByteArray) {
        val letters = CharArray(minOf(4, word.size)) { Char(word[it].toInt()) }
        try {
            typeLetters(activity, screen, CharBuffer.wrap(letters)) { it.backupLetters }
        } finally {
            letters.fill('\u0000')
        }
    }

    /**
     * Cannot check to Start again, then the seed's encrypted backup made and checked through the UI alone
     * (Stage U's U1e; the Pi's step 7, docs/pi-firmware.md:93; docs/mobile-apps.md, steps 13 and 17): a
     * dice-only seed of dice-50-words12 by its 50 rolls tapped, Check now's check QR, Cannot check and its confirm's
     * Back, then its confirm: the seed wiped unseen and a new ceremony at once, its dice at 0 / 50 (no
     * collision, so not 99) with Back doing nothing there; dice-50-words12's 50 rolls tapped, Skip
     * confirmed, the 12 words (the vector's) and their read-back by touches, the summary; Make an
     * encrypted backup through its gate, the passphrase's two pages (read in-process, never printed) and
     * I wrote it down, the confirm's two words' first letters touched on the letter pad, the file saved
     * through the system's picker to Downloads under core's name, read back and verified; the rest skipped
     * to Finish; then Home's Check a backup picking that file, the passphrase's 8 words touched on the
     * letter pad behind the entry's gate, Backup OK with the summary's fingerprint and dice-50-words12's
     * Seal ID, the backup's 12 words through its gate by Next (the vector's), its Done and Done: Home with
     * the slot empty. The saved file is removed from Downloads at the end, so BackupTest saves under the
     * same name into an empty folder.
     */
    @Test
    fun cannotCheckStartsAgainAndTheNewSeedsBackupIsMadeAndCheckedThroughTheUiAlone() {
        Capture.whileOffline {
            val journey = SystemClock.elapsedRealtime()
            val activity = toHome()
            tap("dice_only_seed")
            on(activity, Screen.Length)
            tap("words_12")
            on(activity, Screen.Dice, START_SECONDS)
            tapRolls(activity, 50, DICE_50_ROLLS)
            awaitText("dice_count", "50 / 50 rolls, 129.2 bits")
            tap("dice_done")
            on(activity, Screen.CheckPrompt, START_SECONDS)
            tap("check_now")
            on(activity, Screen.SealCard)
            assertTrue("the seal card does not draw dice-50-words12's Seal ID", shown(Screen.SealCard, DICE_50_SEAL_ID))
            tap("show_check_qr")
            on(activity, Screen.CheckQr)
            tap("cannot_check")
            on(activity, Screen.CannotCheckConfirm)
            tap("back")
            on(activity, Screen.CheckQr)
            tap("cannot_check")
            on(activity, Screen.CannotCheckConfirm)
            tap("confirm_action")
            on(activity, Screen.Dice, START_SECONDS)
            awaitText("dice_count", "0 / 50 rolls, 0.0 bits")
            device.pressBack()
            stays(activity, Screen.Dice, "Back on the new ceremony's dice")
            tapRolls(activity, 50, DICE_50_ROLLS)
            awaitText("dice_count", "50 / 50 rolls, 129.2 bits")
            tap("dice_done")
            on(activity, Screen.CheckPrompt, START_SECONDS)
            tap("skip")
            on(activity, Screen.SkipConfirm)
            tap("confirm_action")
            on(activity, Screen.CheckResult)
            awaitText("check_result_text", SKIPPED)
            val readback = wordsAndReadBack(activity, DICE_50_WORDS, DICE_50_WORDS.size)
            val summary = summaryToBackupOffer(activity)
            val fingerprint = fingerprintHex(summary.fingerprint)
            tap("make_backup")
            find("privacy_gate")
            tap("pass_gate")
            await("past the passphrase's gate", 10) { onMain { activity.model.state.value.let { it.screen == Screen.BackupPassphrase && !it.gate } } }
            // The passphrase's words, read in-process (never printed), zeroed on every way out of the journey,
            // and the saved file removed the same way.
            val passphrase = ArrayList<ByteArray>()
            var name: String? = null
            var creator = ""
            try {
                passphrase.addAll(onMain { passphrasePage(activity) })
                tap("next")
                await("the passphrase's second page", 10) { onMain { activity.model.state.value.page } == 1 }
                passphrase.addAll(onMain { passphrasePage(activity) })
                assertEquals("eight passphrase words", PASSPHRASE_WORDS, passphrase.size)
                tap("passphrase_written")
                on(activity, Screen.BackupConfirm)
                for (question in 1..2) {
                    // The pad's keys carry the page they were drawn for, so each question is typed once the screen
                    // shows it, not only once the model holds it.
                    awaitText("confirm_question", "Check your copy: question $question of 2")
                    val position = onMain { activity.model.state.value.let { checkNotNull(it.challenge).questions[it.page].position } }
                    typeFirstLetters(activity, Screen.BackupConfirm, passphrase[position - 1])
                    tap("confirm_done")
                }
                on(activity, Screen.BackupSave, START_SECONDS)
                val saved = text("backup_name")
                // A file of that name left by a test before (BackupTest's, when one boot runs every part) would
                // be the one Check a backup picks: Downloads holds none of it before this save.
                Picker.removeFromDownloads(saved)
                name = saved
                tap("save_backup")
                creator = Picker.save(saved)
                on(activity, Screen.BackupVerified, START_SECONDS)
                tap("backup_next")
                on(activity, Screen.WatchOffer)
                tap("skip_watch_only")
                on(activity, Screen.RegisterOffer)
                tap("skip_registration")
                checklistToFinish(activity, 1)
                tap("check_backup")
                Picker.pick(saved)
                on(activity, Screen.BackupCheckEntry, START_SECONDS)
                find("privacy_gate")
                tap("pass_gate")
                await("past the entry's gate", 10) { onMain { !activity.model.state.value.gate } }
                for ((index, word) in passphrase.withIndex()) {
                    awaitText("entry_word", "Backup passphrase, word " + (index + 1) + " of " + PASSPHRASE_WORDS)
                    typeFirstLetters(activity, Screen.BackupCheckEntry, word)
                    tap("entry_done")
                }
                on(activity, Screen.BackupCheckResult, START_SECONDS)
                awaitText("backup_fingerprint", fingerprint)
                awaitText("backup_seal_id", DICE_50_SEAL_ID)
                tap("show_backup_words")
                find("privacy_gate")
                tap("pass_gate")
                for (index in DICE_50_WORDS.indices) {
                    assertInsert(activity, DICE_50_WORDS, index, 1, 1)
                    tap(if (index + 1 < DICE_50_WORDS.size) "next" else "backup_words_done")
                }
                on(activity, Screen.BackupCheckResult)
                tap("backup_done")
                on(activity, Screen.Home)
                assertTrue("the slot is not at home: Done did not end the check", Core.selfTest() is Reply.Done)
            } finally {
                for (word in passphrase) word.fill(0)
                name?.let(Picker::removeFromDownloads)
            }
            pass(
                "the Cannot check and backup journey through the UI alone: 50 rolls tapped, Cannot check's confirm and its " +
                    "Back, then Start again: a new ceremony at 0 / 50 with Back doing nothing; dice-50-words12's 50 rolls " +
                    "tapped, Skip, 12 inserts equal to the vector's words, 12 read back by touches ($readback); the backup's " +
                    "passphrase behind its gate, its confirm's two words touched on the letter pad, saved through the " +
                    "picker ($creator) to Downloads under core's name and verified; Finish; Check a backup picking it, its 8 " +
                    "words touched on the letter pad: Backup OK with the summary's fingerprint and Seal ID $DICE_50_SEAL_ID, " +
                    "its 12 words the vector's, Done: Home with the slot empty; the file removed; the journey " + since(journey),
            )
            finish(activity)
        }
    }

    private companion object {
        /** A BIP39 passphrase of watchonly.json's (abandon-trezor's), touched on the ASCII pad and never printed. */
        const val PASSPHRASE = "TREZOR"
    }
}
