package com.keepcrypt.entropy

import android.os.SystemClock
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Ui.DOT
import com.keepcrypt.entropy.Ui.assertInsert
import com.keepcrypt.entropy.Ui.assertInsertAt
import com.keepcrypt.entropy.Ui.await
import com.keepcrypt.entropy.Ui.awaitText
import com.keepcrypt.entropy.Ui.find
import com.keepcrypt.entropy.Ui.on
import com.keepcrypt.entropy.Ui.sameWord
import com.keepcrypt.entropy.Ui.shown
import com.keepcrypt.entropy.Ui.tap
import com.keepcrypt.entropy.Ui.text
import com.keepcrypt.entropy.Ui.two
import com.keepcrypt.entropy.Ui.typeLetters
import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Summary
import com.keepcrypt.entropy.screens.INSERTS_PER_DEVICE
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.screens.TWO_DEVICES
import com.keepcrypt.entropy.screens.fingerprintHex
import java.nio.CharBuffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue

/**
 * The stretches U1's journeys share, from a check's result to Finish, through the UI alone (Stage U's
 * U1b-U1f; lead decision M5-72 (a)): JourneyTest's (the ui part) and SnapshotDrillTest's (the registry
 * part). Each input is made on the screen (Ui's taps, touches and accessibility clicks); state is read
 * in-process only to observe it, and no secret is printed.
 */
internal object Journeys {
    /** Elapsed seconds since start (SystemClock's elapsed real time, in ms), one decimal. */
    fun since(start: Long): String {
        val tenths = (SystemClock.elapsedRealtime() - start) / 100
        return (tenths / 10).toString() + "." + (tenths % 10) + " s"
    }

    /**
     * From a check's result with the words available (passed or skipped): Show words through the privacy
     * gate, each of the count inserts by Next (its position and device, and for a vector seed, words not
     * null, its word, in-process), across the device swap and its second gate on a 24-word seed, then the
     * read-back of every insert's first four letters touched on the letter pad (each a match, the header
     * naming its device; for a seed that is no vector's, the letters read in-process from the insert the
     * read-back holds, never printed), to its end. Returns the read-back's time.
     */
    fun wordsAndReadBack(activity: MainActivity, words: List<String>?, count: Int): String {
        val devices = count / INSERTS_PER_DEVICE
        fun device(index: Int) = index / INSERTS_PER_DEVICE + 1
        tap("show_words")
        find("privacy_gate")
        assertTrue("the words showed before the privacy gate", onMain { activity.model.state.value.gate })
        tap("pass_gate")
        await("past the words' gate", 10) { !onMain { activity.model.state.value.gate } }
        for (index in 0 until count) {
            if (words != null) assertInsert(activity, words, index, device(index), devices) else assertInsertAt(activity, index, count, device(index), devices)
            if (index + 1 == count) break
            tap("next")
            if ((index + 1) % INSERTS_PER_DEVICE == 0) {
                on(activity, Screen.DeviceSwap)
                awaitText("device_swap_text", "Words 13-24 go on device 2 of 2.")
                tap("continue")
                find("privacy_gate")
                assertTrue("device 2's words showed before the privacy gate", onMain { activity.model.state.value.gate })
                tap("pass_gate")
            }
        }
        tap("start_readback")
        on(activity, Screen.ReadbackEntry)
        val readback = SystemClock.elapsedRealtime()
        for (index in 0 until count) {
            awaitText("readback_header", "Read back insert " + two(index + 1) + DOT + "device " + device(index) + " of " + devices)
            if (words != null) {
                typeLetters(activity, Screen.ReadbackEntry, words[index].take(4)) { it.readbackLetters }
            } else {
                // A seed that is no vector's: its insert's first letters read in-process into an array that is
                // zeroed once typed (never a String, never printed).
                val letters = onMain {
                    val word = checkNotNull(activity.model.state.value.insert).word()
                    val first = CharArray(minOf(4, word.size)) { Char(word[it].toInt()) }
                    word.wipe()
                    first
                }
                try {
                    typeLetters(activity, Screen.ReadbackEntry, CharBuffer.wrap(letters)) { it.readbackLetters }
                } finally {
                    letters.fill('\u0000')
                }
            }
            tap("letters_done")
            await("insert " + (index + 1) + " matched", 10) { onMain { activity.model.state.value.matched } }
            if (words != null) {
                assertTrue(
                    "the match does not show insert " + (index + 1) + "'s word",
                    onMain { sameWord(checkNotNull(activity.model.state.value.insert), words[index]) },
                )
            }
            tap("readback_next")
        }
        val time = since(readback)
        on(activity, Screen.ReadbackDone)
        return time
    }

    /** From the read-back's end: Show summary, the wallet summary (core's, its fingerprint on the screen) and its Next, to the backup's offer. Returns the summary. */
    fun summaryToBackupOffer(activity: MainActivity): Summary {
        tap("show_summary")
        on(activity, Screen.Wallet)
        val summary = onMain { checkNotNull(activity.model.state.value.summary) }
        val core = Core.summary()
        assertTrue("the summary is not core's", core is Reply.Done && core.value.firstAddress == summary.firstAddress)
        // Compared in-process: a seed that is no vector's has a fingerprint no selector should carry.
        assertEquals("the summary's fingerprint on the screen", fingerprintHex(summary.fingerprint), text("fingerprint"))
        tap("summary_next")
        on(activity, Screen.BackupOffer)
        return summary
    }

    /** From the read-back's end: summaryToBackupOffer, then the backup's offer skipped, to the watch-only offer. Returns the summary. */
    fun summaryToWatchOffer(activity: MainActivity): Summary {
        val summary = summaryToBackupOffer(activity)
        tap("skip_backup")
        on(activity, Screen.WatchOffer)
        return summary
    }

    /**
     * From the registration's offer: the registration QR behind its gate, read in-process (sealCode's
     * register text for a vector seed; core's own registration QR otherwise, a register text with a seal
     * code; neither printed), and its Next.
     */
    fun registration(activity: MainActivity, sealCode: String?) {
        tap("show_registration")
        find("privacy_gate")
        tap("pass_gate")
        await("past the registration QR's gate", 10) { onMain { activity.model.state.value.let { it.screen == Screen.RegisterQr && !it.gate } } }
        val registration = onMain { activity.model.state.value.registration } ?: throw AssertionError("no registration QR")
        val text = Checker.read(registration)
        if (sealCode != null) {
            assertTrue("the registration QR is not the seed's register text (neither is printed)", text == Checker.ORIGIN + "/register#c=" + sealCode)
        } else {
            val ours = when (val made = Core.registration()) {
                is Reply.Done -> made.value
                is Reply.Refused, Reply.Discarded -> throw AssertionError("core made no registration QR")
            }
            assertTrue("the registration QR drawn is not core's (neither is printed)", text == Checker.read(ours))
            ours.wipe()
            assertTrue("the registration QR is not a register text with a seal code (it is not printed)", REGISTER.matches(text))
        }
        tap("registration_done")
    }

    /** On the checklist: it names two devices for a 24-word seed and none for 12; Finish: Home, with the slot empty. */
    fun checklistToFinish(activity: MainActivity, devices: Int) {
        on(activity, Screen.Checklist)
        if (devices == 2) {
            assertTrue("the checklist does not say which device holds words 1-12", shown(Screen.Checklist, TWO_DEVICES))
        } else {
            // shown scans the checklist's text column to its end, so the line below its items cannot be missed.
            assertFalse("a 12-word seed's checklist names two devices", shown(Screen.Checklist, TWO_DEVICES))
        }
        tap("finish")
        on(activity, Screen.Home)
        assertTrue("the slot is not at home: Finish did not end the session", Core.selfTest() is Reply.Done)
    }

    /**
     * A dice-only vector seed's words to Finish (wordsAndReadBack, summaryToWatchOffer, the watch-only
     * offer skipped, registration with sealCode, checklistToFinish). Returns the read-back's time and the
     * whole stretch's.
     */
    fun wordsToFinish(activity: MainActivity, words: List<String>, sealCode: String): Pair<String, String> {
        val start = SystemClock.elapsedRealtime()
        val readback = wordsAndReadBack(activity, words, words.size)
        summaryToWatchOffer(activity)
        tap("skip_watch_only")
        on(activity, Screen.RegisterOffer)
        registration(activity, sealCode)
        checklistToFinish(activity, words.size / INSERTS_PER_DEVICE)
        return readback to since(start)
    }

    /** The registration QR's text: the registry's register page and 26 Crockford symbols, the seal code. */
    private val REGISTER = Regex("^" + Regex.escape(Checker.ORIGIN) + "/register#c=[0-9A-HJKMNP-TV-Z]{26}$")
}
