package com.keepcrypt.entropy.screens

import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * The app's texts that docs/mobile-apps.md quotes, pinned to the doc (tasks/todo.md, Stage U's U3h): each constant
 * must stand in the doc in double quotes, word for word, so a change on either side fails here and the two are
 * changed together. The doc quotes three of the Android app's texts: the Device entropy screen's sentence
 * (SAFE_IF_EITHER, docs "Device entropy"), the privacy gate's action (GATE_ACTION, docs "Session lifetime" and
 * the words' steps), and, since Q93, the recording placeholder both apps show (REDACTED_LINE, the iPhone
 * section's RedactedCover sample). Its "No data collected or shared" is the store listing's.
 */
class DocsTextsTest {
    private val doc = entropyFile("docs/mobile-apps.md")

    @Test
    fun theDeviceEntropySentenceIsTheDocs() {
        assertTrue(doc.contains("\"" + SAFE_IF_EITHER + "\""), "docs/mobile-apps.md does not quote the Device entropy sentence the app shows")
    }

    @Test
    fun theRecordingPlaceholderIsTheDocs() {
        assertTrue(doc.contains("\"" + REDACTED_LINE + "\""), "docs/mobile-apps.md does not quote the recording placeholder the apps show (Q93)")
    }

    @Test
    fun thePrivacyGatesActionIsTheDocs() {
        assertTrue(doc.contains("\"" + GATE_ACTION + "\""), "docs/mobile-apps.md does not quote the privacy gate's action the app shows")
    }
}
