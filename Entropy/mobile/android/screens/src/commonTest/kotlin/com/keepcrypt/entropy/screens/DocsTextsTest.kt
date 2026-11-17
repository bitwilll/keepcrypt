package com.keepcrypt.entropy.screens

import kotlin.test.Test
import kotlin.test.assertTrue

/**
 * The app's texts that docs/mobile-apps.md quotes, pinned to the doc (tasks/todo.md, Stage U's U3h): each constant
 * must stand in the doc in double quotes, word for word, so a change on either side fails here and the two are
 * changed together. The doc quotes two of the Android app's texts: the Device entropy screen's sentence
 * (SAFE_IF_EITHER, docs "Device entropy") and the privacy gate's action (GATE_ACTION, docs "Session lifetime" and
 * the words' steps). Its "Hidden while the screen is shared or recorded" is the iOS sample's placeholder, not the
 * Android app's, and its "No data collected or shared" is the store listing's.
 */
class DocsTextsTest {
    private val doc = entropyFile("docs/mobile-apps.md")

    @Test
    fun theDeviceEntropySentenceIsTheDocs() {
        assertTrue(doc.contains("\"" + SAFE_IF_EITHER + "\""), "docs/mobile-apps.md does not quote the Device entropy sentence the app shows")
    }

    @Test
    fun thePrivacyGatesActionIsTheDocs() {
        assertTrue(doc.contains("\"" + GATE_ACTION + "\""), "docs/mobile-apps.md does not quote the privacy gate's action the app shows")
    }
}
