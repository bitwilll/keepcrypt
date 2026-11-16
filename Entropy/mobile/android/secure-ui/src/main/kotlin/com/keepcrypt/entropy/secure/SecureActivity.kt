package com.keepcrypt.entropy.secure

import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.accessibility.AccessibilityEvent
import androidx.activity.ComponentActivity
import java.util.function.Consumer

/**
 * The base of the app's one activity (docs/mobile-apps.md, "Screen capture protection: Android";
 * tasks/todo.md, M5 "Built into this plan", SecureActivity, and group 14). In the shipped sources the
 * gate allows an Activity subclass only in this file, so every screen is drawn under these settings:
 *
 * - FLAG_SECURE before super.onCreate, so before any content: screenshots and recordings of the
 *   window come out black, and it never reaches a cast or a non-secure display.
 * - Other apps' overlay windows hidden while it shows (HIDE_OVERLAY_WINDOWS in the manifest), and
 *   no screenshot of it in the recents list.
 * - On the root view, so for every view under it: touches dropped while another window covers it
 *   (tapjacking), no autofill, and no content capture (the root opts out itself; FLAG_SECURE's
 *   effect on content capture is applied by the capture service, not by the app); and
 *   accessibility-data sensitive, so only accessibility tools (TalkBack and its braille displays
 *   among them) read it. The app needs Android 14 (minSdk 34, Q84), so each of these is always set.
 * - Reading counts as input (Q80 (b)): the root view's accessibility delegate sees every event its views
 *   send up to the window, and hands each one that is a person reading them (isReading: an accessibility
 *   focus, a text read by its parts) to onAccessibilityReading, so a braille display's reader, who reads
 *   without touching, is not covered at 30 s or wiped at 10 minutes mid-reading.
 * - No saved instance state: the Bundle Android keeps across a process death is left empty, and
 *   onCreate never reads one, so nothing of a session can come back from it.
 * - The app's comings and goings, for the ceremony model: onAppReturned on every start, onAppResumed
 *   on every resume (which ends the picker rule's exemption), onAppLeft on every stop but a
 *   configuration change's (a recreation is not leaving the app), and on Android 15+
 *   onRecordingChanged whenever the platform reports a recording of the screen starting or ending
 *   (DETECT_SCREEN_RECORDING in the manifest), so Protected screens can show a placeholder.
 *
 * The starting window is black with no icon (Theme.KeepCrypt).
 */
abstract class SecureActivity : ComponentActivity() {
    private val recording = Consumer<Int> { state ->
        onRecordingChanged(state == WindowManager.SCREEN_RECORDING_STATE_VISIBLE)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        window.setHideOverlayWindows(true)
        setRecentsScreenshotEnabled(false)
        super.onCreate(null)
        window.decorView.apply {
            filterTouchesWhenObscured = true
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            importantForContentCapture = View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS
            setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
            accessibilityDelegate = Reading()
        }
    }

    /**
     * The root view's accessibility delegate: each event a view under it sends up (Compose sends its nodes'
     * through its view's parent, requestSendAccessibilityEvent) passes here on its way to the window, and
     * one that is reading (isReading) is reported first; every event goes on unchanged.
     */
    private inner class Reading : View.AccessibilityDelegate() {
        override fun onRequestSendAccessibilityEvent(host: ViewGroup, child: View, event: AccessibilityEvent): Boolean {
            if (isReading(event.eventType)) onAccessibilityReading()
            return super.onRequestSendAccessibilityEvent(host, child, event)
        }
    }

    override fun onStart() {
        super.onStart()
        onAppReturned()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
            val state = windowManager.addScreenRecordingCallback(mainExecutor, recording)
            onRecordingChanged(state == WindowManager.SCREEN_RECORDING_STATE_VISIBLE)
        }
    }

    override fun onResume() {
        super.onResume()
        onAppResumed()
    }

    override fun onStop() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.VANILLA_ICE_CREAM) {
            windowManager.removeScreenRecordingCallback(recording)
        }
        if (!isChangingConfigurations) {
            onAppLeft()
        }
        super.onStop()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.clear()
    }

    /** The activity started: the app is back in front (or there for the first time, or after a recreation). */
    protected open fun onAppReturned() {}

    /** The activity resumed: in front and taking input (after a start, a picker or a prompt). */
    protected open fun onAppResumed() {}

    /** The activity stopped, and not for a configuration change: the app was left (or a picker it opened is up). */
    protected open fun onAppLeft() {}

    /** Android 15+: the platform reports a recording of the screen (visible) or its end. */
    protected open fun onRecordingChanged(visible: Boolean) {}

    /** An accessibility service read one of the activity's views for its user (isReading): input, as a touch is. Main thread. */
    protected open fun onAccessibilityReading() {}
}

/**
 * Whether an accessibility event of eventType is a person reading the app (Q80 (b)): a node taking
 * accessibility focus (TalkBack's touch exploration and swipes, a braille display moving from node to
 * node; Compose sends it only for a service's focus action, under touch exploration) or a text read by its
 * characters, words or lines (a braille display panning through one). Only an accessibility service acting
 * for its user sends either. No other event counts: a focus cleared also comes when the focused node goes
 * (the cover drawn over the screen, a page turned), and a scroll, a content or window change, a selection
 * or an announcement can be the app's own doing; a click is input already, through the press it makes.
 */
fun isReading(eventType: Int): Boolean =
    eventType == AccessibilityEvent.TYPE_VIEW_ACCESSIBILITY_FOCUSED ||
        eventType == AccessibilityEvent.TYPE_VIEW_TEXT_TRAVERSED_AT_MOVEMENT_GRANULARITY
