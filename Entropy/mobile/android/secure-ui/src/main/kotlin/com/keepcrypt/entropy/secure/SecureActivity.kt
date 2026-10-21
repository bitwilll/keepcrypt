package com.keepcrypt.entropy.secure

import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowManager
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
 *   on Android 13+ no screenshot of it in the recents list.
 * - On the root view, so for every view under it: touches dropped while another window covers it
 *   (tapjacking), no autofill, and no content capture (the root opts out itself; FLAG_SECURE's
 *   effect on content capture is applied by the capture service, not by the app); on Android 14+ it
 *   is accessibility-data sensitive, so only accessibility tools (TalkBack and its braille displays
 *   among them) read it.
 * - No saved instance state: the Bundle Android keeps across a process death is left empty, and
 *   onCreate never reads one, so nothing of a session can come back from it.
 * - The app's comings and goings, for the ceremony model: onAppReturned on every start, onAppLeft on
 *   every stop but a configuration change's (a rotation is not leaving the app), and on Android 15+
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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            setRecentsScreenshotEnabled(false)
        }
        super.onCreate(null)
        window.decorView.apply {
            filterTouchesWhenObscured = true
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            importantForContentCapture = View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
            }
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

    /** The activity started: the app is back in front (or there for the first time, or after a rotation). */
    protected open fun onAppReturned() {}

    /** The activity stopped, and not for a configuration change: the app was left (or a picker it opened is up). */
    protected open fun onAppLeft() {}

    /** Android 15+: the platform reports a recording of the screen (visible) or its end. */
    protected open fun onRecordingChanged(visible: Boolean) {}
}
