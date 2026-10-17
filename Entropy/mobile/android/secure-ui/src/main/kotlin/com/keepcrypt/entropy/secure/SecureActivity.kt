package com.keepcrypt.entropy.secure

import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import androidx.activity.ComponentActivity

/**
 * The base of the app's one activity (docs/mobile-apps.md, "Screen capture protection: Android";
 * tasks/todo.md, M5 "Built into this plan", SecureActivity). In the shipped sources the gate
 * allows an Activity subclass only in this file, so every screen is drawn under these settings:
 *
 * - FLAG_SECURE before super.onCreate, so before any content: screenshots and recordings of the
 *   window come out black, and it never reaches a cast or a non-secure display.
 * - Other apps' overlay windows hidden while it shows (HIDE_OVERLAY_WINDOWS in the manifest), and
 *   on Android 13+ no screenshot of it in the recents list.
 * - On the root view, so for every view under it: touches dropped while another window covers it
 *   (tapjacking), no autofill, and no content capture (the root opts out itself; FLAG_SECURE's
 *   effect on content capture is applied by the capture service, not by the app).
 * - No saved instance state: the Bundle Android keeps across a process death is left empty, and
 *   onCreate never reads one, so nothing of a session can come back from it.
 *
 * The starting window is black with no icon (Theme.KeepCrypt). The recording callback (Android
 * 15+), the accessibility-data-sensitive root and the "app left" report come with the Protected
 * screens (group 14).
 */
abstract class SecureActivity : ComponentActivity() {
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
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.clear()
    }
}
