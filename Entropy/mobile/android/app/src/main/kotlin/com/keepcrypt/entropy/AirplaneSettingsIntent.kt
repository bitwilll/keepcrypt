package com.keepcrypt.entropy

import android.app.Activity
import android.content.Intent
import android.provider.Settings
import com.keepcrypt.entropy.screens.AirplaneSettings

/**
 * The Android end of the airplane-settings seam (tasks/todo.md, M5 group 15; lead decision M5-20;
 * docs/mobile-apps.md, step 3): Go offline's button opens the system's airplane-mode settings over the
 * app. It is the one intent the app starts outside its pickers, and the gate allows it in this file
 * alone, written whole on one line, so no other can be started here. Going to the settings is leaving
 * the app (no picker rule): Go offline holds no session, so the privacy cover on the return is all it
 * brings.
 */
internal class AirplaneModeSettings(private val activity: Activity) : AirplaneSettings {
    override fun open() {
        activity.startActivity(Intent(Settings.ACTION_AIRPLANE_MODE_SETTINGS))
    }
}
