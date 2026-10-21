package com.keepcrypt.entropy

import android.os.Bundle
import android.os.Process
import androidx.activity.OnBackPressedCallback
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.lifecycle.ViewModelProvider
import com.keepcrypt.entropy.screens.CeremonyModel
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.screens.Screens
import com.keepcrypt.entropy.secure.SecureActivity

/**
 * The app's one activity (tasks/todo.md, M5 groups 4, 13, 14 and 15), under SecureActivity's
 * protection: the shared screens over the ceremony model, which CeremonyHolder keeps across
 * configuration changes. Each start runs the real self-test through the bridge first (the model's
 * start-up, behind the self-test's screen); the app's comings and goings and the recording reports go
 * to the model, and so does the system Back, always (the model goes back only where nothing is lost,
 * and otherwise does nothing, so Back never leaves a ceremony or the app). Go offline's button opens
 * the airplane-mode settings through AirplaneModeSettings. Compose test tags are exposed as resource
 * ids, so UI Automator finds Public screens by id (group 6).
 */
class MainActivity : SecureActivity() {
    /**
     * The screen on display, set once it is composed: the capture harness's drawn-screen proof
     * (group 6) reads it before it waits for a frame. Main thread only.
     */
    var shownScreen: Screen? = null
        private set

    /** The ceremony model; the instrumentation drives it as the screens do (group 6). Main thread only. */
    lateinit var model: CeremonyModel
        private set

    @OptIn(ExperimentalComposeUiApi::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        model = ViewModelProvider(this)[CeremonyHolder::class.java].model
        onBackPressedDispatcher.addCallback(
            this,
            object : OnBackPressedCallback(true) {
                override fun handleOnBackPressed() {
                    model.back()
                }
            },
        )
        val airplaneSettings = AirplaneModeSettings(this)
        setContent {
            Box(Modifier.semantics { testTagsAsResourceId = true }) {
                Screens(model, airplaneSettings, onClose = this@MainActivity::closeApp, onShown = { shownScreen = it })
            }
        }
    }

    override fun onAppReturned() {
        model.appReturned()
    }

    override fun onAppResumed() {
        model.appResumed()
    }

    override fun onAppLeft() {
        model.appLeft()
    }

    override fun onRecordingChanged(visible: Boolean) {
        model.recordingChanged(visible)
    }

    /**
     * The stop screen's "Close app": the task leaves the recents list, then the process ends, so its
     * halted slot goes with it and the next start runs the self-test on a new one.
     */
    private fun closeApp() {
        finishAndRemoveTask()
        Process.killProcess(Process.myPid())
    }
}
