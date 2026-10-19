package com.keepcrypt.entropy

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import com.keepcrypt.entropy.secure.FirstLaunch
import com.keepcrypt.entropy.secure.SecureActivity

/**
 * The app's one activity (tasks/todo.md, M5 groups 4 and 15), under SecureActivity's protection.
 * Until the FFI and the ceremony screens arrive (commits 14-21) it draws the static first screen.
 * Compose test tags are exposed as resource ids, so UI Automator finds Public screens by id
 * (group 6).
 */
class MainActivity : SecureActivity() {
    /**
     * The screen on display, set once it is composed: the capture harness's drawn-screen proof
     * (group 6) reads it before it waits for a frame. Main thread only.
     */
    var shownScreen: Screen? = null
        private set

    @OptIn(ExperimentalComposeUiApi::class)
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val screen = Screen.FirstLaunch
            Box(Modifier.semantics { testTagsAsResourceId = true }) {
                when (screen) {
                    Screen.FirstLaunch -> FirstLaunch(testRegistry = TEST_REGISTRY)
                }
            }
            SideEffect { shownScreen = screen }
        }
    }
}
