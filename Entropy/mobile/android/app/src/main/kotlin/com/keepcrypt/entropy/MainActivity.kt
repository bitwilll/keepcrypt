package com.keepcrypt.entropy

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.screens.FirstLaunch
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.secure.SecureActivity
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch

/**
 * The app's one activity (tasks/todo.md, M5 groups 4, 13 and 15), under SecureActivity's protection.
 * Each start runs the real self-test through the bridge first (StartUp); until the ceremony screens
 * arrive (commits 15-21) the first screen follows it. Compose test tags are exposed as resource ids,
 * so UI Automator finds Public screens by id (group 6).
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
        StartUp.run()
        setContent {
            val passed by StartUp.passed.collectAsState()
            Box(Modifier.semantics { testTagsAsResourceId = true }) {
                if (passed) {
                    val screen = Screen.FirstLaunch
                    when (screen) {
                        Screen.FirstLaunch -> FirstLaunch(testRegistry = TEST_REGISTRY)
                    }
                    SideEffect { shownScreen = screen }
                }
            }
        }
    }
}

/**
 * The start-up self-test (docs/mobile-apps.md's step 2; tasks/todo.md, M5 group 13): core's
 * known-answer tests through the bridge, once per process and off the main thread, since it is a
 * long call and the main thread never waits on one. Nothing is shown until it passes, and nothing
 * but a pass lets the app go on: the halt status throws KcHalt, and any other reply (a refusal or a
 * discard, which the self-test never gives) halts the slot first (Core.halt), so the process ends
 * on its uncaught-exception path (commit 15 brings the app's own crash path, which wipes first).
 */
private object StartUp {
    val passed = MutableStateFlow(false)
    private val started = AtomicBoolean(false)

    fun run() {
        if (!started.compareAndSet(false, true)) return
        CoroutineScope(Dispatchers.Default).launch {
            when (Core.selfTest()) {
                is Reply.Done -> passed.value = true
                is Reply.Refused, Reply.Discarded -> Core.halt()
            }
        }
    }
}
