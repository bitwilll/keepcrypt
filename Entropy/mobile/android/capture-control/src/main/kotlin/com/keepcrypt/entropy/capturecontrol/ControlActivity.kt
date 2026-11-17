package com.keepcrypt.entropy.capturecontrol

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import com.keepcrypt.entropy.screens.FirstLaunch

/**
 * The capture tests' positive control (tasks/todo.md, M5 group 6): the app's first screen, drawn by
 * the same composable, in a plain activity with no FLAG_SECURE, so a capture of it must show its
 * pixels. CI only, never released.
 */
class ControlActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            FirstLaunch(testRegistry = false)
        }
    }
}
