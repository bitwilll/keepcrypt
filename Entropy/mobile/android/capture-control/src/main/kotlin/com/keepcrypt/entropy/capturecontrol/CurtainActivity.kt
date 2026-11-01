package com.keepcrypt.entropy.capturecontrol

import androidx.activity.ComponentActivity

/**
 * The first-frame test's curtain (tasks/todo.md, M5 group 6): a window that draws nothing over the
 * theme's black background and has no FLAG_SECURE, so its pixels are truly black. The test starts it
 * before a cold launch, so a recording from before the launch to the first screen has nothing but
 * black in the app's window unless a frame of the app leaks. CI only, never released.
 */
class CurtainActivity : ComponentActivity()
