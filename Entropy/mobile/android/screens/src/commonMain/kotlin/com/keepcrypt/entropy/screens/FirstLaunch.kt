package com.keepcrypt.entropy.screens

import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * The first screen, shown on every start (docs/mobile-apps.md, "Role and honest limits";
 * tasks/todo.md, M5 group 15): what no app can stop, that the Pi is the device for life savings,
 * and that every M5 build is a 0.0.0 development build. Static until the self-test and Go offline
 * screens follow it (commits 14 and 16). With testRegistry, the TEST REGISTRY strip is on top
 * (Q60). The scroll position lives in plain memory, never in saved state. Written once in :screens'
 * common code (the re-plan for Compose Multiplatform), it is drawn by the app and the capture
 * control on Android and compiled for iPhone as well.
 */
@Composable
fun FirstLaunch(testRegistry: Boolean) {
    val scroll = remember { ScrollState(0) }
    Column(
        Modifier
            .fillMaxSize()
            .background(Color.Black)
            .safeDrawingPadding()
            .verticalScroll(scroll)
            .testTag("first_launch"),
    ) {
        if (testRegistry) {
            TestRegistryStrip()
        }
        Column(Modifier.padding(24.dp)) {
            BasicText("KeepCrypt", style = TextStyle(color = Color.White, fontSize = 32.sp, fontWeight = FontWeight.Bold))
            Spacer(Modifier.height(16.dp))
            Line("0.0.0 development build: do not use for real funds.", Color(0xFFFFD54F))
            Line("Use the Raspberry Pi device for life savings and inheritance wallets.", Color.White)
            Line(
                "What no app can stop: malware with OS-level control, a second camera pointed at the " +
                    "screen, or a rooted or jailbroken device.",
                Color.White,
            )
            Line("A ceremony needs airplane mode on and Wi-Fi off.", Color.White)
        }
    }
}

/** The strip on every screen of the test-registry APK (Q60): never a real ceremony. */
@Composable
fun TestRegistryStrip() {
    BasicText(
        "TEST REGISTRY",
        Modifier
            .fillMaxWidth()
            .background(Color(0xFFFFD54F))
            .padding(horizontal = 24.dp, vertical = 8.dp)
            .testTag("test_registry_strip"),
        style = TextStyle(color = Color.Black, fontSize = 18.sp, fontWeight = FontWeight.Bold),
    )
}

@Composable
private fun Line(text: String, color: Color) {
    BasicText(text, Modifier.padding(vertical = 8.dp), style = TextStyle(color = color, fontSize = 18.sp))
}
