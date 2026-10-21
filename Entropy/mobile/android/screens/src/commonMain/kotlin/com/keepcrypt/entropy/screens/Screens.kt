package com.keepcrypt.entropy.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.text.BasicText
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.changedToDown
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * The app's screens over its ceremony model (tasks/todo.md, M5 groups 6 and 14): the screen is a when
 * over the model's state, so no back stack reaches a saved-state Bundle. Every tap first reaches the
 * model (input, the idle timer); the cover and the warning lie over the screen and take the tap that
 * removes them, so it reaches nothing under them. onShown reports each screen once it is composed (the
 * capture harness's drawn-screen proof); onClose is the stop screen's "Close app", which ends the
 * process (the platform's).
 */
@Composable
fun Screens(model: CeremonyModel, onClose: () -> Unit, onShown: (Screen) -> Unit) {
    val state by model.state.collectAsState()
    Box(
        Modifier
            .fillMaxSize()
            .background(Color.Black)
            .pointerInput(model) {
                awaitPointerEventScope {
                    while (true) {
                        val event = awaitPointerEvent(PointerEventPass.Initial)
                        if (event.changes.any { it.changedToDown() }) model.input()
                    }
                }
            },
    ) {
        // The system bars' insets are taken here, once, so a screen's own safeDrawingPadding adds none.
        Column(Modifier.fillMaxSize().safeDrawingPadding()) {
            val notice = state.notice
            if (notice != null && state.screen != Screen.Working && state.screen != Screen.Stop) {
                NoticeLine(notice)
            }
            when (state.screen) {
                Screen.FirstLaunch -> FirstLaunch(testRegistry = model.testRegistry)
                Screen.Working -> Working(testRegistry = model.testRegistry)
                Screen.Stop -> Stop(testRegistry = model.testRegistry, onClose = onClose)
            }
        }
        when (state.overlay) {
            Overlay.Cover -> Cover { model.dismissOverlay() }
            Overlay.Warning -> IdleWarning { model.dismissOverlay() }
            null -> {}
        }
        SideEffect { onShown(state.screen) }
    }
}

/**
 * The Protected wrapper (tasks/todo.md, M5 group 14; docs/mobile-apps.md, "Rules for Claude Code"): a
 * Protected screen's content shows only past the privacy gate, and never while a recording of the
 * screen is reported (a redacted placeholder instead, the second layer under FLAG_SECURE). Its 30 s
 * cover is the timers', drawn over every screen by Screens.
 */
@Composable
fun Protected(state: UiState, passGate: () -> Unit, content: @Composable () -> Unit) {
    when {
        state.gate -> PrivacyGate(passGate)
        state.recording -> Redacted()
        else -> content()
    }
}

/** "Working...": a long call runs; no input goes anywhere (the model ignores every tap). */
@Composable
fun Working(testRegistry: Boolean) {
    Column(Modifier.fillMaxSize().background(Color.Black).safeDrawingPadding().testTag("working")) {
        if (testRegistry) {
            TestRegistryStrip()
        }
        Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            BasicText("Working...", style = TextStyle(color = Color.White, fontSize = 24.sp))
        }
    }
}

/**
 * The stop screen (docs/mobile-apps.md, "When something fails (Android)"): red, fixed text, nothing
 * held, and one action, "Close app", which ends the process; the next start runs the self-test again.
 */
@Composable
fun Stop(testRegistry: Boolean, onClose: () -> Unit) {
    Column(Modifier.fillMaxSize().background(STOP_RED).safeDrawingPadding().testTag("stop")) {
        if (testRegistry) {
            TestRegistryStrip()
        }
        Column(Modifier.padding(24.dp)) {
            BasicText("KeepCrypt stopped", style = TextStyle(color = Color.White, fontSize = 28.sp, fontWeight = FontWeight.Bold))
            Spacer(Modifier.height(16.dp))
            BasicText(
                "Something failed, so everything the session held was wiped. Close the app; its next " +
                    "start runs the self-test again before any ceremony.",
                style = TextStyle(color = Color.White, fontSize = 18.sp),
            )
            Spacer(Modifier.height(32.dp))
            Action("Close app", "close_app", onClose)
        }
    }
}

/** The privacy gate before a Protected screen (docs/mobile-apps.md, step 10; docs/pi-firmware.md's gate). */
@Composable
fun PrivacyGate(pass: () -> Unit) {
    Column(Modifier.fillMaxSize().background(Color.Black).padding(24.dp).testTag("privacy_gate")) {
        BasicText(
            "The next screen shows a secret. No person or camera may see it.",
            style = TextStyle(color = Color.White, fontSize = 20.sp),
        )
        Spacer(Modifier.height(32.dp))
        Action("I'm alone, show words", "pass_gate", pass)
    }
}

/** What a Protected screen shows while a recording of the screen is reported. */
@Composable
private fun Redacted() {
    Box(Modifier.fillMaxSize().background(Color.Black).testTag("redacted"), contentAlignment = Alignment.Center) {
        BasicText(
            "Hidden while the screen is recorded. Stop the recording to go on.",
            Modifier.padding(24.dp),
            style = TextStyle(color = Color.White, fontSize = 20.sp),
        )
    }
}

/** The privacy cover: it hides the screen, and the tap on it only takes it away. */
@Composable
private fun Cover(dismiss: () -> Unit) {
    Box(
        Modifier.fillMaxSize().background(Color.Black).clickable(onClick = dismiss).testTag("cover"),
        contentAlignment = Alignment.Center,
    ) {
        BasicText("Tap to show the screen again", style = TextStyle(color = Color.White, fontSize = 20.sp))
    }
}

/** The warning a minute before the idle wipe; the tap on it keeps everything. */
@Composable
private fun IdleWarning(dismiss: () -> Unit) {
    Box(
        Modifier.fillMaxSize().background(Color.Black).clickable(onClick = dismiss).testTag("idle_warning"),
        contentAlignment = Alignment.Center,
    ) {
        BasicText(
            "No input for 9 minutes. The session is wiped in one minute: tap to keep it.",
            Modifier.padding(24.dp),
            style = TextStyle(color = WARNING_YELLOW, fontSize = 20.sp),
        )
    }
}

/** Why the last session was wiped, above the start screen. */
@Composable
private fun NoticeLine(notice: Notice) {
    val text = when (notice) {
        Notice.Left -> "The session was wiped: the app was left during it."
        Notice.Offline -> "The session was wiped: the phone went online."
        Notice.Idle -> "The session was wiped after 10 minutes without input."
        Notice.Background -> "The session was wiped after 60 seconds away from the app."
    }
    BasicText(
        text,
        Modifier.fillMaxWidth().background(WARNING_YELLOW).padding(horizontal = 24.dp, vertical = 8.dp).testTag("notice"),
        style = TextStyle(color = Color.Black, fontSize = 16.sp),
    )
}

/** A full-width action with its test tag (Compose test tags are UI Automator's resource ids, group 6). */
@Composable
private fun Action(text: String, tag: String, onClick: () -> Unit) {
    BasicText(
        text,
        Modifier.fillMaxWidth().border(2.dp, Color.White).clickable(onClick = onClick).padding(16.dp).testTag(tag),
        style = TextStyle(color = Color.White, fontSize = 20.sp, fontWeight = FontWeight.Bold),
    )
}

/** The stop screen's red. */
private val STOP_RED = Color(0xFFB00020)

/** Warnings and notices: the first screen's development-build yellow. */
private val WARNING_YELLOW = Color(0xFFFFD54F)
