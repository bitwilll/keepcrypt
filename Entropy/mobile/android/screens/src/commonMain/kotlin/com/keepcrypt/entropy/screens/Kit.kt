package com.keepcrypt.entropy.screens

import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
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
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// The UI kit (tasks/todo.md, M5 group 15): the theme, the type scale and the components every screen
// draws with, so each later screen looks and reads like the first ones. White on black, as the Pi's
// panel; large type; every control a full-width button whose text is its TalkBack label, with the
// button role and, when disabled, the disabled state; every screen one column with its screen id as
// its test tag (UI Automator's resource id, group 6), its text scrolling above its actions, under the
// TEST REGISTRY strip in that build (Q60). No Material, no theme library (lead decision M5-22): plain
// foundation.

/** The kit's colours. */
object KitColors {
    /** Every screen's background: black, as the Pi's panel. */
    val background = Color.Black

    /** Text and the frames of enabled buttons. */
    val text = Color.White

    /** Disabled buttons and lighter text. */
    val muted = Color(0xFF9E9E9E)

    /** Warnings and notices: the first screen's development-build yellow (the capture tests' known colour). */
    val warning = Color(0xFFFFD54F)

    /** The stop screen's red. */
    val stop = Color(0xFFB00020)
}

/** The kit's type scale, largest first. */
object KitType {
    /** The app's name on its first screens. */
    val title = TextStyle(color = KitColors.text, fontSize = 32.sp, fontWeight = FontWeight.Bold)

    /** A screen's heading. */
    val heading = TextStyle(color = KitColors.text, fontSize = 26.sp, fontWeight = FontWeight.Bold)

    /** Running text. */
    val body = TextStyle(color = KitColors.text, fontSize = 18.sp)

    /** Notes under the running text. */
    val small = TextStyle(color = KitColors.muted, fontSize = 16.sp)

    /** A button's label. */
    val button = TextStyle(color = KitColors.text, fontSize = 20.sp, fontWeight = FontWeight.Bold)

    /** Hex groups (C), in a monospace face so the columns line up. */
    val hex = TextStyle(color = KitColors.text, fontSize = 22.sp, fontFamily = FontFamily.Monospace)

    /** A value read at a glance (the dice pick). */
    val large = TextStyle(color = KitColors.text, fontSize = 48.sp, fontWeight = FontWeight.Bold)
}

/**
 * A screen: one column filling the window, its id as test tag; the TEST REGISTRY strip on top in that
 * build; then content, which scrolls (its position in plain memory, never in saved state), inside the
 * kit's margins; and under it the screen's actions, which never scroll away, so every control is on
 * screen whatever the text's length. The system bars' insets are the caller's, or taken here when the
 * screen is drawn alone (the capture control's first screen).
 */
@Composable
fun KitScreen(
    tag: String,
    testRegistry: Boolean,
    background: Color = KitColors.background,
    actions: (@Composable ColumnScope.() -> Unit)? = null,
    content: @Composable ColumnScope.() -> Unit,
) {
    val scroll = remember { ScrollState(0) }
    Column(Modifier.fillMaxSize().background(background).safeDrawingPadding().testTag(tag)) {
        if (testRegistry) {
            TestRegistryStrip()
        }
        Column(Modifier.weight(1f).verticalScroll(scroll).padding(horizontal = 24.dp, vertical = 16.dp), content = content)
        if (actions != null) {
            Column(Modifier.padding(horizontal = 24.dp, vertical = 8.dp), content = actions)
        }
    }
}

/** A screen's heading, marked as one for TalkBack's heading navigation. */
@Composable
fun Heading(text: String) {
    BasicText(text, Modifier.padding(vertical = 6.dp).semantics { heading() }, style = KitType.heading)
    Gap(16)
}

/** Running text (body), or a note (small). */
@Composable
fun KitText(text: String, style: TextStyle = KitType.body, tag: String? = null) {
    val modifier = Modifier.padding(vertical = 6.dp)
    BasicText(text, if (tag == null) modifier else modifier.testTag(tag), style = style)
}

/** Space between a screen's parts, size dp high. */
@Composable
fun Gap(size: Int) {
    Spacer(Modifier.height(size.dp))
}

/**
 * A button: full width, framed, its text the TalkBack label, with the button role. A disabled one is
 * grey, takes no tap, and TalkBack says it is disabled.
 */
@Composable
fun KitButton(text: String, tag: String, enabled: Boolean = true, modifier: Modifier = Modifier.fillMaxWidth(), onClick: () -> Unit) {
    val colour = if (enabled) KitColors.text else KitColors.muted
    BasicText(
        text,
        modifier
            .padding(vertical = 6.dp)
            .border(2.dp, colour)
            .clickable(enabled = enabled, role = Role.Button, onClick = onClick)
            .padding(16.dp)
            .testTag(tag),
        style = KitType.button.copy(color = colour),
    )
}

/** The notice line above a screen: why the last session was wiped, black on the warning yellow. */
@Composable
fun NoticeBar(text: String) {
    BasicText(
        text,
        Modifier.fillMaxWidth().background(KitColors.warning).padding(horizontal = 24.dp, vertical = 8.dp).testTag("notice"),
        style = TextStyle(color = Color.Black, fontSize = 16.sp),
    )
}

/** The strip on every screen of the test-registry APK (Q60): never a real ceremony. */
@Composable
fun TestRegistryStrip() {
    BasicText(
        "TEST REGISTRY",
        Modifier
            .fillMaxWidth()
            .background(KitColors.warning)
            .padding(horizontal = 24.dp, vertical = 8.dp)
            .testTag("test_registry_strip"),
        style = TextStyle(color = Color.Black, fontSize = 18.sp, fontWeight = FontWeight.Bold),
    )
}

/**
 * The one-way-choice confirm screen (docs/pi-firmware.md, "Confirmations": Skip, Match found and
 * Cannot check each take one, from commit 17): the question, what cannot be undone, the one action
 * that does it, and Back, which keeps everything; the system Back does the same (the model's back).
 */
@Composable
fun OneWayConfirm(
    tag: String,
    testRegistry: Boolean,
    question: String,
    consequence: String,
    action: String,
    onAction: () -> Unit,
    onBack: () -> Unit,
) {
    KitScreen(
        tag,
        testRegistry,
        actions = {
            KitButton(action, "confirm_action", onClick = onAction)
            KitButton("Back", "back", onClick = onBack)
        },
    ) {
        Heading(question)
        KitText(consequence)
    }
}
