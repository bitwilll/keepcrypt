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
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.isSensitiveData
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// The UI kit (tasks/todo.md, M5 group 15): the theme, the type scale and the components every screen
// draws with, so each later screen looks and reads like the first ones. White on black, as the Pi's
// panel; large type; every control a framed button whose text is its TalkBack label, with the button
// role and, when disabled, the disabled state, full width except a pad's keys (Pads.kt) and buttons
// that share a row (the dice screen's Undo and Confirm); every screen one column with its screen id as
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

/** The app's name in title type on its first screens and the stop screen, marked as a heading as Heading is (U3g). */
@Composable
fun Title(text: String) {
    BasicText(text, Modifier.padding(vertical = 6.dp).semantics { heading() }, style = KitType.title)
}

/**
 * Running text (body), or a note (small). live marks a line that appears or changes while its screen
 * stays (a refusal, a failure, the dice's counts, the scan's state) as a polite live region, so TalkBack
 * reads it when it changes (U3g); only for fixed or public text, never a secret's node.
 */
@Composable
fun KitText(text: String, style: TextStyle = KitType.body, tag: String? = null, live: Boolean = false) {
    val padded = Modifier.padding(vertical = 6.dp)
    val spoken = if (live) padded.semantics { liveRegion = LiveRegionMode.Polite } else padded
    BasicText(text, if (tag == null) spoken else spoken.testTag(tag), style = style)
}

/** The test tag (UI Automator's resource id) of every node that shows a secret: the capture harness reads each one's mark. */
const val SECRET_TAG = "secret"

/**
 * A node that shows a secret on a Protected screen (the words, their SeedBook numbers and faces, the
 * read-back's letters and verdicts): marked sensitive, which Android 14+ gives its accessibility node
 * as accessibility-data sensitive (docs/mobile-apps.md, "Rules for Claude Code"), so only accessibility
 * tools read it, TalkBack and its braille displays among them; SecureActivity marks the root so too.
 * Its test tag is SECRET_TAG, which names no secret.
 */
fun Modifier.secret(): Modifier = semantics { isSensitiveData = true }.testTag(SECRET_TAG)

/** Space between a screen's parts, size dp high. */
@Composable
fun Gap(size: Int) {
    Spacer(Modifier.height(size.dp))
}

/**
 * A button: framed, full width unless modifier says otherwise (two sharing a row), its text the
 * TalkBack label, with the button role. A disabled one is grey, takes no tap, and TalkBack says it is
 * disabled.
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

/** The notice line above a screen: why the last session was wiped, black on the warning yellow, a polite live region (U3g). */
@Composable
fun NoticeBar(text: String) {
    BasicText(
        text,
        Modifier
            .fillMaxWidth()
            .background(KitColors.warning)
            .padding(horizontal = 24.dp, vertical = 8.dp)
            .semantics { liveRegion = LiveRegionMode.Polite }
            .testTag("notice"),
        style = TextStyle(color = Color.Black, fontSize = 16.sp),
    )
}

/** The strip on every screen and overlay of the test-registry APK (Q60, lead decision M5-51): never a real ceremony. */
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
 * The one-way-choice confirm screen (docs/pi-firmware.md, "Confirmations": Skip, Match found and Cannot
 * check each take one): the question, what cannot be undone, the one action that does it, and Back,
 * which keeps everything and returns to the screen that offered the choice. The system Back does the
 * same: both are the model's back, which goes back from each confirm screen.
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
