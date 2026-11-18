package com.keepcrypt.entropy.screens

import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.text.BasicText
import androidx.compose.foundation.text.TextAutoSize
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.Layout
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.isSensitiveData
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Constraints
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// The UI kit (tasks/todo.md, M5 group 15): the theme, the type scale and the components every screen
// draws with, so each later screen looks and reads like the first ones. White on black, as the Pi's
// panel; large type; every control a framed button whose text is its TalkBack label, with the button
// role and, when disabled, the disabled state, full width except a pad's keys (Pads.kt) and buttons
// that share a row (the dice screen's Undo and Confirm); every screen one column with its screen id as
// its test tag (UI Automator's resource id, group 6), its text scrolling above its actions (or with them,
// when they are tall: KitScreen), under the TEST REGISTRY strip in that build (Q60). No Material, no theme
// library (lead decision M5-22): plain foundation.

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
 * A screen's actions scroll with its text, after it, once they are taller than this share of the screen's
 * height (Q78, Q85; lead decision M5-84 (a)): under them the text column keeps at least the rest, so a
 * tall pad (the BIP39 passphrase's six rows of 48 dp keys and three rows of buttons, about 490 dp of CI's
 * 640 dp window) no longer squeezes the text above it out of view.
 */
const val ACTIONS_SHARE = 0.5f

/**
 * Whether actions actionsHeight high join a screen's scrolling column on a screen screenHeight high (both
 * in one unit): when they are taller than ACTIONS_SHARE of it. Before the first layout both are 0, and the
 * actions stay under the column.
 */
fun actionsScroll(actionsHeight: Int, screenHeight: Int): Boolean = actionsHeight > screenHeight * ACTIONS_SHARE

/** The line under a screen's column while the column can scroll further (Q85): fixed text, never a secret. */
const val MORE_BELOW = "More below"

/** The "More below" line's test tag. */
const val MORE_BELOW_TAG = "more_below"

/**
 * A screen: one column filling the window, its id as test tag; the TEST REGISTRY strip on top in that
 * build; then content, which scrolls (its position in plain memory, never in saved state), inside the
 * kit's margins; and the screen's actions, under the column, where they never scroll away, so every
 * control is on screen whatever the text's length; or, while they are taller than ACTIONS_SHARE of the
 * screen (actionsScroll), in the column after the content, scrolling with it (Q78, Q85; M5-84 (a)). Their
 * height and the screen's are measured at each layout that changes them, so a font or window change moves
 * them back once they fit; and since they are as wide in either place, moving them never changes their
 * height, and the choice holds (no back and forth). A move draws them anew where they go (they hold no
 * state of their own: the model does), so their nodes are new ones there and no accessibility service is
 * left with a node that changed its parent. While the column can scroll further, a "More below" line
 * (MORE_BELOW, a polite live region, which TalkBack reads when it appears) stands under it. The system
 * bars' insets are the caller's, or taken here when the screen is drawn alone (the capture control's
 * first screen).
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
    var screenHeight by remember { mutableIntStateOf(0) }
    var actionsHeight by remember { mutableIntStateOf(0) }
    val scrolling = actions != null && actionsScroll(actionsHeight, screenHeight)
    val placed = @Composable {
        if (actions != null) Column(Modifier.padding(vertical = 8.dp).onSizeChanged { actionsHeight = it.height }, content = actions)
    }
    Column(Modifier.fillMaxSize().background(background).safeDrawingPadding().onSizeChanged { screenHeight = it.height }.testTag(tag)) {
        if (testRegistry) {
            TestRegistryStrip()
        }
        Column(Modifier.weight(1f).verticalScroll(scroll).padding(horizontal = 24.dp, vertical = 16.dp)) {
            content()
            if (scrolling) placed()
        }
        if (scroll.canScrollForward) {
            // In the text's colour, not KitType.small's grey, which is under 4.5:1 on the stop screen's red.
            Box(Modifier.padding(horizontal = 24.dp)) { KitText(MORE_BELOW, KitType.small.copy(color = KitColors.text), tag = MORE_BELOW_TAG, live = true) }
        }
        if (actions != null && !scrolling) {
            Box(Modifier.padding(horizontal = 24.dp)) { placed() }
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
fun KitText(text: String, style: TextStyle = KitType.body, tag: String? = null, live: Boolean = false, whole: Int? = null) {
    val padded = Modifier.padding(vertical = 6.dp)
    val spoken = if (live) padded.semantics { liveRegion = LiveRegionMode.Polite } else padded
    val modifier = if (tag == null) spoken else spoken.testTag(tag)
    if (whole == null) {
        BasicText(text, modifier, style = style)
    } else {
        WholeLines(text, modifier, style, whole)
    }
}

/**
 * Q97: a text kept to its own lines (lines, its hard lines), shrunk down to half its size (WHOLE_SCALE) instead
 * of breaking a line: no line break inside a seed word, the go-ahead code, the typed letters, the Seal ID or a
 * row of C's and D's hex groups. Compose's step-based auto size, from the style's size down; in sp, so at font
 * scale 2.0 the smallest is the default scale's size.
 */
@Composable
fun WholeLines(text: String, modifier: Modifier, style: TextStyle, lines: Int = 1) {
    BasicText(text, modifier, style = style, maxLines = lines, autoSize = wholeSize(style))
}

/** WholeLines for an annotated text (the insert's word, its letters past the fourth lighter). */
@Composable
fun WholeLines(text: AnnotatedString, modifier: Modifier, style: TextStyle, lines: Int = 1) {
    BasicText(text, modifier, style = style, maxLines = lines, autoSize = wholeSize(style))
}

/** The auto size of a whole-line text in style: from its size down to WHOLE_SCALE of it. */
private fun wholeSize(style: TextStyle): TextAutoSize =
    TextAutoSize.StepBased(minFontSize = style.fontSize * WHOLE_SCALE, maxFontSize = style.fontSize, stepSize = 1.sp)

/**
 * The smallest share of its size a whole-line text shrinks to (Q97): one half, so at font scale 2.0 such a text is
 * never drawn smaller than at 1.0, and at 1.0 the longest seed word, the code and C's rows fit a 360 dp screen
 * whole. The iPhone's KitType.fitScale.
 */
const val WHOLE_SCALE = 0.5f

/** The space between two buttons side by side (KitPair; the 6 dp each side of the rows before Q97). */
private val PAIR_GAP = 12.dp

/**
 * Two buttons sharing a row (Q97; U3i): side by side, each half the row, a label wrapping between its words as any
 * text does, unless one word of either label is wider than a half's text width (the label's min intrinsic width,
 * its widest word, with the button's padding), which would break it inside the word; then one per row, each the
 * row's width. U3h stacked whenever a whole label did not fit its half on one line (its max intrinsic width), so at
 * font scale 1.0 the check QR's four answers stood one per row and the check QR lost its full view (CheckTest, run
 * 44398792258). The iPhone's KitPair (Kit.swift).
 */
@Composable
fun KitPair(content: @Composable () -> Unit) {
    Layout(content, Modifier.fillMaxWidth()) { measurables, constraints ->
        val width = constraints.maxWidth
        val gap = PAIR_GAP.roundToPx()
        val half = (width - gap) / 2
        if (measurables.all { it.minIntrinsicWidth(Constraints.Infinity) <= half }) {
            val placeables = measurables.map { it.measure(Constraints.fixedWidth(half)) }
            layout(width, placeables.maxOf { it.height }) {
                placeables.forEachIndexed { index, placeable -> placeable.placeRelative(index * (half + gap), 0) }
            }
        } else {
            val placeables = measurables.map { it.measure(Constraints.fixedWidth(width)) }
            layout(width, placeables.sumOf { it.height }) {
                var y = 0
                for (placeable in placeables) {
                    placeable.placeRelative(0, y)
                    y += placeable.height
                }
            }
        }
    }
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
