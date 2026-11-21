package com.keepcrypt.entropy

import android.app.Activity
import android.view.WindowInsets
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getAllSemanticsNodes
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.text.font.FontFamily

/**
 * A screen's layout as Compose has it, read in-process from the activity's semantics (Q78, lead decision
 * M5-84 (d), commit U3i-b), for what an accessibility read cannot give: Compose leaves a node out of view out of
 * its accessibility tree and hands over only the part of a node its parents leave shown. Here every node of the
 * screen is read, in view or not, with its whole size and where it lies unclipped, the part of it shown, and
 * whether its text overflows its own box. Ids, tags, flags and sizes only, never a node's text: nothing read here
 * goes into a selector or a log.
 */
internal object Layout {
    /**
     * One semantics node (Compose's unmerged tree, as its accessibility reads it) at one position of its screen's
     * column: its id (Compose's, the same at every position while the screen shows), its test tag, whether it is a
     * control (it takes a click, or is a button by its role) and whether it shows text; its whole size and its
     * top-left corner, unclipped, and shown, the part of it inside its parents' clips, the window and the system
     * bars' insets (null when none), all in the window's pixels; overflow, whether its text overflows its box
     * (overflows); and Q97's facts of its text's lines (U3h), each a yes or no computed here, its text never kept:
     * brokenWord, a line broken between two letters or digits (inside a word or a group); wrapped, more lines than
     * its own (a soft wrap); monospace, set in the monospaced face (the code, the letters typed, C, D, the overview,
     * the choices); large, set at 36 sp or more (the insert's word, the Seal ID).
     */
    class Node(
        val id: Int,
        val tag: String?,
        val control: Boolean,
        val text: Boolean,
        val width: Float,
        val height: Float,
        val left: Float,
        val top: Float,
        val shown: Rect?,
        val overflow: Boolean,
        val brokenWord: Boolean,
        val wrapped: Boolean,
        val monospace: Boolean,
        val large: Boolean,
    )

    /** Every semantics node of the activity's Compose view as it lies now. */
    fun read(activity: Activity): List<Node> = Capture.onMain {
        val decor = activity.window.decorView
        val bars = decor.rootWindowInsets!!.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
        val safe = Rect(bars.left.toFloat(), bars.top.toFloat(), (decor.width - bars.right).toFloat(), (decor.height - bars.bottom).toFloat())
        Tags.root(activity).semanticsOwner.getAllSemanticsNodes(mergingEnabled = false, skipDeactivatedNodes = true).map { node ->
            val config = node.config
            val texts = ArrayList<TextLayoutResult>()
            if (SemanticsActions.GetTextLayoutResult in config) config[SemanticsActions.GetTextLayoutResult].action?.invoke(texts)
            Node(
                node.id,
                if (SemanticsProperties.TestTag in config) config[SemanticsProperties.TestTag] else null,
                SemanticsActions.OnClick in config || (SemanticsProperties.Role in config && config[SemanticsProperties.Role] == Role.Button),
                SemanticsProperties.Text in config && config[SemanticsProperties.Text].any { it.isNotEmpty() },
                node.size.width.toFloat(),
                node.size.height.toFloat(),
                node.positionInWindow.x,
                node.positionInWindow.y,
                node.boundsInWindow.intersect(safe).takeUnless { it.isEmpty },
                texts.any { overflows(it, node.size.width.toFloat(), node.size.height.toFloat()) },
                texts.any(::brokenWord),
                texts.any(::wrapped),
                texts.any { it.layoutInput.style.fontFamily == FontFamily.Monospace },
                texts.any { it.layoutInput.style.fontSize.value >= LARGE_SP },
            )
        }
    }

    /**
     * Whether text, laid out as its node's semantics give it (GetTextLayoutResult), overflows a box width by height:
     * more lines than its limit, its lines taller than the box, or one of them wider. Not TextLayoutResult's
     * hasVisualOverflow: the result the semantics hand over is laid out again at its constraints' whole width, so
     * a short line in a wider column (a title, the "More below" line) reads there as overflowing a box it fits
     * (kc37, local: first_launch's title at font scale 1.0, 302x75 px).
     */
    private fun overflows(text: TextLayoutResult, width: Float, height: Float): Boolean =
        text.multiParagraph.didExceedMaxLines || text.multiParagraph.height > height + EDGE_PX ||
            (0 until text.lineCount).any { text.getLineRight(it) - text.getLineLeft(it) > width + EDGE_PX }

    /** Whether a line of text ends between two letters or digits: a word or a group broken across lines (Q97). */
    private fun brokenWord(text: TextLayoutResult): Boolean {
        val chars = text.layoutInput.text.text
        return (0 until text.lineCount - 1).any { line ->
            val end = text.getLineEnd(line)
            end in 1 until chars.length && chars[end - 1].isLetterOrDigit() && chars[end].isLetterOrDigit()
        }
    }

    /** Whether text takes more lines than its own (its newlines plus one): a soft wrap (Q97). */
    private fun wrapped(text: TextLayoutResult): Boolean = text.lineCount > text.layoutInput.text.text.count { it == '\n' } + 1

    /** The size from which a text is large (Q97): the insert's word (48 sp) and the Seal ID (36 sp). */
    private const val LARGE_SP = 36f

    /** How far, in pixels, a node's laid-out text or its shown parts may pass its bounds (Compose's sizes are fractional). */
    const val EDGE_PX = 1f
}
