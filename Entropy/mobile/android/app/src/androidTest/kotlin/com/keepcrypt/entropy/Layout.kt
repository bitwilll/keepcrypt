package com.keepcrypt.entropy

import android.app.Activity
import android.view.WindowInsets
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getAllSemanticsNodes
import androidx.compose.ui.text.TextLayoutResult

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
     * bars' insets (null when none), all in the window's pixels; and overflow, whether its text overflows its box
     * (overflows).
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

    /** How far, in pixels, a node's laid-out text or its shown parts may pass its bounds (Compose's sizes are fractional). */
    const val EDGE_PX = 1f
}
