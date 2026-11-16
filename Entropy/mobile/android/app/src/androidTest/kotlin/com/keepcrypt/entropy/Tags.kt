package com.keepcrypt.entropy

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import android.view.accessibility.AccessibilityNodeProvider
import androidx.compose.ui.platform.ViewRootForTest
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getAllSemanticsNodes

/**
 * The tests' own reading of the screens' Compose test tags (Q84, lead decision M5-84 (c), commit U3n). The
 * shipping APK turns none of its test tags into resource ids (MainActivity's testTagsAsResourceId is the
 * test-registry APK's alone), so no node an accessibility service reads there names by its id what it holds. The
 * tests, most of which run on the shipping APK, still find nodes by their
 * tags, read in-process: install() hands Compose a callback that runs as each of this process's Compose views
 * is made (ViewRootForTest.onViewCreatedCallback, Compose's own hook for its tests, called right after the
 * view's accessibility delegate is set), which wraps that delegate so that each node the view's node provider
 * creates carries its semantics node's test tag, read from the view's own semantics (its unmerged tree, as
 * Compose's accessibility reads it), as its resource id (the id the test-registry APK gives it itself). So the UI Automator searches by id (By.res) and the
 * node walks that read viewIdResourceName work in the app's process alone, while the tests run, and only for
 * the app under test: nothing of the app changes, and no other process (capture-control's, the system's) is
 * touched. While exposed is false the nodes go out as the app makes them (CaptureTest's
 * noResourceIdReachesAccessibility reads them so). Every other call goes to Compose's own delegate and provider
 * unchanged, the provider's own searches by text and for focus among them (their nodes carry no id; UI Automator
 * finds nodes by walking the tree, never through them).
 */
internal object Tags {
    /** Whether the nodes carry their tags as resource ids (the tests' reading); false: as the app makes them. */
    @Volatile
    var exposed = true

    /** Compose's node attribute that offers a node's test tag as extra data on request (AndroidComposeViewAccessibilityDelegateCompat's ExtraDataTestTagKey). */
    const val EXTRA_TAG = "androidx.compose.ui.semantics.testTag"

    /** Sets the callback for every Compose view this process makes from now on (Capture's first use). */
    fun install() {
        ViewRootForTest.onViewCreatedCallback = ::wrap
    }

    /**
     * The test tags of the activity's Compose view, read in-process from its semantics (unmerged), in tree
     * order. Main thread only.
     */
    fun of(activity: Activity): List<String> =
        root(activity).semanticsOwner.getAllSemanticsNodes(mergingEnabled = false, skipDeactivatedNodes = true)
            .filter { SemanticsProperties.TestTag in it.config }
            .map { it.config[SemanticsProperties.TestTag] }

    /** The activity's Compose view (its screens' one), whose semantics the tests read in-process (Layout too). Main thread only. */
    fun root(activity: Activity): ViewRootForTest =
        composeRoot(activity.window.decorView) ?: throw AssertionError("no Compose view in the activity")

    private fun composeRoot(view: View): ViewRootForTest? {
        if (view is ViewRootForTest) return view
        if (view is ViewGroup) for (index in 0 until view.childCount) composeRoot(view.getChildAt(index))?.let { return it }
        return null
    }

    private fun wrap(root: ViewRootForTest) {
        val view = root.view
        val compose = view.accessibilityDelegate ?: throw AssertionError("a Compose view without its accessibility delegate")
        view.accessibilityDelegate = Delegate(compose, Tagged(root))
    }

    /**
     * A node's test tag by the id its node provider gives it (the semantics node's own id; the root's is
     * HOST_VIEW_ID, and the root carries no tag). The ids' tags are read once for each main-thread task
     * that asks (a node provider's requests and prefetches each run in one), so a walk of the tree reads the
     * semantics once and never a tag a later recomposition changed.
     */
    private class Tagged(private val root: ViewRootForTest) {
        private val main = Handler(Looper.getMainLooper())
        private var now: Map<Int, String>? = null

        fun of(virtualId: Int): String? {
            val tags = now ?: root.semanticsOwner.getAllSemanticsNodes(mergingEnabled = false, skipDeactivatedNodes = true)
                .filter { SemanticsProperties.TestTag in it.config }
                .associate { it.id to it.config[SemanticsProperties.TestTag] }
                .also {
                    now = it
                    main.postAtFrontOfQueue { now = null }
                }
            return tags[virtualId]
        }
    }

    /** Compose's view delegate, its node provider wrapped (Provider); every other call passed on. */
    private class Delegate(private val compose: View.AccessibilityDelegate, private val tags: Tagged) : View.AccessibilityDelegate() {
        private var provider: Provider? = null

        override fun getAccessibilityNodeProvider(host: View): AccessibilityNodeProvider? {
            val inner = compose.getAccessibilityNodeProvider(host) ?: return null
            provider?.takeIf { it.inner === inner }?.let { return it }
            return Provider(inner, tags).also { provider = it }
        }

        override fun sendAccessibilityEvent(host: View, eventType: Int) = compose.sendAccessibilityEvent(host, eventType)

        override fun sendAccessibilityEventUnchecked(host: View, event: AccessibilityEvent) = compose.sendAccessibilityEventUnchecked(host, event)

        override fun dispatchPopulateAccessibilityEvent(host: View, event: AccessibilityEvent): Boolean =
            compose.dispatchPopulateAccessibilityEvent(host, event)

        override fun onPopulateAccessibilityEvent(host: View, event: AccessibilityEvent) = compose.onPopulateAccessibilityEvent(host, event)

        override fun onInitializeAccessibilityEvent(host: View, event: AccessibilityEvent) = compose.onInitializeAccessibilityEvent(host, event)

        override fun onInitializeAccessibilityNodeInfo(host: View, info: AccessibilityNodeInfo) = compose.onInitializeAccessibilityNodeInfo(host, info)

        override fun addExtraDataToAccessibilityNodeInfo(host: View, info: AccessibilityNodeInfo, extraDataKey: String, arguments: Bundle?) =
            compose.addExtraDataToAccessibilityNodeInfo(host, info, extraDataKey, arguments)

        override fun onRequestSendAccessibilityEvent(host: ViewGroup, child: View, event: AccessibilityEvent): Boolean =
            compose.onRequestSendAccessibilityEvent(host, child, event)

        override fun performAccessibilityAction(host: View, action: Int, args: Bundle?): Boolean = compose.performAccessibilityAction(host, action, args)
    }

    /** Compose's node provider, each node it creates given its test tag as its resource id while exposed. */
    private class Provider(val inner: AccessibilityNodeProvider, private val tags: Tagged) : AccessibilityNodeProvider() {
        override fun createAccessibilityNodeInfo(virtualViewId: Int): AccessibilityNodeInfo? {
            val info = inner.createAccessibilityNodeInfo(virtualViewId) ?: return null
            if (exposed) tags.of(virtualViewId)?.let { info.viewIdResourceName = it }
            return info
        }

        override fun addExtraDataToAccessibilityNodeInfo(virtualViewId: Int, info: AccessibilityNodeInfo, extraDataKey: String, arguments: Bundle?) =
            inner.addExtraDataToAccessibilityNodeInfo(virtualViewId, info, extraDataKey, arguments)

        override fun performAction(virtualViewId: Int, action: Int, arguments: Bundle?): Boolean = inner.performAction(virtualViewId, action, arguments)

        override fun findAccessibilityNodeInfosByText(text: String, virtualViewId: Int): List<AccessibilityNodeInfo>? =
            inner.findAccessibilityNodeInfosByText(text, virtualViewId)

        override fun findFocus(focus: Int): AccessibilityNodeInfo? = inner.findFocus(focus)
    }
}
