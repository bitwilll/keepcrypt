package com.keepcrypt.entropy

import android.app.Activity
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.Color
import android.graphics.Rect
import android.os.Build
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.view.ViewTreeObserver
import android.view.WindowInsets
import android.view.accessibility.AccessibilityNodeInfo
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.BySelector
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.Until
import com.keepcrypt.entropy.ffi.WordPage
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.screens.faceLabel
import com.keepcrypt.entropy.screens.screenId
import com.keepcrypt.entropy.screens.seedbookText
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.regex.Pattern
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail

/**
 * The capture harness's tools (tasks/todo.md, M5 group 6), shared by CaptureTest and ControlTest, and
 * by the other instrumented tests (the launch, the shell, the waits and the offline block).
 * Every capture is the shell's (UiAutomation.executeShellCommand and executeShellCommandRwe run as the
 * shell user, which lacks CAPTURE_BLACKOUT_CONTENT, as adb does; no root) or
 * UiAutomation.takeScreenshot(), read into memory and never written to a file. Values go back to
 * scripts/android-instrument.sh as instrumentation status values (status code 2): kc_probe, the
 * platform probe's facts; kc_pass, a check that passed; kc_region and kc_display, the app window's
 * region for the frame checker.
 */
internal object Capture {
    /**
     * capture-control's package: the positive control, the same first screen (ControlActivity) and a
     * gate seed's words page (WordsActivity), each with no FLAG_SECURE.
     */
    const val CONTROL_PACKAGE = "com.keepcrypt.entropy.capturecontrol"

    /** capture-control's first screen, the app's First launch. */
    const val CONTROL_FIRST_LAUNCH = "ControlActivity"

    /** capture-control's words page: dice-99-words12's first, drawn by the app's words composable. */
    const val CONTROL_WORDS = "WordsActivity"

    /** A pixel is black when no channel is above this (the frame checker's limit too). */
    private const val BLACK_MAX = 16

    /**
     * The known colour: the first screen's warning line, Color(0xFFFFD54F), within these distances
     * per channel (scaled thumbnails blend its edges). A full-screen capture of the control must hold
     * KNOWN_MIN such pixels; a recents view KNOWN_MIN_RECENTS.
     */
    private val KNOWN = intArrayOf(0xFF, 0xD5, 0x4F)
    private val KNOWN_TOLERANCE = intArrayOf(40, 40, 48)
    const val KNOWN_MIN = 50
    const val KNOWN_MIN_RECENTS = 10

    /** How long SurfaceFlinger gets to show a drawn frame, or a changed setting, before a capture. */
    const val SETTLE_MS = 1_000L

    private const val REPORT = 2

    val instrumentation get() = InstrumentationRegistry.getInstrumentation()

    fun report(key: String, value: String) {
        val values = Bundle()
        values.putString(key, value)
        instrumentation.sendStatus(REPORT, values)
    }

    fun probe(value: String) = report("kc_probe", value)

    fun pass(value: String) = report("kc_pass", value)

    /** The shell's stdout for command (run without a shell: no pipe or redirection). */
    fun shell(command: String): ByteArray =
        ParcelFileDescriptor.AutoCloseInputStream(instrumentation.uiAutomation.executeShellCommand(command))
            .use { it.readBytes() }

    fun shellText(command: String): String = String(shell(command), Charsets.UTF_8).trim()

    /**
     * The shell's stdout and stderr for command, through executeShellCommandRwe (API 31, the minSdk),
     * whose three descriptors are stdout, stdin and stderr: stdin is closed at once, then stdout is
     * read to its end, then stderr.
     */
    fun shellWithErrors(command: String): Pair<ByteArray, ByteArray> {
        val fds = instrumentation.uiAutomation.executeShellCommandRwe(command)
        fds[1].close()
        val out = ParcelFileDescriptor.AutoCloseInputStream(fds[0]).use { it.readBytes() }
        val err = ParcelFileDescriptor.AutoCloseInputStream(fds[2]).use { it.readBytes() }
        return Pair(out, err)
    }

    private val PNG_SIGNATURE = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)

    /**
     * The shell's screencap, as a PNG decoded in memory. Run 39289081979 showed the shell's own
     * screencap working (`adb exec-out`, 313,287 bytes) while this one decoded to nothing, and run
     * 39290401362 that it gave 0 bytes, so it runs through shellWithErrors and a failure names what
     * came back: its length and first bytes, where the PNG starts, if at all, and screencap's stderr.
     */
    fun screencap(): Bitmap {
        val (out, err) = shellWithErrors("screencap -p")
        return decodePng(out, err)
    }

    /**
     * A capture of the app's own screen through the shell's screencap: an image, or null when the
     * platform refused the capture. Android 12's SurfaceFlinger gives a caller without
     * CAPTURE_BLACKOUT_CONTENT no image at all while a secure window is shown, instead of blacking the
     * window out (run 39309562117: `adb exec-out screencap -p` gave 0 bytes over the shipping app and
     * 78,608 over capture-control in the same run; lead decision M5-18). A refusal counts only when it
     * is exactly that, no bytes on stdout and none on stderr; anything else must be a PNG. ControlTest,
     * run first, proves the same call returns an image of a screen without FLAG_SECURE.
     */
    fun screencapOrRefused(): Bitmap? {
        val (out, err) = shellWithErrors("screencap -p")
        if (out.isEmpty() && err.isEmpty()) return null
        return decodePng(out, err)
    }

    private fun decodePng(out: ByteArray, err: ByteArray): Bitmap {
        val start = (0..out.size - PNG_SIGNATURE.size).firstOrNull { i ->
            PNG_SIGNATURE.indices.all { out[i + it] == PNG_SIGNATURE[it] }
        }
        val head = out.take(16).joinToString("") { String.format("%02x", it.toInt() and 0xFF) }
        val errors = String(err, Charsets.UTF_8).trim().lines().joinToString(" | ").take(500)
        if (start == null) {
            probe("screencap -p: no PNG in ${out.size} bytes, first $head; stderr ${err.size} bytes: $errors")
            throw AssertionError("screencap -p gave no PNG (the kc_probe line before this has its length and stderr)")
        }
        if (start != 0) probe("screencap -p: $start bytes before the PNG (first $head)")
        val image = BitmapFactory.decodeByteArray(out, start, out.size - start)
        if (image == null) {
            probe(
                "screencap -p: a PNG at $start of ${out.size} bytes that does not decode; stderr ${err.size} bytes: $errors",
            )
            throw AssertionError("screencap -p gave a PNG that does not decode (see the kc_probe line before this)")
        }
        return image
    }

    /** UiAutomation.takeScreenshot(), copied out of a hardware bitmap so its pixels can be read. */
    fun screenshot(): Bitmap =
        screenshotOrRefused() ?: throw AssertionError("UiAutomation.takeScreenshot() gave no image")

    /** UiAutomation.takeScreenshot() of the app's own screen, or null when the platform refused it (M5-18). */
    fun screenshotOrRefused(): Bitmap? {
        val shot = instrumentation.uiAutomation.takeScreenshot() ?: return null
        if (shot.config != Bitmap.Config.HARDWARE) return shot
        return shot.copy(Bitmap.Config.ARGB_8888, false) ?: throw AssertionError("the screenshot could not be copied")
    }

    /** Lit pixels in region of a capture that may have been refused: a refusal shows nothing, so 0. */
    fun litOrRefused(image: Bitmap?, region: Rect): Int = if (image == null) 0 else litPixels(image, region)

    /** Known-colour pixels of a capture that may have been refused: a refusal shows nothing, so 0. */
    fun knownOrRefused(image: Bitmap?): Int = if (image == null) 0 else knownPixels(image)

    /** How a capture of the app's screen came back, for probe lines. */
    fun described(image: Bitmap?): String = if (image == null) "refused (no image)" else "a ${image.width}x${image.height} image"

    /** How many pixels inside region have a channel above BLACK_MAX. */
    fun litPixels(bitmap: Bitmap, region: Rect): Int {
        assertTrue("the region is outside the capture", Rect(0, 0, bitmap.width, bitmap.height).contains(region))
        val row = IntArray(region.width())
        var count = 0
        for (y in region.top until region.bottom) {
            bitmap.getPixels(row, 0, row.size, region.left, y, row.size, 1)
            for (c in row) {
                if (Color.red(c) > BLACK_MAX || Color.green(c) > BLACK_MAX || Color.blue(c) > BLACK_MAX) count++
            }
        }
        return count
    }

    /** How many pixels of the whole capture have the known colour. */
    fun knownPixels(bitmap: Bitmap): Int {
        val row = IntArray(bitmap.width)
        var count = 0
        for (y in 0 until bitmap.height) {
            bitmap.getPixels(row, 0, row.size, 0, y, row.size, 1)
            for (c in row) {
                if (Math.abs(Color.red(c) - KNOWN[0]) <= KNOWN_TOLERANCE[0] &&
                    Math.abs(Color.green(c) - KNOWN[1]) <= KNOWN_TOLERANCE[1] &&
                    Math.abs(Color.blue(c) - KNOWN[2]) <= KNOWN_TOLERANCE[2]
                ) count++
            }
        }
        return count
    }

    /** A new MainActivity in a task of its own, created in this process. */
    fun launch(): MainActivity {
        val intent = Intent(instrumentation.targetContext, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        return instrumentation.startActivitySync(intent) as MainActivity
    }

    fun finish(activity: Activity) {
        instrumentation.runOnMainSync { activity.finish() }
        waitUntil("the activity is destroyed") { onMain { activity.isDestroyed } }
    }

    /**
     * The drawn-screen proof (positive control (b)), before every capture of the app: the activity
     * reports screen as shown, then a frame is drawn after that report (an OnDrawListener sees it),
     * and SurfaceFlinger gets SETTLE_MS to show it.
     */
    fun proveDrawn(activity: MainActivity, screen: Screen) {
        waitUntil("the activity reports " + screenId(screen)) { onMain { activity.shownScreen == screen } }
        val drawn = CountDownLatch(1)
        val listener = ViewTreeObserver.OnDrawListener { drawn.countDown() }
        instrumentation.runOnMainSync {
            activity.window.decorView.viewTreeObserver.addOnDrawListener(listener)
            activity.window.decorView.invalidate()
        }
        assertTrue("no frame drawn after the screen was reported", drawn.await(10, TimeUnit.SECONDS))
        instrumentation.runOnMainSync { activity.window.decorView.viewTreeObserver.removeOnDrawListener(listener) }
        instrumentation.waitForIdleSync()
        SystemClock.sleep(SETTLE_MS)
    }

    /** The app window's region on the screen, without the system bars (which the system draws). */
    fun region(activity: Activity): Rect {
        val region = Rect()
        instrumentation.runOnMainSync {
            val decor = activity.window.decorView
            val at = IntArray(2)
            decor.getLocationOnScreen(at)
            val bars = decor.rootWindowInsets!!.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout())
            region.set(at[0] + bars.left, at[1] + bars.top, at[0] + decor.width - bars.right, at[1] + decor.height - bars.bottom)
        }
        assertTrue("the app window's region is empty", !region.isEmpty)
        return region
    }

    /** The display's size in pixels, the frame of every capture. */
    fun display(activity: Activity): Rect {
        val bounds = Rect()
        instrumentation.runOnMainSync { bounds.set(activity.windowManager.currentWindowMetrics.bounds) }
        return bounds
    }

    fun assertCaptureSize(bitmap: Bitmap, display: Rect, what: String) {
        assertEquals(what + " width", display.width(), bitmap.width)
        assertEquals(what + " height", display.height(), bitmap.height)
    }

    /**
     * A window of dumpsys window windows: its title, whether its flags (fl=) hold SECURE, and whether
     * its owner line (package=) named the package.
     */
    class WindowFacts(val title: String, val secure: Boolean, val byOwner: Boolean)

    /**
     * Every window of pkg that dumpsys window windows lists, each block starting at a header
     * "Window #N Window{ID uU TITLE}:". A window is pkg's when its owner line ("mOwnerUid=U
     * showForAllUsers=B package=PKG appop=OP") names the app's uid and package=pkg as whole words, which every window
     * the app adds has whatever its title (a pop-up's or a panel's title names no package), or when
     * its title is pkg, pkg/ACTIVITY or ends in " pkg" (the starting window's "Splash Screen pkg",
     * which the system adds), so another package that starts with pkg is not one.
     */
    fun windows(pkg: String): List<WindowFacts> {
        val header = Regex("""^\s*Window #\d+ Window\{\S+ \S+ (.*)\}:\s*$""")
        val ours = Regex("""(^|\s)""" + Regex.escape(pkg) + """(/\S*)?$""")
        val owner = "package=$pkg"
        // The app's uid: run 39329698964 showed com.android.systemui.ImageWallpaper's own owner line
        // holding package=pkg on API 31, so the line must also name the app's uid to count.
        // Read through the shell, which sees every package: the app cannot look up capture-control's uid itself
        // (package visibility; run 39331183291 gave NameNotFoundException). "package:PKG uid:U" per line.
        val listed = shellText("cmd package list packages -U " + pkg).lines()
            .map { it.trim().split(Regex("""\s+""")) }
            .firstOrNull { it.firstOrNull() == "package:$pkg" }
            ?.firstOrNull { it.startsWith("uid:") }
            ?: throw AssertionError("cmd package list packages -U names no uid for the package")
        val uid = "mOwnerUid=" + listed.removePrefix("uid:")
        val blocks = HashMap<String, ArrayList<String>>()
        val flags = Regex("""(^|\s)fl=(.*)$""")
        val found = ArrayList<WindowFacts>()
        var title: String? = null
        var titled = false
        var owned = false
        var secure = false
        var flagsSeen = false
        var ownerSeen = false
        fun close() {
            val t = title
            if (t != null && (titled || owned)) found.add(WindowFacts(t, secure, owned))
        }
        for (line in shellText("dumpsys window windows").lines()) {
            val h = header.find(line)
            if (h != null) {
                close()
                title = h.groupValues[1]
                titled = ours.containsMatchIn(h.groupValues[1])
                owned = false
                secure = false
                flagsSeen = false
                ownerSeen = false
                continue
            }
            if (title == null) continue
            val kept = line.trim()
            if (kept.startsWith("mOwnerUid=") || kept.startsWith("mSession=") || kept.startsWith("mAttrs=")) {
                blocks.getOrPut(title) { ArrayList() }.add(kept.take(160))
            }
            // The window's own owner line, WindowState.dump's "mOwnerUid=N showForAllUsers=B package=P ...".
            // Any other line can name the app too (run 39311080988 counted com.android.systemui.ImageWallpaper
            // as the app's from such a line), so only this one counts.
            val trimmed = line.trim()
            // Only the block's first owner line is the window's own: run 39334935255 showed the wallpaper's
            // block (mOwnerUid=10095 package=com.android.systemui) followed later by a second owner line, the
            // wallpaper target's, which is the app's.
            if (!ownerSeen && trimmed.startsWith("mOwnerUid=")) {
                ownerSeen = true
                val words = trimmed.split(Regex("""\s+"""))
                if (words.firstOrNull() == uid && words.contains(owner)) owned = true
            }
            val f = flags.find(line)
            if (!flagsSeen && f != null) {
                flagsSeen = true
                secure = Regex("[A-Z_]+").findAll(f.groupValues[2]).any { it.value == "SECURE" }
            }
        }
        close()
        for (w in found) if (!w.secure) probe("window block of " + w.title + ": " + (blocks[w.title] ?: emptyList()).joinToString(" | "))
        return found
    }

    /**
     * A node of the app's windows as UiAutomation reads it: its text, its resource name (a Compose test
     * tag), whether it is marked accessibility-data sensitive (Android 14+; false before), whether it
     * lies on screen and its bounds there, in the display's pixels. No data class: its text is never
     * part of a printed value.
     */
    class NodeFacts(val text: String?, val resourceName: String?, val dataSensitive: Boolean, val visible: Boolean, val bounds: Rect)

    /**
     * Every node of pkg's windows, read down from each window's root (UiDevice.getWindowRoots) child by
     * child in this process, so no text on the screen is handed to UI Automator, which logs the selector
     * of every search at debug level, its text included (UiDevice.findObjects: "Retrieving nodes with
     * selector: %s"; By.text's prints TEXT='...'; lead decision M5-68 (e)): the caller compares the texts
     * in-process. A node off screen is read too (UI Automator's own searches pass over one), and a child
     * that cannot be read fails the walk, which would otherwise miss what it draws.
     */
    fun nodes(pkg: String): List<NodeFacts> {
        val found = ArrayList<NodeFacts>()
        val marked = Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE
        fun read(node: AccessibilityNodeInfo) {
            val sensitive = marked && node.isAccessibilityDataSensitive
            val bounds = Rect()
            node.getBoundsInScreen(bounds)
            found.add(NodeFacts(node.text?.toString(), node.viewIdResourceName, sensitive, node.isVisibleToUser, bounds))
            for (index in 0 until node.childCount) {
                read(node.getChild(index) ?: throw AssertionError("a node's child could not be read, so the walk would miss it"))
            }
        }
        val roots = UiDevice.getInstance(instrumentation).windowRoots.filter { it.packageName?.toString() == pkg }
        assertTrue("no window of the app to read its nodes from", roots.isNotEmpty())
        for (root in roots) read(root)
        return found
    }

    /**
     * The secret texts a words page draws for insert, as WordsScreens.kt draws them: the word, its
     * SeedBook number, and each face's letter and label (a blank face's letter and an empty label are
     * no text). For in-process comparisons alone (CaptureTest's walk, ControlTest's words page): never
     * printed. The word's copy is wiped once read.
     */
    fun wordsPageSecrets(insert: WordPage): Set<String> = buildSet {
        add(wordOf(insert))
        add(seedbookText(insert.seedbook))
        for (n in 1..5) {
            val face = insert.face(n)
            face.letter?.let { add(it.toString()) }
            faceLabel(face.isBlank, face.mirrorPartner != null).takeIf { it.isNotEmpty() }?.let { add(it) }
        }
    }

    /** insert's word as a String, as the screens draw it, its copy wiped once read. */
    fun wordOf(insert: WordPage): String {
        val bytes = insert.word()
        val word = buildString { for (index in 0 until bytes.size) append(Char(bytes[index].toInt() and 0xFF)) }
        bytes.wipe()
        return word
    }

    /**
     * Starts one of capture-control's screens (its first screen unless activity names another) from the
     * shell (am start -W) and lets it draw. Its activities share a task, so the task is cleared first
     * (--activity-clear-task): the one named is then the task's only activity, and the one on screen.
     */
    fun startControl(activity: String = CONTROL_FIRST_LAUNCH) {
        val out = shellText("am start -W --activity-clear-task -n " + CONTROL_PACKAGE + "/" + CONTROL_PACKAGE + "." + activity)
        assertTrue("am start of the capture control did not report Status: ok", out.lines().contains("Status: ok"))
        SystemClock.sleep(2 * SETTLE_MS)
    }

    /**
     * Opens the recents view and proves it is on screen before anything there is captured: the home
     * app (what HOME resolves to, Launcher3's Quickstep on these images, which draws the recents
     * view) must show its overview_panel, the view its own test library waits for. pressRecentApps
     * only reports that the key was sent, and a recents view that never opened would leave the
     * app's black window, or the control's whole screen, to be captured instead of a thumbnail.
     */
    fun openRecents(device: UiDevice) {
        val home = homePackage()
        assertTrue("the recents key was not sent", device.pressRecentApps())
        val shown = device.wait(Until.hasObject(By.res(home, "overview_panel")), 10_000)
        assertTrue("the recents view did not open (no $home:id/overview_panel); " + focus(), shown == true)
        device.waitForIdle()
        SystemClock.sleep(2 * SETTLE_MS)
        probe("recents: $home's overview_panel is shown; " + focus())
    }

    /** The package of the activity HOME resolves to (cmd package resolve-activity --brief). */
    private fun homePackage(): String {
        val out = shellText("cmd package resolve-activity --brief -a android.intent.action.MAIN -c android.intent.category.HOME")
        val component = out.lines().last().trim()
        assertTrue("HOME resolves to no activity: $out", component.contains('/'))
        return component.substringBefore('/')
    }

    /** dumpsys window's focus lines, for the record. */
    private fun focus(): String =
        shellText("dumpsys window").lines().filter { it.contains("mCurrentFocus=") }.joinToString("; ") { it.trim() }

    /**
     * block's value, run with the phone offline as Q57 wants it (airplane mode on, then Wi-Fi off,
     * switched through the shell's cmd as the system's own toggles switch them, and read back from
     * the settings before block runs); then both settings are put back as they were, whatever block
     * did with them (LifecycleTest, CaptureTest and FlowTest, group 15).
     */
    fun <T> whileOffline(block: () -> T): T {
        val airplane = shellText("settings get global airplane_mode_on")
        val wifi = shellText("settings get global wifi_on")
        probe("before the offline block: airplane_mode_on=$airplane, wifi_on=$wifi")
        return try {
            shellText("cmd connectivity airplane-mode enable")
            shellText("cmd wifi set-wifi-enabled disabled")
            val end = SystemClock.elapsedRealtime() + 30_000
            while (!(globalSetting("airplane_mode_on") == "1" && globalSetting("wifi_on") in listOf("0", "3"))) {
                if (SystemClock.elapsedRealtime() > end) fail("timed out: the phone going offline")
                SystemClock.sleep(100)
            }
            block()
        } finally {
            shellText("cmd connectivity airplane-mode " + (if (airplane == "1") "enable" else "disable"))
            shellText("cmd wifi set-wifi-enabled " + (if (wifi == "0" || wifi == "3") "disabled" else "enabled"))
        }
    }

    /** A global setting as the shell reads it. */
    fun globalSetting(name: String): String = shellText("settings get global " + name)

    /** The system's permission prompt: the permission controller's window (AOSP's on these images, Google's elsewhere). */
    val PERMISSION_PROMPT: BySelector = By.pkg(Pattern.compile("com[.](google[.])?android[.]permissioncontroller"))

    /** The permission prompt's "Don't allow". */
    val PROMPT_DENY: BySelector = By.res(Pattern.compile("com[.](google[.])?android[.]permissioncontroller:id/permission_deny_button"))

    /**
     * Presses the permission prompt's "Don't allow" (deny, found by PROMPT_DENY) once, then waits up to
     * 10 s for the prompt to go. The press is the button's accessibility click, as TalkBack presses
     * it, not a touch at its centre: the permission controller's prompt (GrantPermissionsActivity, read
     * in kc37's aml_370546220) drops every touch until its enter animation has completed, which nothing
     * outside its process reports, and it shows its window empty, then its request, so its buttons'
     * first bounds lie where the empty window stood (kc37: 401 px lower, off the screen). A touch on a
     * button found after UI Automator's idle wait can still come too soon on a slow emulator, and the
     * prompt then stays up with no answer: most likely run 39783747240's failure (API 36: no refusal
     * reached the scan screen), but inferred, not reproduced (kc37 never lost the old touch), with no
     * logcat kept, AOSP's API 36 controller not read and an app-side loss of the refusal not ruled out.
     * The click goes to the button's own click handler, which answers as soon as the button is shown,
     * since the prompt shows it only with its request. A press the button does not take, or a prompt
     * still up, fails here, so a refusal that never comes after the prompt went is the app's, and a
     * repeat of that failure names its half.
     */
    fun denyPrompt(device: UiDevice, deny: UiObject2) {
        val pressed = deny.accessibilityNodeInfo.performAction(AccessibilityNodeInfo.ACTION_CLICK)
        assertTrue("the prompt's Don't allow did not take the press", pressed)
        assertTrue("the prompt stayed up after Don't allow", device.wait(Until.gone(PERMISSION_PROMPT), 10_000) == true)
    }

    /**
     * What dumpsys package says of one of pkg's permissions, read in pkg's own block ("Package [pkg]"
     * to the next package or section): whether it is among the requested permissions, whether a line
     * grants it ("PERMISSION: granted=true", a runtime permission's state line), and those state lines.
     */
    class PermissionFacts(val requested: Boolean, val granted: Boolean, val state: String)

    fun permission(pkg: String, permission: String): PermissionFacts {
        val lines = shellText("dumpsys package " + pkg).lines()
        val start = lines.indexOfFirst { it.trim().startsWith("Package [" + pkg + "]") }
        if (start < 0) throw AssertionError("dumpsys package lists no block for " + pkg)
        val block = lines.drop(start + 1)
            .takeWhile { !it.trim().startsWith("Package [") && (it.isBlank() || it[0].isWhitespace()) }
            .map { it.trim() }
        val requested = block.any { it == permission || it.startsWith(permission + ",") || it.startsWith(permission + " ") }
        val state = block.filter { it.startsWith(permission + ": granted=") }
        val granted = state.any { it.startsWith(permission + ": granted=true") }
        return PermissionFacts(requested, granted, state.joinToString(" | ").ifEmpty { "no state line" })
    }

    /** block's value, computed on the main thread. */
    @Suppress("UNCHECKED_CAST")
    fun <T> onMain(block: () -> T): T {
        var result: T? = null
        instrumentation.runOnMainSync { result = block() }
        return result as T
    }

    /** Waits up to seconds (10 unless given) for condition, checked every 100 ms. */
    fun waitUntil(what: String, seconds: Int = 10, condition: () -> Boolean) {
        val end = SystemClock.elapsedRealtime() + seconds * 1_000L
        while (!condition()) {
            if (SystemClock.elapsedRealtime() > end) fail("timed out: " + what)
            SystemClock.sleep(100)
        }
    }
}
