package com.keepcrypt.entropy

import android.os.ParcelFileDescriptor
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.UiSelector
import androidx.test.uiautomator.Until
import com.keepcrypt.entropy.Capture.probe
import java.util.regex.Pattern
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue

/**
 * The system's file picker on the phone (tasks/todo.md, M5 group 18), shared by BackupTest and JourneyTest
 * (the backup saved and Check a backup's file), CheckTest and SnapshotDrillTest (Load registry snapshot's file):
 * DocumentsUI driven by UI Automator, its controls found by their own resource ids and labels, and the
 * files it lists put in Downloads by the shell. Every name here is a public one (core's suggested backup
 * name, a vector's snapshot), never a secret.
 */
internal object Picker {
    /** The system's file picker: AOSP's DocumentsUI or Google's. */
    val PACKAGE: Pattern = Pattern.compile("com[.](google[.])?android[.]documentsui")

    /** Where the picker's Downloads root keeps its files, as the shell reads them. */
    const val DOWNLOADS = "/sdcard/Download/"

    /** The Downloads root's label in the picker. */
    private val DOWNLOADS_ROOT: Pattern = Pattern.compile("Downloads?")

    /** The picker's roots drawer button (its content description). */
    private val DRAWER: Pattern = Pattern.compile("(?i)(show roots|open navigation drawer|navigate up)")

    /** A probe line's longest picker facts. */
    private const val FACTS = 900

    private val device: UiDevice get() = UiDevice.getInstance(Capture.instrumentation)

    /** The system's file picker's package, once its window is up (DocumentsUI: AOSP's on the default images, Google's on Play images). */
    fun opened(): String {
        val shown = device.wait(Until.findObject(By.pkg(PACKAGE)), 20_000) ?: throw AssertionError("the system's file picker did not open")
        device.waitForIdle()
        return shown.applicationPackage
    }

    /**
     * The picker's visible texts and controls, for a probe line: its texts (its own labels and the files
     * it lists, none secret: the backup's name and the snapshots' are public) and its resource ids,
     * shortened.
     */
    fun facts(mode: String): String {
        val nodes = device.findObjects(By.pkg(PACKAGE))
        val ids = nodes.mapNotNull { it.resourceName }.distinct().joinToString(",")
        val texts = nodes.mapNotNull { it.text }.filter { it.isNotBlank() }.distinct().joinToString(" | ")
        val facts = "picker ($mode): texts $texts; ids $ids"
        return if (facts.length > FACTS) facts.substring(0, FACTS) else facts
    }

    /**
     * The picker in Downloads: where its title or breadcrumb already names it, nothing; otherwise the
     * roots drawer (its navigation button) and the Downloads root, each found first and then clicked
     * through a selector UI Automator resolves at the click (clicked), as Ui.tap does, since the picker
     * may redraw between the two (kc37's local run at commit 21a: StaleObjectException on the drawer's
     * node, found just before DocumentsUI redrew its Recent view).
     */
    fun toDownloads(mode: String) {
        if (device.hasObject(By.pkg(PACKAGE).text(DOWNLOADS_ROOT))) return
        device.wait(Until.findObject(By.pkg(PACKAGE).desc(DRAWER)), 10_000)
            ?: throw AssertionError("the picker is not in Downloads and has no roots drawer (its facts are the probe line before this)")
                .also { probe(facts(mode)) }
        clicked(UiSelector().packageNameMatches(PACKAGE.pattern()).descriptionMatches(DRAWER.pattern()))
        device.wait(Until.findObject(By.pkg(PACKAGE).text(DOWNLOADS_ROOT)), 10_000)
            ?: throw AssertionError("the picker's roots list no Downloads (its facts are the probe line before this)").also { probe(facts(mode)) }
        clicked(UiSelector().packageNameMatches(PACKAGE.pattern()).textMatches(DOWNLOADS_ROOT.pattern()))
        probe("the picker ($mode) went to Downloads through its roots drawer")
    }

    /**
     * In the create-document picker the save screen's Save opened: its name field must hold name (core's
     * suggested backup name, public), the picker goes to Downloads, and its Save is clicked. Returns the
     * picker's package. Its facts are a probe line before any failure, and one probe line names the
     * picker and its name field (BackupTest, JourneyTest).
     */
    fun save(name: String): String {
        val creator = opened()
        val title = device.wait(Until.findObject(By.pkg(PACKAGE).res("android:id/title")), 10_000)
            ?: throw AssertionError("the picker shows no name field (its facts are the probe line before this)").also { probe(facts("create")) }
        probe("the create-document picker: package $creator, its name field ${title.text}; " + facts("create"))
        assertEquals("the picker's name is not core's suggested one", name, title.text)
        toDownloads("create")
        val save = device.findObject(By.pkg(PACKAGE).res("android:id/button1"))
            ?: device.findObject(By.pkg(PACKAGE).clickable(true).text(Pattern.compile("(?i)save")))
            ?: throw AssertionError("the picker has no Save (its facts are the probe line before this)").also { probe(facts("create")) }
        save.click()
        return creator
    }

    /** In the open-document picker, the file named fileName in Downloads (or where it opened, if it lists it there), picked. */
    fun pick(fileName: String) {
        val opener = opened()
        var item: UiObject2? = device.wait(Until.findObject(By.pkg(PACKAGE).text(fileName)), 5_000)
        if (item == null) {
            toDownloads("open")
            item = device.wait(Until.findObject(By.pkg(PACKAGE).text(fileName)), 10_000)
        }
        if (item == null) {
            probe(facts("open"))
            throw AssertionError("the picker does not list the file to open (its facts are the probe line before this)")
        }
        probe("the open-document picker: package $opener")
        clicked(UiSelector().packageNameMatches(PACKAGE.pattern()).text(fileName))
        assertTrue("the picker stayed up", device.wait(Until.gone(By.pkg(PACKAGE)), 10_000) == true)
    }

    /**
     * Clicks the picker's control selector names once the picker is idle, the selector resolved at the
     * click; a control gone by then throws UiObjectNotFoundException. The click's boolean is not read
     * (see Ui.tap): what the click leads to is waited for after it.
     */
    private fun clicked(selector: UiSelector) {
        device.waitForIdle()
        device.findObject(selector).click()
        device.waitForIdle()
    }

    /**
     * bytes written as Downloads' file name by the shell (tee, its stdin the bytes, which it echoes on its
     * stdout: read back and compared), so the picker lists it as the backup's copy is listed; the file's
     * listing as a probe line. A public file only (a vector's snapshot).
     */
    fun putInDownloads(name: String, bytes: ByteArray) {
        val fds = Capture.instrumentation.uiAutomation.executeShellCommandRwe("tee " + DOWNLOADS + name)
        ParcelFileDescriptor.AutoCloseOutputStream(fds[1]).use { it.write(bytes) }
        val echoed = ParcelFileDescriptor.AutoCloseInputStream(fds[0]).use { it.readBytes() }
        val errors = ParcelFileDescriptor.AutoCloseInputStream(fds[2]).use { it.readBytes() }
        assertEquals("the shell's tee wrote to stderr: " + String(errors, Charsets.UTF_8).trim(), 0, errors.size)
        assertArrayEquals("tee did not echo the file's bytes", bytes, echoed)
        val listed = Capture.shellText("ls -l " + DOWNLOADS + name)
        probe("put in Downloads: $listed")
        assertTrue("the file is not in Downloads", listed.contains(name))
    }

    /** Downloads' file name removed by the shell, the test's own file. */
    fun removeFromDownloads(name: String) {
        Capture.shellText("rm -f " + DOWNLOADS + name)
    }
}
