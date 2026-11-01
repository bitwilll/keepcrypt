package com.keepcrypt.entropy

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import com.keepcrypt.entropy.Capture.finish
import com.keepcrypt.entropy.Capture.onMain
import com.keepcrypt.entropy.Capture.pass
import com.keepcrypt.entropy.Capture.probe
import com.keepcrypt.entropy.Capture.shellText
import com.keepcrypt.entropy.Ui.await
import com.keepcrypt.entropy.Ui.on
import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.screens.Screen
import com.keepcrypt.entropy.screens.screenId
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The process killed, then the app started again (tasks/todo.md, Stage U's U2j-a, the probe): the
 * instrumentation runs in the app's own process, so no test can kill the app and watch it return. So
 * android-emulator.sh's registry part kills the shipping app between runs of this class's tests, one test a
 * run: the backgrounded app killed as the system reclaims it (am kill), the app killed in the foreground
 * (kill -9 as root), and an instrumented run's own end (leavesTheAppOpen leaves the activity open on First
 * launch, and am instrument ends its process). After each, a test starts MainActivity as a person returning
 * does (the launcher's intent from the shell, no CLEAR_TASK, so a task left in recents comes forward) and
 * prints what the start was given: a saved-state Bundle or none and the intent's flags (MainActivity's
 * createdWith), the app's tasks in recents before the start, the screen shown and the slot. What must hold on
 * any restore path is asserted: First launch, the slot empty (in a new process it can be nothing else; a
 * restore of a session would need the app to keep one, which nothing here does). KillTest proper (U2j-b) is
 * written from these lines.
 */
@RunWith(AndroidJUnit4::class)
class KillTest {
    @Test
    fun afterTheBackgroundKill() = startAfter("the backgrounded app killed as the system reclaims it (am kill)")

    @Test
    fun afterTheForegroundKill() = startAfter("the app killed in the foreground (kill -9)")

    /** The activity left open on First launch: the run's own end is the kill afterTheRunsOwnEnd starts after. */
    @Test
    fun leavesTheAppOpen() {
        val activity = startAsAPerson()
        on(activity, Screen.FirstLaunch)
        pass("the app left open on First launch (" + onMain { activity.createdWith } + "); the run's own end ends its process")
    }

    @Test
    fun afterTheRunsOwnEnd() = startAfter("an instrumented run's own end, the app open")

    /** The probe after kill: the app's tasks in recents, then the start, what it was given, the screen and the slot. */
    private fun startAfter(kill: String) {
        val tasks = recentTasks()
        val activity = startAsAPerson()
        on(activity, Screen.FirstLaunch)
        val shown = onMain { activity.shownScreen }
        val home = Core.selfTest() is Reply.Done
        probe(
            "after $kill: $tasks of the app's tasks in recents before the start; the start was given " +
                onMain { activity.createdWith } + "; it shows " + (shown?.let(::screenId) ?: "nothing") +
                "; the slot " + (if (home) "at home" else "not at home"),
        )
        assertTrue("after $kill the slot is not at home: something of a session came back", home)
        pass("after $kill: First launch, the slot empty, nothing restored")
        finish(activity)
    }

    /** The shipping app's tasks dumpsys activity recents lists (its A=uid:package} entries, the test package's not among them). */
    private fun recentTasks(): Int {
        val pkg = Capture.instrumentation.targetContext.packageName
        return shellText("dumpsys activity recents").lines().count { it.contains("Recent #") && it.contains(":$pkg}") }
    }

    /**
     * MainActivity started as a person returning starts it: the launcher's action and category from the shell, no
     * flag that clears a task, so a task left in recents comes forward; the resumed instance, through the lifecycle
     * monitor (it is created in this process, which am instrument started).
     */
    private fun startAsAPerson(): MainActivity {
        val pkg = Capture.instrumentation.targetContext.packageName
        shellText("am start -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -n $pkg/com.keepcrypt.entropy.MainActivity")
        var started: MainActivity? = null
        await("MainActivity resumed after the start", 30) {
            started = onMain {
                ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(Stage.RESUMED).filterIsInstance<MainActivity>().firstOrNull()
            }
            started != null
        }
        return checkNotNull(started)
    }
}
