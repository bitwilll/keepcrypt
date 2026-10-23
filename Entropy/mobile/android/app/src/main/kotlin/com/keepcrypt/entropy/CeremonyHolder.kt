package com.keepcrypt.entropy

import android.app.Application
import android.os.SystemClock
import androidx.lifecycle.AndroidViewModel
import com.keepcrypt.entropy.screens.CeremonyModel
import com.keepcrypt.entropy.screens.MonotonicClock
import com.keepcrypt.entropy.screens.OfflineMonitor
import com.keepcrypt.entropy.screens.UtcDate
import com.keepcrypt.entropy.secure.SystemOffline
import java.time.LocalDate
import java.time.ZoneOffset
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * The ViewModel that holds the ceremony model (tasks/todo.md, M5 group 14; the re-plan's module
 * layout): it outlives a configuration change but never the activity's finish, and keeps nothing in
 * saved state. Its end (onCleared) wipes everything the slot holds. It gives the model the phone's seam
 * ends (lead decision M5-20): the main thread's scope, Dispatchers.Default for long calls,
 * SystemClock.elapsedRealtime() for every timer, today's UTC date for a snapshot's freshness,
 * secure-ui's offline monitor, the phone's motion (PhoneMotion, the accelerometer and gyroscope for
 * Device entropy) and the flavour's testRegistry flag; and it runs the model's timers in that scope.
 */
class CeremonyHolder(application: Application) : AndroidViewModel(application) {
    private val scope = CoroutineScope(Job() + Dispatchers.Main.immediate)

    val model = CeremonyModel(
        scope,
        Dispatchers.Default,
        ElapsedRealtime,
        UtcToday,
        Offline(SystemOffline(application)),
        PhoneMotion(application),
        TEST_REGISTRY,
    )

    init {
        scope.launch { model.runTimers() }
    }

    override fun onCleared() {
        scope.cancel()
        model.wipeAll()
    }
}

/** The phone's monotonic clock: it counts deep sleep and never follows the wall clock. */
private object ElapsedRealtime : MonotonicClock {
    override fun nowMillis(): Long = SystemClock.elapsedRealtime()

    override fun nowNanos(): Long = SystemClock.elapsedRealtimeNanos()
}

/**
 * Today's date in UTC as YYYYMMDD, from the phone's wall clock (lessons.md, time rules per target):
 * only a loaded snapshot's freshness reads it, never a timer.
 */
private object UtcToday : UtcDate {
    override fun today(): Int {
        val today = LocalDate.now(ZoneOffset.UTC)
        return today.year * 10_000 + today.monthValue * 100 + today.dayOfMonth
    }
}

/** secure-ui's offline monitor as the model's seam. */
private class Offline(private val system: SystemOffline) : OfflineMonitor {
    override fun start(report: (airplaneMode: Boolean, wifiOff: Boolean) -> Unit) {
        system.start(report)
    }

    override fun stop() {
        system.stop()
    }
}
