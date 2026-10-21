package com.keepcrypt.entropy.secure

import android.content.Context
import android.database.ContentObserver
import android.os.Handler
import android.os.Looper
import android.provider.Settings

/**
 * The Android end of the offline monitor seam (tasks/todo.md, M5 group 14 and finding 9; Q57; lead
 * decision M5-20): airplane mode on and Wi-Fi off, read from Settings.Global's AIRPLANE_MODE_ON and
 * WIFI_ON, which any app may read, with no receiver and no permission. A ContentObserver on the two
 * reports each change on the main thread, and start reads them again, so each return to the app reads
 * the state afresh. :app hands it to the ceremony model as its OfflineMonitor. The gate allows
 * Settings.Global in this file alone.
 */
class SystemOffline(context: Context) {
    private val resolver = context.applicationContext.contentResolver
    private var report: ((Boolean) -> Unit)? = null
    private val observer = object : ContentObserver(Handler(Looper.getMainLooper())) {
        override fun onChange(selfChange: Boolean) {
            report?.invoke(read())
        }
    }

    /** Starts reporting: the state now, then each change, on the main thread, until stop. */
    fun start(report: (Boolean) -> Unit) {
        stop()
        this.report = report
        resolver.registerContentObserver(Settings.Global.getUriFor(Settings.Global.AIRPLANE_MODE_ON), false, observer)
        resolver.registerContentObserver(Settings.Global.getUriFor(Settings.Global.WIFI_ON), false, observer)
        report(read())
    }

    /** Stops reporting. */
    fun stop() {
        if (report == null) return
        report = null
        resolver.unregisterContentObserver(observer)
    }

    /** Whether the phone is offline now, by isOffline's rule; a setting that is missing reads as online. */
    fun read(): Boolean = isOffline(
        Settings.Global.getInt(resolver, Settings.Global.AIRPLANE_MODE_ON, UNSET),
        Settings.Global.getInt(resolver, Settings.Global.WIFI_ON, UNSET),
    )
}

/**
 * Q57's rule on the two settings: offline only with airplane mode on (AIRPLANE_MODE_ON is 1) and Wi-Fi
 * off. WIFI_ON is 0 (off) or 3 (off because airplane mode came on) while Wi-Fi is off, and 1 (on) or 2
 * (on again inside airplane mode) while it is on: the values of the platform's WifiSettingsStore. Any
 * other value, or a missing setting, reads as online, so the rule fails closed.
 */
fun isOffline(airplaneModeOn: Int, wifiOn: Int): Boolean = airplaneModeOn == 1 && (wifiOn == 0 || wifiOn == 3)

/** What a missing setting reads as: neither on nor off, so online. */
private const val UNSET = -1
