package com.keepcrypt.entropy.secure

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The offline rule on the two settings (tasks/todo.md, M5 group 14; Q57): only airplane mode on with
 * Wi-Fi off (WIFI_ON 0, or 3 when airplane mode turned it off) is offline; Wi-Fi on again inside
 * airplane mode (2), airplane mode off, and any value the platform does not define, a missing setting
 * among them, are online.
 */
class OfflineRuleTest {
    @Test
    fun onlyAirplaneModeOnWithWifiOffIsOffline() {
        assertTrue(isOffline(1, 0))
        assertTrue(isOffline(1, 3))
        assertFalse("Wi-Fi on again inside airplane mode", isOffline(1, 2))
        assertFalse(isOffline(1, 1))
        for (wifi in 0..3) assertFalse("airplane mode off", isOffline(0, wifi))
    }

    @Test
    fun anUnknownOrMissingValueIsOnline() {
        assertFalse(isOffline(-1, 0))
        assertFalse(isOffline(2, 0))
        assertFalse(isOffline(1, -1))
        assertFalse(isOffline(1, 4))
    }
}
