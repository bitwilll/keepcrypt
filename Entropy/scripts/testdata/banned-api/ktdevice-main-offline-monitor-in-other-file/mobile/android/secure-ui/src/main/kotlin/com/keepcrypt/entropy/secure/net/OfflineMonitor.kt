// Only secure-ui's own OfflineMonitor.kt may read the settings tables.
val wifi = Settings.Global.getInt(resolver, Settings.Global.WIFI_ON, 0)
