val airplane = Settings.Global.getInt(resolver, Settings.Global.AIRPLANE_MODE_ON, 0)
resolver.registerContentObserver(Settings.Global.getUriFor(Settings.Global.WIFI_ON), false, observer)
