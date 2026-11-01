// Only the app's own AirplaneSettingsIntent.kt may open the airplane-mode settings.
startActivity(Intent(Settings.ACTION_AIRPLANE_MODE_SETTINGS))
