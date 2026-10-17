// The one intent: the airplane-mode settings.
startActivity(Intent(Settings.ACTION_AIRPLANE_MODE_SETTINGS))
context.startActivity( Intent( android.provider.Settings.ACTION_AIRPLANE_MODE_SETTINGS ) )
val ask = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }
