// The Android end of the airplane-settings seam, the one intent: the airplane-mode settings.
import androidx.activity.result.contract.ActivityResultContracts
startActivity(Intent(Settings.ACTION_AIRPLANE_MODE_SETTINGS))
context.startActivity( Intent( android.provider.Settings.ACTION_AIRPLANE_MODE_SETTINGS ) )
val ask = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { }
