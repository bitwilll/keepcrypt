// :capture-control draws the same composables without FLAG_SECURE: the capture tests' positive control.
class ControlActivity : ComponentActivity() {
val properties = DialogProperties(dismissOnBackPress = false)
val popup = PopupProperties(securePolicy = SecureFlagPolicy.SecureOff)
