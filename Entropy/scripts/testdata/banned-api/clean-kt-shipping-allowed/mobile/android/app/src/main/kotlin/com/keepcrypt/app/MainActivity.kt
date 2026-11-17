// The app's activity derives from SecureActivity, so it keeps FLAG_SECURE.
class MainActivity : SecureActivity() {
class Other : com.keepcrypt.secureui.SecureActivity()
class Third : SecureActivity {
    constructor() : super()
}
