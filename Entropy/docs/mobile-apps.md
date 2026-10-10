# Mobile apps (Android and iPhone)

## Role and honest limits

The phone apps run the same core and the same ceremony as the Pi, but a phone is a networked, general-purpose computer, so the Pi stays the recommended device for long-term family savings.

| Use the phone app for | Prefer the Pi for |
| --- | --- |
| Smaller or everyday wallets | Life savings and inheritance wallets |
| Checking a Pi or Coldcard ceremony with the built-in verifier | Anything where an OS-level compromise is in your threat model |
| Checking that an encrypted backup restores | Users who cannot keep the phone offline during the ceremony |

**What no app can stop:** malware with OS-level control, a second camera pointed at the screen, or a rooted or jailbroken device. The app says this on its first screen in plain words and requires airplane mode during a ceremony.

## Architecture

Both apps are thin native shells over `keepcrypt-core` through UniFFI; no seed logic is written twice, and no seed ever leaves memory unencrypted.

| Concern | Android | iPhone |
| --- | --- | --- |
| UI | Kotlin, Jetpack Compose | Swift, SwiftUI |
| Minimum OS | Android 12 (API 31) | iOS 17 |
| Core | `libkeepcrypt.so` built with `cargo-ndk` (arm64-v8a, armeabi-v7a, x86\_64); Kotlin bindings from UniFFI | `KeepCryptCore.xcframework`; Swift bindings from UniFFI |
| Modules | `:app`, `:secure-ui` (secure activity base, capture monitors), `:core-ffi` | App target, `SecureUI` Swift package, core XCFramework |
| Capture protection | `FLAG_SECURE` on every window, including dialogs | Capture-state redaction, screenshot discards the session, secure-layer rendering |
| Network | No `INTERNET` permission in the manifest | No networking code or SDKs; offline check before a ceremony |
| Storage | Nothing persisted; `allowBackup="false"` | Nothing persisted |
| Backup export | Storage Access Framework "create document" | Document picker export |
| Text entry | In-app dice pad and word picker; no system keyboard | Same |
| Collision check | Signed snapshot opened with the file picker (works in airplane mode), or a check QR for a second device, with the go-ahead QR scanned back by the camera or its code typed | Same |
| Braille | Insert view with five braille faces per word, metal read-back; TalkBack braille displays | Same; VoiceOver braille displays |
| Watch-only export | Account and descriptor QR codes on a protected screen; never a file | Same |

**Session lifetime.** One `CeremonyViewModel` (Android) or `CeremonyModel` (iOS) owns the FFI session. Leaving the app while words or the backup passphrase are on screen discards the seed; earlier steps show a privacy cover and wipe after 60 seconds in the background.

## Screen capture protection: Android

Android can block screenshots and recordings outright: `FLAG_SECURE` makes screenshots come out blank and keeps the window off casts and non-secure displays ([Android Developers](https://developer.android.com/security/fraud-prevention/activities)). KeepCrypt sets it on every window before any content is drawn.

```kotlin
abstract class SecureActivity : ComponentActivity() {
    private val recordingCallback = Consumer<Int> { state ->
        ceremony.onRecordingChanged(state == WindowManager.SCREEN_RECORDING_STATE_VISIBLE)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        // Before any content: blank screenshots, block recording and casting.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        window.setHideOverlayWindows(true)                 // API 31, HIDE_OVERLAY_WINDOWS permission
        if (Build.VERSION.SDK_INT >= 33) setRecentsScreenshotEnabled(false)
        super.onCreate(savedInstanceState)
    }

    override fun onStart() {
        super.onStart()
        if (Build.VERSION.SDK_INT >= 35) {                 // DETECT_SCREEN_RECORDING permission
            recordingCallback.accept(windowManager.addScreenRecordingCallback(mainExecutor, recordingCallback))
        }
    }

    override fun onStop() {
        if (Build.VERSION.SDK_INT >= 35) windowManager.removeScreenRecordingCallback(recordingCallback)
        super.onStop()
    }
}
```

**Rules for Claude Code.**

- Compose dialogs and popups create their own windows: pass `securePolicy = SecureFlagPolicy.SecureOn` in every `DialogProperties` and `PopupProperties`.
- When the recording callback reports visible (Android 15+), replace words with a redacted placeholder as a second layer.
- On Android 14+, mark the word views `accessibilityDataSensitive` so only genuine accessibility tools can read them.
- No system keyboard on sensitive screens: dice use a 1 to 6 pad, word entry uses an in-app picker. Android's own docs warn keyboard taps can leak on older versions, one reason minSdk is 31.
- **Test:** on each sensitive screen, `adb exec-out screencap -p` must return a blank window, and a screen recording must show it blank, on at least one Pixel and one Samsung device.

## Screen capture protection: iPhone

iOS offers no public API that blocks screenshots, so the iPhone app stacks four layers and treats any screenshot during a ceremony as a reason to throw that seed away. Because the seed is not yet funded, discarding it costs the user only a few minutes.

| Layer | API | Effect | Limit |
| --- | --- | --- | --- |
| Capture redaction | SwiftUI `isSceneCaptured`; UIKit `sceneCaptureState` ([Apple](https://developer.apple.com/documentation/swiftui/protecting-sensitive-content-when-screen-sharing.md)) | Words replaced while recording, mirroring or remote control is active | Developers report cases where the state reads inactive while recording continues ([Apple forums](https://developer.apple.com/forums/thread/817446)) |
| Screenshot response | `UIApplication.userDidTakeScreenshotNotification` | Fires after a screenshot; the app wipes the session and starts over | Cannot stop the screenshot itself |
| Secure-layer rendering | Words drawn inside the layer of a `UITextField` with `isSecureTextEntry` | iOS leaves secure-entry content out of screenshots and recordings | Undocumented behavior; retest on every iOS release; never the only layer |
| App-switcher cover | Cover view whenever `scenePhase` is not `.active` | The task-switcher snapshot shows the cover | None significant |

```swift
struct SeedWordsView: View {
    @Environment(\.isSceneCaptured) private var isSceneCaptured
    @Environment(\.scenePhase) private var scenePhase
    @ObservedObject var ceremony: CeremonyModel

    var body: some View {
        Group {
            if isSceneCaptured || scenePhase != .active {
                RedactedCover(text: "Hidden while the screen is shared or recorded")
            } else {
                SecureLayer { WordGrid(words: ceremony.visibleWords) }  // secure-entry rendering
            }
        }
        .textSelection(.disabled)
        .onReceive(NotificationCenter.default.publisher(
            for: UIApplication.userDidTakeScreenshotNotification)) { _ in
            ceremony.discardAfterScreenshot()   // wipe and explain why a new seed is needed
        }
    }
}
```

**Rules for Claude Code.**

- Apply the same view wrapper to the backup passphrase, reveal-D, seal code, registration and watch-only QR screens.
- Words appear only after the user taps "I'm alone, show words" and hide again after 30 seconds without input. One tap shows them again without ending the session, so slow insert punching is never cut short.
- **Test** on every supported iOS version: screen recording from Control Center, AirPlay mirroring, and a hardware screenshot on each sensitive screen. Recordings must show the cover or a blank area; a screenshot must end the session.

## No network, no cloud backup, no clipboard

The seed exists only in the app's memory during the ceremony; the only thing that ever leaves the app is the encrypted backup file the user explicitly saves.

| Guard | Android | iPhone | CI check |
| --- | --- | --- | --- |
| No network | `INTERNET` permission absent, so the OS refuses sockets | No networking code or third-party SDKs | Android: merged-manifest permission dump; iOS: grep gate rejects `URLSession`, `NWConnection`, `CFNetwork` |
| Offline during ceremony | Require airplane mode (`Settings.Global.AIRPLANE_MODE_ON`) | `NWPathMonitor` must report no usable path | UI test with network on must block the ceremony |
| No OS backup | `allowBackup="false"`, `fullBackupContent="false"`, `dataExtractionRules` excluding everything | Nothing persisted, so nothing for iCloud to copy | Lint rule on manifest |
| No clipboard | Never call `setPrimaryClip`; text selection disabled | Never write `UIPasteboard`; `.textSelection(.disabled)` | Grep gate on clipboard APIs |
| No analytics or crash SDKs | None in dependencies | None; App Privacy label "Data Not Collected" | Dependency allow-list |
| Memory | Session wiped on discard, finish or timeout | Same | FFI tests assert wipe on every exit path |

**Collision checks stay offline too.** The app never goes online to check a seal: it reads a signed snapshot through the file picker, or shows a check QR for a second device and takes the go-ahead back by camera or typed code. Camera permission is asked for only when the user scans a go-ahead QR or turns on the camera extra. Registration uses the same second-device QR.

## Entropy sources on phones

Phones do not expose a raw hardware noise source to apps, so the device leg is the OS CSPRNG through the core's `getrandom`, and 50 or 99 dice rolls (12 or 24 words) remain mandatory in the default mode.

| Source | Android | iPhone | Credit |
| --- | --- | --- | --- |
| OS CSPRNG | `getrandom` syscall via the core | System CSPRNG via the core's `getrandom` | Device leg (256 bits by policy) |
| Physical dice | In-app 1 to 6 pad | Same | User leg, 2.585 bits per roll |
| Touch and button timing | Event timestamps in nanoseconds | Same | Mixed in, zero credit |
| Motion sensors | `SensorManager` accelerometer and gyroscope | Core Motion accelerometer and gyroscope | Mixed in, zero credit |
| Camera raw frames | Optional, off by default; camera permission | Optional, off by default; camera permission | Mixed in, zero credit |
| Snake and Tetris | Optional waiting screen; pieces from core's separate game-randomness call (its own `getrandom` call), never the pool | Same | Only their touch timing is mixed in |

The app explains the default mode in one sentence: "Your seed is safe if either your phone or your dice are honest."

## Encrypted backup only

The apps can save exactly one thing: the age-encrypted backup file defined in the build plan, written to a location the user picks and verified by reading it back. Words on paper remain the primary backup, and the app says so.

**Saving.**

1. The core generates an 8-word backup passphrase; it is shown on a protected screen, written on paper, and 2 words are confirmed.
2. The core encrypts in memory; the app never holds plaintext in a file.
3. Android opens the system "create document" picker (`ActivityResultContracts.CreateDocument`) and writes the bytes to the returned URI. iPhone uses `.fileExporter` with an in-memory document.
4. The app reads the saved file back, decrypts it in memory and compares the fingerprint before showing "Backup verified."
5. If the user picks a cloud folder, the app allows it with one line: the passphrase is what protects the file, so keep it on paper, away from the file.

**Never offered:** share sheet, copy, a QR code of the words (SeedQR), image, Photos, email, plaintext text file, or any export of the words themselves.

**Checking a backup.** Open a `.age` file from the picker, enter the passphrase with the in-app word picker, and the app shows the fingerprint and "Backup OK." Words appear only if the user asks, on the same protected screen.

**Reading a snapshot.** The file picker also opens `.kcr` registry snapshots. The app checks the Ed25519 signature against the pinned key and keeps the snapshot in memory only; it is the only file type the app reads besides `.age` backups.

## Screens and user flow

The phone ceremony mirrors the Pi screen for screen, so one user guide and one verifier cover all three platforms.

1. **First launch.** What the app does, what no phone app can protect against, and a pointer to the Pi build for life savings.
2. **Self-test.** Core known-answer tests; a failure blocks every ceremony.
3. **Go offline.** Shows airplane-mode status; the Start button stays disabled until the phone is offline.
4. **Home.** New seed, Dice-only seed, Check a backup, Load registry snapshot, Verify another device's ceremony, About.
5. **Length.** 12 words (default; fills one KeepCrypt Hinge or Screw) or 24.
6. **Device entropy.** Motion and touch extras are mixed in, with optional Snake or Tetris; the OS CSPRNG is read at the commitment.
7. **Commitment.** C as 16 groups of 4 hex characters.
8. **Dice.** 1 to 6 pad with undo; count and bits only, never the roll history.
9. **Check for collisions.** The same prompt and seal card as the Pi: automatic with a loaded snapshot; otherwise the user scans the check QR with the website or the offline checker app on a second device, then scans the go-ahead QR back with the camera (works in airplane mode) or types the go-ahead code. Only a verified go-ahead reveals the words; a Stop wipes the session unseen and offers "Add fresh entropy".
10. **Show words.** "I'm alone, show words," then one word per page in insert view on the protected screen: the word, its SeedBook number and five braille faces, with blank faces and mirror pairs flagged.
11. **Read-back from the metal.** First four letters of every punched insert (or paper word), compared with the seed.
12. **Wallet summary.** Fingerprint and first receive address.
13. **Encrypted backup (optional).** Passphrase, save, read-back verification.
14. **Watch-only export (optional).** Account QR for Sparrow and descriptor QR for Bitcoin Core.
15. **Register seal (optional, once).** Registration QR for a second device.
16. **Reveal D (optional).** Verification runs only.
17. **Finish.** The SeedBook "before you walk away" checklist; the session is wiped and the app returns to Home.

**Verify another device** runs the offline verifier inside the app: enter C, D and the rolls from a disposable KeepCrypt Pi run, or just the rolls from a Coldcard dice-only run, and compare the words.

## Store distribution and reproducible builds

Ship open source first and through the stores second, and be explicit about which builds users can reproduce.

| Channel | Requirement or note |
| --- | --- |
| Apple App Store | Guideline 3.1.5(i) allows wallet apps only from developers enrolled as an organization, so register a legal entity (for example a KeepCrypt foundation) before submission ([guideline summary](https://conductatlas.com/platform/apple/apple-app-store-review-guidelines/provision/CA-P-018935/crypto-wallet-apps-require-organization-developer-enrollment/)) |
| iOS reproducibility | Not achievable today because the store re-signs binaries; publish source, Xcode version and build steps |
| F-Droid | Builds from source and supports reproducible Android builds; the preferred Android channel |
| GitHub releases | Signed APK plus SHA-256 sums, matching the F-Droid build |
| Google Play | Check Play's current policies for crypto wallet apps before submitting; this was not verified for this doc |
| Labels | iOS App Privacy "Data Not Collected"; Play Data safety "No data collected or shared" |

## Sources

- [Android Developers: Secure sensitive activities (FLAG\_SECURE, HIDE\_OVERLAY\_WINDOWS)](https://developer.android.com/security/fraud-prevention/activities)
- [Guardsquare: Android 15 screen recording detection](https://www.guardsquare.com/blog/android-15-screen-spying-protection)
- [Android source: screen recording callback API](https://android.googlesource.com/platform/frameworks/base/+/c3aa8fee8c99%5E%21)
- [Apple: Protecting sensitive content when screen sharing is active](https://developer.apple.com/documentation/swiftui/protecting-sensitive-content-when-screen-sharing.md)
- [Apple: sceneCaptureState](https://developer.apple.com/tutorials/data/documentation/uikit/uitraitcollection/scenecapturestate.md)
- [Apple Developer Forums: capture state reads inactive during recording](https://developer.apple.com/forums/thread/817446)
- [App Store guideline 3.1.5(i) summary](https://conductatlas.com/platform/apple/apple-app-store-review-guidelines/provision/CA-P-018935/crypto-wallet-apps-require-organization-developer-enrollment/)
- [age v1 specification (C2SP)](https://age-encryption.org/v1)
