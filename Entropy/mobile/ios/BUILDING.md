# Building the iPhone app

The iPhone app is the one KeepCrypt artifact nobody can rebuild bit for bit (docs/build-plan.md,
"Release, reproducible builds and audit"; docs/mobile-apps.md): Apple signs and re-signs every app
it distributes, and Xcode's output is not byte-for-byte stable across machines. So a release
publishes this source, the exact tools CI builds it with, and these steps, and recommends the Pi or
Android for the highest assurance. Until the App Store listing (Q106), the app is built from source
only.

What *can* be checked: the Rust core inside the app is the same source as every other artifact's,
built with the same pinned toolchain, and `scripts/banned-api-check.sh --ios-app` checks any built
app against the reviewed `mobile/ios/expected/` (its Info.plist and privacy manifest, its own files
alone, the one OS randomness call core makes as its only RNG import, no network or clipboard API,
no test marker).

## Tools (as CI, .github/workflows/entropy-ios.yml)

| | Leg 1 | Leg 2 |
| --- | --- | --- |
| macOS runner | macos-26 | macos-15 |
| Xcode | 26.6 | 16.4 |
| Simulator | iPhone 17, iOS 26.5 | iPhone 16, iOS 18.6 |

- Deployment target: iOS 17.0. No runner image has an iOS 17 simulator, so iOS 17 itself is tested
  on hardware only.
- Rust: the toolchain `rust-toolchain.toml` pins (rustup installs it), with the
  `aarch64-apple-ios` and `aarch64-apple-ios-sim` targets.
- No Swift package, CocoaPods or other dependency: the project has none, and the gate refuses one.
- Choose Xcode with `DEVELOPER_DIR` (for example
  `DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer`); CI never changes `xcode-select`.

## Steps

From `Entropy/`, on a checkout of the release's tag:

```bash
# The Rust library (keepcrypt-capi, libkeepcrypt_capi.a) for the device and the simulator,
# copied into mobile/ios/build/rust/ (ignored by git)
sh scripts/ios-rust.sh shipping

# Build and test on a simulator
xcodebuild -project mobile/ios/KeepCrypt.xcodeproj -scheme KeepCrypt-Shipping -configuration Shipping \
  -destination 'platform=iOS Simulator,name=iPhone 17' CODE_SIGNING_ALLOWED=NO build test

# The device build, unsigned, and its scan against the reviewed expectations
xcodebuild -project mobile/ios/KeepCrypt.xcodeproj -scheme KeepCrypt-Shipping -configuration Shipping \
  -sdk iphoneos -destination 'generic/platform=iOS' -derivedDataPath "${TMPDIR:-/tmp}/kc-dd" CODE_SIGNING_ALLOWED=NO build
sh scripts/banned-api-check.sh --ios-app Shipping "${TMPDIR:-/tmp}/kc-dd/Build/Products/Shipping-iphoneos/KeepCrypt.app" mobile/ios/expected
```

To run it on your own iPhone, open the project in Xcode, choose your own team under Signing for the
KeepCrypt target, and build to the device. That signs it with your certificate; nothing else
changes. Build only the `KeepCrypt-Shipping` scheme for real use: `KeepCrypt-WithTestRegistry`
trusts the test registry key, and `KeepCrypt-TestHooks` holds the UI tests' hooks. Neither is ever
released.

## What cannot be reproduced, and why

- **The binary's bytes.** Xcode's compiler, linker and asset tools embed paths and build details,
  and differ between Xcode versions. Two builds of the same source are not compared by hash.
- **Apple's signature.** An App Store or TestFlight copy is re-signed by Apple, so even a
  byte-identical build would not match the downloaded app.

So the trust an iPhone build gives is the source's and the scan's, not a hash's. For seeds that guard
real savings, use the Pi image (rebuilt and compared on three hosts) or the Android APK.
