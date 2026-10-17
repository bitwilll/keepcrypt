// The canary library (tasks/todo.md, M5 group 5): never shipped and in no real build. Only the
// Android workflow's canary build, run with -Pkc.canary=true, includes it (mobile/android/
// settings.gradle.kts) and makes :app depend on it (mobile/android/app/build.gradle.kts). Its
// manifest asks for INTERNET and declares a provider, as a library that must be rejected would;
// scripts/banned-api-check.sh --apk must refuse the APK that merges it, and a pass fails the job.
// It lives under scripts/testdata/, outside mobile/, so the gate never scans it as app code.
//
// It declares no dependency and has no source. The canary build runs offline, with the strict
// dependency verification, after the real build has resolved everything, so it can bring in
// nothing the real build did not. The root build locks every configuration of every module
// strictly against its gradle.lockfile; this module has none (lock state can only be written in the
// bootstrap, which the gate refuses), so its own configurations alone are unlocked here. :app's
// configurations stay locked: a project dependency is not lock state, and what this library
// resolves (the Kotlin standard library) is already in :app's.

plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "com.keepcrypt.canary"
    compileSdk = libs.versions.android.compile.sdk.get().toInt()
    buildToolsVersion = libs.versions.android.build.tools.get()
    ndkVersion = libs.versions.android.ndk.get()
    defaultConfig {
        minSdk = libs.versions.android.min.sdk.get().toInt()
    }
}

dependencyLocking {
    unlockAllConfigurations()
}
