// :secure-ui (tasks/todo.md, M5 groups 4 and 14; MA:24; the re-plan for Compose Multiplatform):
// Android only, SecureActivity, the base of the app's one activity, with its theme and backup
// rules, and later the offline and capture monitors, with JVM tests. What both apps draw lives in
// :screens (the first screen from commit 8q; later the Protected wrapper, timers, pads and the QR,
// seal and braille drawing), which :capture-control draws without SecureActivity.

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.keepcrypt.entropy.secure"
    compileSdk = libs.versions.android.compile.sdk.get().toInt()
    buildToolsVersion = libs.versions.android.build.tools.get()
    ndkVersion = libs.versions.android.ndk.get()
    defaultConfig {
        minSdk = libs.versions.android.min.sdk.get().toInt()
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
    }
}

dependencies {
    implementation(platform(libs.compose.bom))
    implementation(libs.activity.compose)
    implementation(libs.compose.foundation)
    testImplementation(libs.junit)
}
