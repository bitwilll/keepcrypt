// :secure-ui (tasks/todo.md, M5 groups 4 and 14; MA:24): SecureActivity, the base of the app's one
// activity, and what both apps draw (from commit 5 the static first screen; later the monitors,
// the Protected wrapper, timers, pads and the QR, seal and braille drawing), with JVM tests.
// :capture-control draws the same composables from here, without SecureActivity.

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
