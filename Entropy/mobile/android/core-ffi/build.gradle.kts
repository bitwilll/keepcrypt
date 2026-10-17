// :core-ffi, Kotlin only (tasks/todo.md, M5 groups 4 and 13): Native (the JNI declarations over
// libkeepcrypt.so), Wire (the decoders) and Core (typed calls), with JVM tests against the host
// library. Until commit 14 it holds a placeholder Native object and loads no library.

plugins {
    alias(libs.plugins.android.library)
}

android {
    namespace = "com.keepcrypt.entropy.ffi"
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
}

dependencies {
    // The JVM tests: JUnit, and ZXing to decode every QR matrix the FFI draws (group 13).
    testImplementation(libs.junit)
    testImplementation(libs.zxing.core)
}
