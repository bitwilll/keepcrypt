// :core-ffi, Kotlin Multiplatform (tasks/todo.md, M5 groups 4 and 13; the re-plan for Compose
// Multiplatform, "Module layout"; the re-cut after Q73): Native, Wire and Core in the common code,
// compiled for Android over JNI and libkeepcrypt.so, with the common tests run on the JVM against
// the host library. M5 declares the Android target only (lead decision M5-31), so no Kotlin/Native
// toolchain enters the build; whether the iPhone reuses this code is M6's question. Until commit 14
// it holds a placeholder Native object and loads no library.

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
}

kotlin {
    android {
        namespace = "com.keepcrypt.entropy.ffi"
        compileSdk = libs.versions.android.compile.sdk.get().toInt()
        minSdk = libs.versions.android.min.sdk.get().toInt()
        withHostTestBuilder {}
    }
    sourceSets {
        commonTest.dependencies {
            implementation(libs.kotlin.test)
        }
        // The JVM tests only: JUnit, and ZXing to decode every QR matrix the FFI draws (group 13).
        getByName("androidHostTest").dependencies {
            implementation(libs.junit)
            implementation(libs.zxing.core)
        }
    }
}
