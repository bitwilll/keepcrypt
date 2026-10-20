// :core-ffi, Kotlin Multiplatform (tasks/todo.md, M5 groups 4 and 13; the re-plan for Compose
// Multiplatform, "Module layout"): Native, Wire and Core in the common code, compiled for Android
// over JNI and libkeepcrypt.so and for iPhone over the C bridge and libkeepcrypt_capi.a, with the
// common tests run on the JVM against the host library and on the iOS simulator, one class per
// process (lead decision M5-29). Until commit 14 it holds a placeholder Native object and loads no
// library; the bridge's definition and the test executables' link lines come with it. Both iPhone
// targets are declared on every host (lead decision M5-23), so no lockfile depends on the host
// that wrote it.

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
    iosArm64()
    iosSimulatorArm64()
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
