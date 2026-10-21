// :core-ffi, Kotlin Multiplatform (tasks/todo.md, M5 groups 4 and 13; the re-plan for Compose
// Multiplatform, "Module layout"; the re-cut after Q73): Native, Wire, Core and Secret in the common
// code, compiled for Android over JNI and libkeepcrypt.so (Native's Android actual is the JNI method
// itself, lead decision M5-41), with the common tests run on the JVM against the host library. M5
// declares the Android target only (lead decision M5-31), so no Kotlin/Native toolchain enters the
// build; whether the iPhone reuses this code is M6's question.

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

// The JVM tests (group 13): the common tests and androidHostTest's ZXing round trips, run as the
// Android target's host tests against the host library that scripts/android-rust.sh withTestRegistry
// builds (x86_64-unknown-linux-gnu with keepcrypt-core's test-registry feature; it never ships), one
// test class per JVM, since a halt latches the process's slot for good. kc.entropy names Entropy/,
// whose vectors/ and ffi/src/wire.rs the tests read.
val entropy = rootDir.resolve("../..").canonicalPath
tasks.withType<Test>().configureEach {
    forkEvery = 1
    systemProperty("java.library.path", "$entropy/target/ffi-test-registry/x86_64-unknown-linux-gnu/release")
    systemProperty("kc.entropy", entropy)
}
