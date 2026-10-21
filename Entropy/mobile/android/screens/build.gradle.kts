// :screens, Kotlin Multiplatform (the re-plan for Compose Multiplatform, "Module layout"; Q64,
// Q67; the re-cut after Q73): every screen, written once in the common code and drawn with Compose
// Multiplatform's runtime, foundation and ui (by coordinates, no Material, no navigation, lead
// decision M5-22). :app and :capture-control draw them. M5 declares the Android target only (lead
// decision M5-31); the screens and the platform seams stay in the common code, so M6 can reuse them
// for iPhone or not. FirstLaunch and Screen are here from commit 8q; the ceremony model, the timers,
// the pads, the drawing helpers and the clock and offline seams (lead decision M5-20) from commit 15.

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    alias(libs.plugins.kotlin.compose)
}

kotlin {
    android {
        namespace = "com.keepcrypt.entropy.screens"
        compileSdk = libs.versions.android.compile.sdk.get().toInt()
        minSdk = libs.versions.android.min.sdk.get().toInt()
        withHostTestBuilder {}
    }
    sourceSets {
        commonMain.dependencies {
            implementation(project(":core-ffi"))
            implementation(libs.cmp.runtime)
            implementation(libs.cmp.foundation)
            implementation(libs.cmp.ui)
        }
        commonTest.dependencies {
            implementation(libs.kotlin.test)
        }
    }
}

// The JVM tests (group 14): the common tests, run as the Android target's host tests, one test class
// per JVM, since the model's tests (CeremonyModelTest, CeremonyModelHaltTest and
// CeremonyModelRefusalTest) drive the process's one slot through Core over the host library that
// scripts/android-rust.sh withTestRegistry builds (it never ships), and a halt latches that slot for
// good.
val entropy = rootDir.resolve("../..").canonicalPath
tasks.withType<Test>().configureEach {
    forkEvery = 1
    systemProperty("java.library.path", "$entropy/target/ffi-test-registry/x86_64-unknown-linux-gnu/release")
}
