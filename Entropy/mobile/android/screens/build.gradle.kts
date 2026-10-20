// :screens, Kotlin Multiplatform (the re-plan for Compose Multiplatform, "Module layout"; Q64,
// Q67): every screen, written once in the common code and drawn with Compose Multiplatform's
// runtime, foundation and ui (by coordinates, no Material, no navigation, lead decision M5-22). On
// Android, :app and :capture-control draw them; for iPhone the device target also links a static
// framework, which carries no Rust (the re-plan's "iOS link facts"). The screen ids, the ceremony
// model, the timers, pads and drawings and the platform seams (lead decision M5-20) follow with the
// commits that need them; FirstLaunch and Screen are here from commit 8q. Both iPhone targets are
// declared on every host (lead decision M5-23).

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
    iosArm64 {
        binaries.framework {
            baseName = "KeepCryptScreens"
            isStatic = true
        }
    }
    iosSimulatorArm64()
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
