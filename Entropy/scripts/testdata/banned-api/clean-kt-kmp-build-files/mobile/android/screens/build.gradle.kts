// :screens, Kotlin Multiplatform: every screen, written once (the gate's clean case, tasks/todo.md, M5).

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
        withHostTestBuilder {
        }
    }
    iosArm64 {
        binaries.framework {
            baseName = "KeepCryptScreens"
            isStatic = true
        }
        binaries.getTest("DEBUG").linkerOpts("$rootDir/../../target/ios-test/aarch64-apple-ios/release/libkeepcrypt_capi.a")
    }
    iosSimulatorArm64()
    sourceSets {
        commonMain.dependencies {
            implementation(project(":core-ffi"))
            implementation(libs.compose.runtime)
            implementation(libs.compose.foundation)
            implementation(libs.compose.ui)
        }
        iosMain.dependencies {
        }
        iosTest.dependencies {
        }
    }
}
