// :core-ffi, Kotlin Multiplatform: the gate's clean case of the re-plan's KMP build lines (tasks/todo.md, M5).

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
    iosArm64 {
        compilations.getByName("main").cinterops.create("keepcrypt") {
            compilerOpts("-I$rootDir/../../ffi/capi/include")
        }
        binaries.getTest("DEBUG").linkerOpts("$rootDir/../../target/ios-test/aarch64-apple-ios/release/libkeepcrypt_capi.a")
    }
    iosSimulatorArm64 {
        compilations.getByName("main").cinterops.create("keepcrypt") {
            compilerOpts("-I$rootDir/../../ffi/capi/include")
        }
        binaries.getTest("DEBUG").linkerOpts("$rootDir/../../target/ios-test/aarch64-apple-ios-sim/release/libkeepcrypt_capi.a")
        testRuns["test"].deviceId = "iPhone 16 Pro"
    }
    sourceSets {
        commonTest.dependencies {
            implementation(libs.kotlin.test)
        }
    }
}

tasks.withType<Test>().configureEach {
    forkEvery = 1
}
