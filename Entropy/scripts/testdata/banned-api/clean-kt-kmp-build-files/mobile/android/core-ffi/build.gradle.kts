// :core-ffi, Kotlin Multiplatform: the gate's clean case of the KMP build lines, the Android target alone (tasks/todo.md, M5, Q73).

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
        getByName("androidHostTest").dependencies {
            implementation(libs.junit)
        }
    }
}

tasks.withType<Test>().configureEach {
    forkEvery = 1
}
