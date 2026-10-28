// :capture-control (tasks/todo.md, M5 groups 4 and 6): the capture tests' positive control, built
// only in CI and never uploaded or released. It draws the app's composables (from :screens, with
// :secure-ui's theme and backup rules) with no FLAG_SECURE, so the same screencap, UiAutomation and
// raw-frame calls must find its pixels; a missing control fails the job. Its words page is a gate
// seed's page from vectors/, made as :core-ffi's WordPage (lead decision M5-68 (f)); it has no
// native library. Its own app id; :app never depends on it. Release build type, not debuggable,
// with the app's reproducibility settings (and, as there, no lint until M7).

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.keepcrypt.entropy.capturecontrol"
    compileSdk = libs.versions.android.compile.sdk.get().toInt()
    buildToolsVersion = libs.versions.android.build.tools.get()
    ndkVersion = libs.versions.android.ndk.get()
    defaultConfig {
        applicationId = "com.keepcrypt.entropy.capturecontrol"
        minSdk = libs.versions.android.min.sdk.get().toInt()
        targetSdk = libs.versions.android.target.sdk.get().toInt()
        versionCode = 1
        versionName = "0.0.0"
        // Exactly MA:23's three ABIs (lead decision M5-10): a library's native code for any other
        // (graphics-path's x86 copy) stays out of the APK.
        ndk {
            abiFilters.addAll(listOf("arm64-v8a", "armeabi-v7a", "x86_64"))
        }
    }
    buildTypes {
        release {
            isDebuggable = false
            isMinifyEnabled = false
            isShrinkResources = false
            isCrunchPngs = false
            vcsInfo {
                include = false
            }
        }
    }
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
    }
    lint {
        checkReleaseBuilds = false
    }
}

tasks.configureEach {
    if (name.contains("ArtProfile")) {
        enabled = false
    }
}

dependencies {
    implementation(project(":core-ffi"))
    implementation(project(":screens"))
    implementation(project(":secure-ui"))
    implementation(platform(libs.compose.bom))
    implementation(libs.activity.compose)
    implementation(libs.compose.foundation)
}
