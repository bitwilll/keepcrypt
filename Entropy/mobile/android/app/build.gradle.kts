// :app (tasks/todo.md, M5 groups 4, 5 and 15-18; Q60, Q62; the re-plan for Compose
// Multiplatform): MainActivity over the shared screens of :screens, the holder of their ceremony
// model, the pickers and the scanner. Two flavours, both built only as the release build type and
// neither debuggable: shipping (com.keepcrypt.entropy, the APK the owner installs) and withTestRegistry,
// the plan's test-registry APK (com.keepcrypt.entropy.testregistry, built only in CI and never
// released; labelled "KeepCrypt TEST REGISTRY" with a strip on every screen). The Android Gradle
// plugin refuses a flavour name that starts with "test", hence "with". The instrumented tests run
// against the release build type too, so they test the bytes that ship. Every M5 APK is a 0.0.0
// development build.
//
// Reproducibility groundwork (M5 "Built into this plan"; the two-build comparison is M7): no
// dependency or VCS block in the APK, no R8, no PNG crunching and no baseline profile. Android
// lint is M7 too, so release builds do not run its vital checks yet.

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.keepcrypt.entropy"
    compileSdk = libs.versions.android.compile.sdk.get().toInt()
    buildToolsVersion = libs.versions.android.build.tools.get()
    ndkVersion = libs.versions.android.ndk.get()
    defaultConfig {
        applicationId = "com.keepcrypt.entropy"
        minSdk = libs.versions.android.min.sdk.get().toInt()
        targetSdk = libs.versions.android.target.sdk.get().toInt()
        versionCode = 1
        versionName = "0.0.0"
        // Exactly MA:23's three ABIs (lead decision M5-10): a library's native code for any other
        // (graphics-path's x86 copy) stays out of the APK.
        ndk {
            abiFilters.addAll(listOf("arm64-v8a", "armeabi-v7a", "x86_64"))
        }
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }
    flavorDimensions += "registry"
    productFlavors {
        create("shipping") {
            dimension = "registry"
            applicationId = "com.keepcrypt.entropy"
        }
        create("withTestRegistry") {
            dimension = "registry"
            applicationId = "com.keepcrypt.entropy.testregistry"
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
    testBuildType = "release"
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
    // libkeepcrypt.so is packaged as scripts/android-rust.sh built and scanned it, symbol table and
    // all: banned-api-check.sh --apk requires the APK's copy to be those bytes, and the release
    // artifact scan refuses a stripped library. Any other library is stripped with the pinned NDK.
    packaging {
        jniLibs {
            keepDebugSymbols += "**/libkeepcrypt.so"
        }
    }
}

// No baseline profile in the APK (assets/dexopt/): its tasks are switched off, as F-Droid's
// reproducible-builds guide does.
tasks.configureEach {
    if (name.contains("ArtProfile")) {
        enabled = false
    }
}

// The Rust library (M5 group 4, lead decision M5-9): scripts/android-rust.sh <flavour> copies
// libkeepcrypt.so for MA:23's three ABIs into src/<flavour>/jniLibs/<abi>/, Gradle's default
// native-library source set, and Gradle never builds Rust. A flavour without all three fails its
// native-library merge, so no APK is made without them.
val rustLibraries = listOf("shipping", "withTestRegistry").associateWith { flavour ->
    listOf("arm64-v8a", "armeabi-v7a", "x86_64").map { abi ->
        layout.projectDirectory.file("src/$flavour/jniLibs/$abi/libkeepcrypt.so").asFile
    }
}
tasks.configureEach {
    for ((flavour, libraries) in rustLibraries) {
        if (name == "merge" + flavour.replaceFirstChar { it.uppercase() } + "ReleaseNativeLibs") {
            doFirst {
                if (libraries.any { !it.isFile }) {
                    throw GradleException("libkeepcrypt.so is missing for one of the three ABIs: run scripts/android-rust.sh first")
                }
            }
        }
    }
}

// The JVM tests (group 13): GoAheadPngTest reads vectors/kcr.json under kc.entropy (Entropy/) and
// writes the P4 drill's two go-ahead PNGs into kc.p4 (build/p4/), which the Android workflow uploads.
val entropy = rootDir.resolve("../..").canonicalPath
val p4 = layout.buildDirectory.dir("p4").get().asFile.path
tasks.withType<Test>().configureEach {
    systemProperty("kc.entropy", entropy)
    systemProperty("kc.p4", p4)
}

dependencies {
    implementation(project(":core-ffi"))
    implementation(project(":screens"))
    implementation(project(":secure-ui"))
    implementation(platform(libs.compose.bom))
    implementation(libs.activity.compose)
    implementation(libs.compose.foundation)
    // The go-ahead QR decoder of the camera scanner (group 16): its decode step from commit 14, the
    // camera from commit 18; ZXing's writer draws the go-ahead PNGs in the JVM tests alone.
    implementation(libs.zxing.core)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.core)
    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.uiautomator)
    androidTestImplementation(libs.junit)
}

// The canary build only (tasks/todo.md, M5 group 5): with the property the if below reads set to
// true (settings.gradle.kts) the app also takes the canary library, whose manifest asks for INTERNET
// and declares a provider, so that the Android workflow can prove scripts/banned-api-check.sh --apk
// refuses such an APK.
if (providers.gradleProperty("kc.canary").orNull == "true") {
    dependencies {
        implementation(project(":canary-lib"))
    }
}
