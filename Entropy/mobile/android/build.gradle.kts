// The root build file (tasks/todo.md, M5 group 4). The plugins are put on the build's classpath
// here, once, at their catalog versions, and applied by the modules. The Android Gradle plugin 9
// compiles Kotlin itself (its built-in Kotlin), so no module applies org.jetbrains.kotlin.android:
// it is listed only so that the Kotlin compiler is the catalog's 2.4.20, the same version as the
// Compose compiler plugin, whatever version the Android Gradle plugin itself depends on. The shared
// modules, :core-ffi and :screens, apply Kotlin Multiplatform and the Android Gradle plugin's plugin
// for its Android target (the re-plan for Compose Multiplatform; lead decision M5-7's pattern).

import org.gradle.api.artifacts.dsl.LockMode

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.kotlin.multiplatform) apply false
    alias(libs.plugins.android.kotlin.multiplatform.library) apply false
}

subprojects {
    // profileinstaller writes files into the app's own storage at start (rule 8), so no
    // configuration of any module has it (the androidx.startup provider that would start the
    // other libraries' initializers is removed in each app's manifest).
    configurations.configureEach {
        exclude(group = "androidx.profileinstaller", module = "profileinstaller")
    }
    // Every configuration is locked, strictly: a configuration with no lock state in the module's
    // gradle.lockfile fails the build, and so does one that resolves to anything else (group 4;
    // scripts/android-deps-review.py reviews the lockfiles with gradle/verification-metadata.xml).
    dependencyLocking {
        lockAllConfigurations()
        lockMode.set(LockMode.STRICT)
    }
}
