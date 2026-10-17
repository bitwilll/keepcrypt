// The root build file (tasks/todo.md, M5 group 4). The plugins are put on the build's classpath
// here, once, at their catalog versions, and applied by the modules. The Android Gradle plugin 9
// compiles Kotlin itself (its built-in Kotlin), so no module applies org.jetbrains.kotlin.android:
// it is listed only so that the Kotlin compiler is the catalog's 2.4.20, the same version as the
// Compose compiler plugin, whatever version the Android Gradle plugin itself depends on.

import org.gradle.api.artifacts.dsl.LockMode

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.compose) apply false
}

// The bootstrap switch (group 4, commit 5 only): the Android workflow's one run with
// -Pkc.bootstrap=true writes the lockfiles and gradle/verification-metadata.xml, which commit 6
// commits after review, with strict locking off (no lock state exists yet) and verification off (no
// metadata file exists yet). Any other value, or none, is strict. Commit 6 removes the switch,
// and a gate rule then fails if kc.bootstrap appears at all.
val kcBootstrap = providers.gradleProperty("kc.bootstrap").orNull == "true"

subprojects {
    // profileinstaller writes files into the app's own storage at start (rule 8), so no
    // configuration of any module has it (the androidx.startup provider that would start the
    // other libraries' initializers is removed in each app's manifest).
    configurations.configureEach {
        exclude(group = "androidx.profileinstaller", module = "profileinstaller")
    }
    // Every configuration is locked; strict from commit 6 on, so an unlocked configuration fails.
    dependencyLocking {
        lockAllConfigurations()
        lockMode.set(if (kcBootstrap) LockMode.DEFAULT else LockMode.STRICT)
    }
}
