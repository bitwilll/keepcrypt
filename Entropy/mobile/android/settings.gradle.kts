// The KeepCrypt Android project (tasks/todo.md, M5 groups 4 and 13-18; docs/mobile-apps.md,
// "Architecture"). Run it only through scripts/android-gradle.sh, which fetches Gradle 9.7.1 by a
// pinned SHA-256 (there is no wrapper jar in git).
//
// Two repositories, declared here and nowhere else (Q54; the gate's KtSdk rule refuses a
// repositories block in any other build file, and FAIL_ON_PROJECT_REPOS fails the build if a
// project adds one): Google's Maven, searched only for the androidx, com.android and com.google
// groups, and Maven Central. No Gradle plugin portal: both plugins come from these two (the Android
// Gradle plugin from Google's Maven, the Kotlin ones from Maven Central). The bare com.android
// group is included with its subgroups, since the Android Gradle plugin's own libraries use it.

pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("androidx\\..*")
                includeGroupByRegex("com\\.android(\\..*)?")
                includeGroupByRegex("com\\.google\\..*")
            }
        }
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google {
            content {
                includeGroupByRegex("androidx\\..*")
                includeGroupByRegex("com\\.android(\\..*)?")
                includeGroupByRegex("com\\.google\\..*")
            }
        }
        mavenCentral()
    }
}

rootProject.name = "keepcrypt-android"

// MA:24's four modules, :screens holding the screens both phones share (the re-plan for Compose
// Multiplatform), and the CI-only positive control of the capture tests (group 6), which :app never
// depends on.
include(":core-ffi", ":screens", ":secure-ui", ":app", ":capture-control")

// The canary build only (tasks/todo.md, M5 group 5): the Gradle property the if below reads, set to
// true with -P, adds the canary library, scripts/testdata/android-canary-lib, which :app then depends
// on (app/build.gradle.kts); its manifest asks for INTERNET and declares a provider, and the Android
// workflow requires scripts/banned-api-check.sh --apk to refuse that APK. No real build sets the
// property: the gate's KtSdk rule allows its name only in this if line, app/build.gradle.kts's and
// the workflow's canary command, and a project from outside mobile/android only as this block has it.
if (providers.gradleProperty("kc.canary").orNull == "true") {
    include(":canary-lib")
    project(":canary-lib").projectDir = file("../../scripts/testdata/android-canary-lib")
}
