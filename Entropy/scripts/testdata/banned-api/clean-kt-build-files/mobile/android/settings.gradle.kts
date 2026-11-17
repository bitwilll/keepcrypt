pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("androidx.*")
                includeGroupByRegex("com[.]android.*")
                includeGroupByRegex("com[.]google.*")
            }
        }
        mavenCentral()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "keepcrypt"
include(":app", ":core-ffi", ":secure-ui", ":capture-control")

if (providers.gradleProperty("kc.canary").orNull == "true") {
    include(":canary-lib")
    project(":canary-lib").projectDir = file("../../scripts/testdata/android-canary-lib")
}
