if (providers.gradleProperty("kc.canary").orNull == "true") {
    include(":canary-lib")
    include(":helper")
    project(":canary-lib").projectDir = file("../../scripts/testdata/android-canary-lib")
}
