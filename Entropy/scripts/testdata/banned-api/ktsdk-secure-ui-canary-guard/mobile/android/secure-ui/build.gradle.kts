if (providers.gradleProperty("kc.canary").orNull == "true") {
    dependencies { implementation(project(":canary-lib")) }
}
