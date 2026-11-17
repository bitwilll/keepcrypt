if (System.getProperty("kc.canary") == "true") {
    dependencies { implementation(project(":canary-lib")) }
}
