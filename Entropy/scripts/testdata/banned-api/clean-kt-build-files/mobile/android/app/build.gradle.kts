plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}
android {
    namespace = "com.keepcrypt.app"
    compileSdk = 37
    ndkVersion = "30.0.16248370"
    sourceSets["main"].kotlin.srcDir("src/main/kotlin")
    sourceSets["main"].java.srcDirs( "src/main/java" )
}
dependencies {
    implementation(project(":core-ffi"))
    implementation(libs.androidx.activity.compose)
    implementation("com.google.zxing:core:3.5.4")
}
configurations.all { exclude(group = "androidx.profileinstaller") }
if (providers.gradleProperty("kc.canary").orNull == "true") {
    dependencies {
        implementation(project(":canary-lib"))
    }
}
