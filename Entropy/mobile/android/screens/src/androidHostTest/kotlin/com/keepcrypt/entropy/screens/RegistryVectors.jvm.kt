package com.keepcrypt.entropy.screens

import java.io.File

/** On the JVM: the file at path under Entropy/, whose path screens/build.gradle.kts sets in kc.entropy. */
internal actual fun entropyFile(path: String): String =
    File(checkNotNull(System.getProperty("kc.entropy")) { "screens/build.gradle.kts sets kc.entropy" }, path)
        .readText(Charsets.UTF_8)
