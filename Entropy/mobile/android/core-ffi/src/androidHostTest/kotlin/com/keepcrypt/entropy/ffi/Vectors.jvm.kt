package com.keepcrypt.entropy.ffi

import java.io.File

/** On the JVM: the file at path under Entropy/, whose path core-ffi/build.gradle.kts sets in kc.entropy. */
internal actual fun entropyFile(path: String): String =
    File(checkNotNull(System.getProperty("kc.entropy")) { "core-ffi/build.gradle.kts sets kc.entropy" }, path)
        .readText(Charsets.UTF_8)
