package com.keepcrypt.entropy.screens

import java.security.MessageDigest

/** On the JVM: java.security's SHA-256. */
internal actual fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)
