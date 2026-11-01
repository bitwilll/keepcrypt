package com.keepcrypt.entropy.screens

/**
 * SHA-256 of bytes, for the tests that check a value the screens show against its definition (D's
 * screen against C: C = SHA-256("KCE/v1/commit" || D), CLAUDE.md's domain constants): common Kotlin has
 * no digest, so it is a test-only expect with its actual in androidHostTest, as entropyFile is (lead
 * decision M5-43).
 */
internal expect fun sha256(bytes: ByteArray): ByteArray
