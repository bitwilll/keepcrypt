package com.keepcrypt.entropy.screens

import androidx.compose.runtime.Composable
import com.keepcrypt.entropy.ffi.Refusal
import com.keepcrypt.entropy.ffi.RefusalGroup
import com.keepcrypt.entropy.ffi.RegistryHeader

// Home's Load registry snapshot and About (tasks/todo.md, M5 groups 15 and 18; lead decision M5-48;
// docs/mobile-apps.md, step 4 and "Reading a snapshot"; the Pi's wording, pi/app's screens/usb.rs and
// screens.rs, wherever those say nothing else): the result of a snapshot's load, the snapshot's number,
// date, count and any freshness warning, or why core refused it (the shipping APK trusts no registry key
// yet), and About, the version, this build's flavour and the source address as plain text. Both are
// Public, and each hands its presses to the ceremony model, which ignores a press its screen no longer
// shows.

/** The app's version: every M5 APK is a development build (tasks/todo.md, M5 "Built into this plan"). */
const val APP_VERSION = "0.0.0"

/** First launch's and About's line for every M5 APK ("Built into this plan": a development build). */
const val DEVELOPMENT_BUILD = "$APP_VERSION development build: do not use for real funds."

/** Where the source is (docs/pi-firmware.md, "Build, flash and verify"), shown as plain text: no link opens anything. */
const val SOURCE_ADDRESS = "https://github.com/bitwilll/keepcrypt"

/** The security address (SECURITY.md), as the Pi's About shows it. */
const val SECURITY_ADDRESS = "admin@keepcrypt.com"

/** A loaded snapshot's result (the Pi's snapshot-loaded, for a phone, which warns by date itself, swb:120). */
const val SNAPSHOT_LOADED_NOTE = "Check now runs the check against it on its own. It stays loaded until the app closes."

/** Core's text before a snapshot error's (core/src/error.rs, CoreError::Snapshot's Display). */
const val SNAPSHOT_REJECTED = "registry snapshot or proof rejected: "

/** A build that pins no registry key (the shipping APK until M9), as the scan screen says it (Q60). */
const val SNAPSHOT_NO_REGISTRY_KEY = "This build trusts no registry key yet, so it cannot load a registry snapshot."

/** Home's snapshot line (the Pi's): the one loaded, by number and date, or that none is. */
fun homeSnapshotLine(loaded: RegistryHeader?): String = if (loaded == null) {
    "No registry snapshot loaded"
} else {
    "Snapshot No. ${loaded.number}, dated ${registryDate(loaded.date)}"
}

/**
 * Core's text for a refusal of a snapshot (core/src/error.rs's Display, verbatim, as the Pi's
 * snapshot-failed shows it; HomeScreensTest pins each against core's source), or the phone's own line
 * for a build with no registry key; null for any other refusal, which loadSnapshot never gives.
 */
fun snapshotRefusalText(refusal: Refusal): String? = when (refusal) {
    Refusal.NoRegistryKey -> SNAPSHOT_NO_REGISTRY_KEY
    Refusal.TooShort -> SNAPSHOT_REJECTED + "too short"
    Refusal.BadMagic -> SNAPSHOT_REJECTED + "wrong magic"
    Refusal.BadVersion -> SNAPSHOT_REJECTED + "unsupported version"
    Refusal.BadSignature -> SNAPSHOT_REJECTED + "bad signature"
    Refusal.BadDate -> SNAPSHOT_REJECTED + "bad date"
    Refusal.TooManyEntries -> SNAPSHOT_REJECTED + "too many entries"
    Refusal.BadLength -> SNAPSHOT_REJECTED + "wrong length"
    Refusal.Unsorted -> SNAPSHOT_REJECTED + "entries out of order"
    Refusal.Duplicate -> SNAPSHOT_REJECTED + "duplicate entry"
    Refusal.ZeroCount -> SNAPSHOT_REJECTED + "zero registration count"
    Refusal.RootMismatch -> SNAPSHOT_REJECTED + "bucket root mismatch"
    Refusal.BucketOutOfRange -> SNAPSHOT_REJECTED + "bucket index out of range"
    Refusal.EntryOutsideBucket -> SNAPSHOT_REJECTED + "entry outside its bucket"
    Refusal.ProofCount -> SNAPSHOT_REJECTED + "more bucket entries than the snapshot holds"
    else -> null
}

/** Whether refusal is one a snapshot's load gives (its text exists): any other is the shell's bug. */
fun isSnapshotRefusal(refusal: Refusal): Boolean = refusal == Refusal.NoRegistryKey || refusal.group == RefusalGroup.Snapshot

/** About's line for this build's flavour (Q60: the test-registry APK is built only in CI and never released). */
fun flavourText(testRegistry: Boolean): String = if (testRegistry) {
    "This build: the TEST REGISTRY app, built only in CI and never released. Registry key: the test key."
} else {
    "This build: the shipping app. Registry key: none pinned in this build yet."
}

/**
 * Load registry snapshot's result (docs/mobile-apps.md, "Reading a snapshot"; the Pi's snapshot-loaded
 * and snapshot-failed), a Public screen: the snapshot loaded, with its number, date and count and any
 * Stale or Future warning, or that it was not loaded and why (core's text, or that this build trusts no
 * registry key yet); Done (and the system Back) returns Home.
 */
@Composable
fun SnapshotResult(state: UiState, testRegistry: Boolean, onDone: () -> Unit) {
    KitScreen(
        screenId(Screen.Snapshot),
        testRegistry,
        actions = { KitButton("Done", "snapshot_done", onClick = onDone) },
    ) {
        Heading("Registry snapshot")
        val refusal = state.snapshotRefusal
        val loaded = state.loaded
        if (refusal != null) {
            KitText("Snapshot not loaded", tag = "snapshot_result")
            KitText(snapshotRefusalText(refusal).orEmpty(), KitType.body.copy(color = KitColors.warning), tag = "snapshot_refusal")
        } else if (loaded != null) {
            KitText("Snapshot loaded", tag = "snapshot_result")
            KitText(snapshotLine(loaded), KitType.small, tag = "snapshot_line")
            val warning = freshnessWarning(loaded.freshness)
            if (warning != null) {
                KitText(warning, KitType.body.copy(color = KitColors.warning), tag = "snapshot_warning")
            }
            KitText(SNAPSHOT_LOADED_NOTE, KitType.small)
        }
    }
}

/**
 * About (docs/mobile-apps.md, step 4; the Pi's About), a Public screen: the app's version, that it is a
 * development build, this build's flavour and its registry key, the source address, the licence and the
 * security address, all plain text (no link: the app opens nothing); Back (and the system Back) returns
 * Home.
 */
@Composable
fun About(testRegistry: Boolean, onBack: () -> Unit) {
    KitScreen(
        screenId(Screen.About),
        testRegistry,
        actions = { KitButton("Back", "back", onClick = onBack) },
    ) {
        Heading("About")
        KitText("KeepCrypt-Entropy", KitType.title)
        Gap(8)
        KitText("Version " + APP_VERSION, tag = "about_version")
        KitText(DEVELOPMENT_BUILD, KitType.body.copy(color = KitColors.warning))
        KitText(flavourText(testRegistry), KitType.small, tag = "about_flavour")
        KitText("Source code", KitType.small)
        KitText(SOURCE_ADDRESS, tag = "about_source")
        KitText("Licence: MIT OR Apache-2.0", KitType.small)
        KitText("Security reports: " + SECURITY_ADDRESS, KitType.small)
    }
}
