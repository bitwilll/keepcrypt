package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Mode
import com.keepcrypt.entropy.ffi.Words

/**
 * One walk to every screen but the stop screen (tasks/todo.md, Stage U's U-3): a fresh Rig brought to the
 * screen a test names, over the real slot, by the path CaptureTest's walk takes on the device (a Mixed
 * seed of 24 words, so Device entropy, the commitment, the device swap and D are on it), each screen
 * reached from the one before it on its branch and checked on arrival. Where a shorter branch reaches a
 * screen with nothing else lost, the walk takes it: the check's screens branch from the check QR, the
 * skipped check's result from Skip's confirm, the watch-only offer from the backup offer's Skip, the
 * watch-only summary from the BIP39 question's No, D's offer from the registration's Skip, the checklist
 * from D's Skip, and Check a backup, Load registry snapshot and About from Home. The stop screen is the
 * halt classes' alone: a halt latches the process's one slot for good. "Working..." is Length's start
 * held on the worker; the start-up self-test's screen is First launch's Continue, held likewise.
 * Check a backup opens SavedBackup.shared, which a ceremony of its own saves before the walk's rig starts.
 * Each picker's answer is followed by the activity's resume, as on the device, which ends the picker
 * rule's exemption (appResumed), so a leaving after it is one.
 */
internal object Walk {
    /** Every screen the walk reaches: every screen but Stop, in the enum's order. */
    val screens: List<Screen> = Screen.entries.filter { it != Screen.Stop }

    /**
     * The Protected screens, as docs/mobile-apps.md:34 lists them (the Pi's list): the words in insert view
     * and overview, the read-back entry and mismatch, the backup passphrase and its confirm, the BIP39
     * passphrase's and Check a backup's passphrase entry, D, the registration QR, the collision-report QR,
     * and the account and descriptor QRs. The every-screen tests take what they expect from this list, not
     * from the model's isProtected, which LeavingTest checks against it.
     */
    val protected: Set<Screen> = setOf(
        Screen.Words, Screen.WordsOverview, Screen.ReadbackEntry, Screen.ReadbackMismatch, Screen.BackupPassphrase,
        Screen.BackupConfirm, Screen.Bip39Entry, Screen.BackupCheckEntry, Screen.RevealD, Screen.RegisterQr,
        Screen.CollisionReport, Screen.WatchAccountQr, Screen.WatchDescriptorQr,
    )

    /**
     * The screens the walk enters through a privacy gate: each Protected screen entered from a Public one
     * (the device swap's second gate is passed on the way to the read-back). The Protected screens entered
     * from a Protected one (the overview, the read-back entry and mismatch, the backup's confirm and the
     * descriptor QR) show none.
     */
    val gated: Set<Screen> = setOf(
        Screen.CollisionReport, Screen.Words, Screen.BackupPassphrase, Screen.Bip39Entry, Screen.WatchAccountQr,
        Screen.RegisterQr, Screen.RevealD, Screen.BackupCheckEntry,
    )

    /** How one screen is reached: from the screen before it on its branch (none for First launch), by go. */
    private class Step(val from: Screen?, val go: (Rig) -> Unit)

    private val steps: Map<Screen, Step> = mapOf(
        Screen.FirstLaunch to Step(null) {},
        Screen.SelfTest to Step(Screen.FirstLaunch) { it.model.firstLaunchDone() },
        Screen.GoOffline to Step(Screen.SelfTest) { it.worker.run() },
        Screen.Home to Step(Screen.GoOffline) { it.model.startOffline() },
        Screen.Length to Step(Screen.Home) { it.model.chooseMode(Mode.Mixed) },
        Screen.Working to Step(Screen.Length) { it.model.chooseLength(Words.TwentyFour) },
        Screen.DeviceEntropy to Step(Screen.Working) { it.worker.run() },
        Screen.Commitment to Step(Screen.DeviceEntropy) { it.model.deviceEntropyDone() },
        Screen.Dice to Step(Screen.Commitment) { it.model.commitmentDone() },
        Screen.CheckPrompt to Step(Screen.Dice) {
            it.roll(99)
            it.model.diceDone()
            it.worker.run()
        },
        Screen.SkipConfirm to Step(Screen.CheckPrompt) { it.model.skip() },
        Screen.SealCard to Step(Screen.CheckPrompt) { it.model.checkNow() },
        Screen.CheckQr to Step(Screen.SealCard) { it.model.showCheckQr() },
        Screen.Scan to Step(Screen.CheckQr) { it.model.scanQr() },
        Screen.CodeEntry to Step(Screen.CheckQr) { it.model.typeCode() },
        Screen.MatchFoundConfirm to Step(Screen.CheckQr) { it.model.matchFound() },
        Screen.CannotCheckConfirm to Step(Screen.CheckQr) { it.model.cannotCheck() },
        Screen.Collision to Step(Screen.MatchFoundConfirm) { it.model.matchFoundConfirmed() },
        Screen.CollisionReport to Step(Screen.Collision) { it.model.showReport() },
        Screen.CheckResult to Step(Screen.SkipConfirm) { it.model.skipConfirmed() },
        Screen.Words to Step(Screen.CheckResult) { it.model.showWords() },
        Screen.WordsOverview to Step(Screen.Words) { it.model.toOverview() },
        Screen.DeviceSwap to Step(Screen.WordsOverview) { rig -> repeat(INSERTS_PER_DEVICE / OVERVIEW_WORDS) { rig.model.nextPage() } },
        Screen.ReadbackEntry to Step(Screen.DeviceSwap) { rig ->
            rig.model.swapDone()
            rig.model.passGate()
            rig.model.toInsertView()
            repeat(INSERTS_PER_DEVICE - 1) { rig.model.nextPage() }
            rig.model.startReadback()
        },
        Screen.ReadbackMismatch to Step(Screen.ReadbackEntry) { rig ->
            rig.press("zzzz")
            rig.model.readbackTyped()
        },
        Screen.ReadbackDone to Step(Screen.ReadbackEntry) { rig ->
            repeat(2 * INSERTS_PER_DEVICE) {
                readBackShown(rig)
                rig.model.readbackNext()
            }
        },
        Screen.Wallet to Step(Screen.ReadbackDone) { it.model.showSummary() },
        Screen.BackupOffer to Step(Screen.Wallet) { it.model.summaryDone() },
        Screen.BackupPassphrase to Step(Screen.BackupOffer) { it.model.makeBackup() },
        Screen.BackupConfirm to Step(Screen.BackupPassphrase) { rig ->
            rig.model.nextPage()
            rig.model.passphraseWritten()
        },
        Screen.BackupSave to Step(Screen.BackupPassphrase) { rig ->
            val words = rig.passphraseWords().toMutableList()
            rig.model.nextPage()
            words.addAll(rig.passphraseWords())
            rig.model.passphraseWritten()
            rig.confirm(words)
        },
        Screen.BackupVerified to Step(Screen.BackupSave) { rig ->
            rig.model.saveBackup(FakePickers())
            rig.model.backupPlaced(FakePlace())
            rig.model.appResumed()
            rig.worker.run()
        },
        Screen.WatchOffer to Step(Screen.BackupOffer) { it.model.skipBackup() },
        Screen.Bip39Ask to Step(Screen.WatchOffer) { it.model.showWatchOnly() },
        Screen.Bip39Entry to Step(Screen.Bip39Ask) { it.model.withBip39Passphrase() },
        Screen.WatchSummary to Step(Screen.Bip39Ask) { it.model.noBip39Passphrase() },
        Screen.WatchAccountQr to Step(Screen.WatchSummary) { it.model.watchSummaryDone() },
        Screen.WatchDescriptorQr to Step(Screen.WatchAccountQr) { it.model.nextPage() },
        Screen.RegisterOffer to Step(Screen.WatchDescriptorQr) { it.model.watchDone() },
        Screen.RegisterQr to Step(Screen.RegisterOffer) { it.model.showRegistration() },
        Screen.RevealDOffer to Step(Screen.RegisterOffer) { it.model.skipRegistration() },
        Screen.RevealD to Step(Screen.RevealDOffer) { it.model.showDeviceLeg() },
        Screen.Checklist to Step(Screen.RevealDOffer) { it.model.skipDeviceLeg() },
        Screen.BackupCheckEntry to Step(Screen.Home) { rig ->
            val saved = SavedBackup.shared
            rig.model.checkBackup(FakePickers())
            rig.model.backupPicked(FakeFile(SavedBackup.NAME, saved.file.size.toLong(), saved.file))
            rig.model.appResumed()
            rig.worker.run()
        },
        Screen.BackupCheckResult to Step(Screen.BackupCheckEntry) { rig ->
            for (word in SavedBackup.shared.passphrase) {
                rig.press(word.take(4))
                rig.model.entryTyped()
            }
            rig.worker.run()
        },
        Screen.BackupRecheck to Step(Screen.BackupCheckResult) { it.model.showRecheck() },
        Screen.Snapshot to Step(Screen.Home) { rig ->
            val bytes = kcrSnapshot(SNAPSHOT)
            rig.model.loadSnapshot(FakePickers())
            rig.model.snapshotPicked(FakeFile("$SNAPSHOT.kcr", bytes.size.toLong(), bytes))
            rig.model.appResumed()
            rig.worker.run()
        },
        Screen.About to Step(Screen.Home) { it.model.about() },
    )

    /**
     * States of the words' screens the walk's screens do not name, each a fresh Rig in that state (Stage
     * U's U2b2): the second privacy gate a 24-word seed's device swap leads to (device 2's overview);
     * Check a backup's words on their gate and past it; and an insert reviewed from a read-back mismatch
     * (Words, its one way on back to its read-back). All are Protected screens.
     */
    val states: List<Pair<String, () -> Rig>> = listOf(
        "the device swap's second gate" to {
            val rig = to(Screen.DeviceSwap)
            rig.model.swapDone()
            check(rig.screen == Screen.WordsOverview && rig.model.state.value.gate) { "the second gate did not show" }
            rig
        },
        "Check a backup's words on their gate" to { checkedWords(gate = true) },
        "Check a backup's words" to { checkedWords(gate = false) },
        "an insert reviewed from a mismatch" to {
            val rig = to(Screen.ReadbackMismatch)
            rig.model.reviewInsert()
            check(rig.screen == Screen.Words && rig.model.state.value.reviewing) { "the insert was not reviewed" }
            rig
        },
    )

    /** Check a backup's words, insert 1, on their privacy gate or past it. */
    private fun checkedWords(gate: Boolean): Rig {
        val rig = to(Screen.BackupCheckResult)
        rig.model.showBackupWords()
        val state = rig.model.state.value
        check(state.screen == Screen.Words && state.opened != null && state.gate) { "Check a backup's words did not show their gate" }
        if (!gate) rig.model.passGate()
        return rig
    }

    /** kcr.json's snapshot Load registry snapshot's result shows, loaded. */
    private const val SNAPSHOT = "with-dice-50"

    /**
     * A fresh Rig on screen (any but Stop), its long calls run but "Working..."'s and the self-test's own:
     * past the privacy gate, or on it when gate (a screen of gated). Every screen on the way is checked as
     * it shows, its gate with it (shown on gated's alone), and passed through its gate.
     */
    fun to(screen: Screen, gate: Boolean = false): Rig {
        require(screen != Screen.Stop) { "the stop screen is the halt classes' alone" }
        require(!gate || screen in gated) { screenId(screen) + " is entered with no privacy gate" }
        if (Screen.BackupCheckEntry in path(screen)) SavedBackup.shared
        val rig = reach(screen)
        val shown = rig.model.state.value.gate
        check(shown == (screen in gated)) { screenId(screen) + (if (shown) ": a privacy gate showed" else ": its privacy gate did not show") }
        if (!gate && shown) rig.model.passGate()
        return rig
    }

    /** The screens from First launch to screen on its branch, screen last. */
    private fun path(screen: Screen): List<Screen> {
        val before = steps.getValue(screen).from ?: return listOf(screen)
        return path(before) + screen
    }

    /** A fresh Rig on screen, by its branch, each screen checked as it shows and passed through its gate on the way. */
    private fun reach(screen: Screen): Rig {
        val step = steps.getValue(screen)
        val rig = step.from?.let(::to) ?: Rig().startUp()
        step.go(rig)
        check(rig.screen == screen) { "the walk to " + screenId(screen) + " reached " + screenId(rig.screen) }
        return rig
    }

    /**
     * On the read-back entry, the insert on show read back: its word's first four letters (a three-letter
     * word's three), read from the page the state holds through a copy wiped at once and pressed on the
     * pad, then Done.
     */
    private fun readBackShown(rig: Rig) {
        val word = checkNotNull(rig.model.state.value.insert).word()
        val letters = String(CharArray(minOf(4, word.size)) { Char(word[it].toInt()) })
        word.wipe()
        rig.press(letters)
        rig.model.readbackTyped()
    }
}
