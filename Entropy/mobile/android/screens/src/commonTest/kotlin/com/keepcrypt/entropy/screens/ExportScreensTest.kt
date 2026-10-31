package com.keepcrypt.entropy.screens

import com.keepcrypt.entropy.ffi.Core
import com.keepcrypt.entropy.ffi.QrMatrix
import com.keepcrypt.entropy.ffi.Reply
import com.keepcrypt.entropy.ffi.Secret
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * The CeremonyModel transitions of the exports after the backup (tasks/todo.md, M5 group 18;
 * docs/mobile-apps.md, steps 14-16; docs/seal-watchonly-braille.md, "Watch-only export" and "Registering
 * a new seal"; the Pi's steps 12-14), over the real slot through Core and the host library: from the
 * backup's Skip, the watch-only offer (Public), whose Skip and the registration's Skip lead to the
 * checklist with no D offer for a dice-only seed; "No BIP39 passphrase": core's export, its summary
 * (Public) the wallet summary's, the account QR behind the privacy gate and the descriptor QR, each core's
 * own, paged back and on, then wiped as the registration's offer comes; a BIP39 passphrase typed on the
 * ASCII pad (Protected, through the gate), Back to the question wiping it, Done with none typed doing
 * nothing, and its export that passphrase's wallet's, core's; the registration QR behind the gate, core's,
 * once, then D's offer in Mixed mode; D behind the gate, 16 groups of 4 hex digits whose SHA-256 under
 * "KCE/v1/commit" is the C the commitment screen showed, wiped as the checklist comes; leaving the app on
 * each Protected export discarding at once with what it showed wiped; and wipeAll (the BIP39 passphrase
 * typed too). The exports' values are compared in-process and never printed. Each test leaves the slot at
 * home.
 */
class ExportScreensTest {
    @AfterTest
    fun emptyTheSlot() {
        assertTrue(Core.wipeAll() is Reply.Done)
    }

    private fun assertNoSession(message: String) {
        assertTrue(Core.selfTest() is Reply.Done, message)
    }

    private fun <T> done(reply: Reply<T>, what: String): T = when (reply) {
        is Reply.Done -> reply.value
        else -> fail(what + " was not done")
    }

    /** Whether two matrices have the same modules (the same QR code's text), compared in-process. */
    private fun sameModules(a: QrMatrix, b: QrMatrix): Boolean =
        a.side == b.side && (0 until a.side).all { y -> (0 until a.side).all { x -> a.isDark(x, y) == b.isDark(x, y) } }

    /** Whether a matrix was wiped: no dark module left. */
    private fun blank(matrix: QrMatrix): Boolean = (0 until matrix.side).all { y -> (0 until matrix.side).none { x -> matrix.isDark(x, y) } }

    /** Whether a Secret was wiped: every byte zero. */
    private fun blank(secret: Secret): Boolean = (0 until secret.size).all { secret[it] == 0.toByte() }

    /** A new model at dice-50-words12's watch-only offer, the backup skipped. */
    private fun atWatchOffer(): Rig {
        val rig = Rig().toHome().toSummary(DICE_50)
        rig.model.summaryDone()
        rig.model.skipBackup()
        assertEquals(Screen.WatchOffer, rig.screen)
        return rig
    }

    /** A new model at a mixed 12-word seed's watch-only offer, the backup skipped; C as its commitment screen showed it. */
    private fun atMixedWatchOffer(): Pair<Rig, String> {
        val rig = Rig().toHome()
        val commitment = rig.toMixedSummary()
        rig.model.summaryDone()
        rig.model.skipBackup()
        assertEquals(Screen.WatchOffer, rig.screen)
        return rig to commitment
    }

    @Test
    fun theOffersArePublicAndTheirSkipsLeadADiceOnlySeedToTheChecklistWithNoD() {
        val rig = atWatchOffer()
        val offer = rig.model.state.value
        assertFalse(isProtected(Screen.WatchOffer))
        assertFalse(offer.gate)
        rig.model.back()
        assertSame(offer, rig.model.state.value, "Back does nothing on the watch-only offer")
        rig.model.skipWatchOnly()
        val register = rig.model.state.value
        assertEquals(Screen.RegisterOffer, register.screen)
        assertFalse(isProtected(Screen.RegisterOffer))
        assertNull(register.watch, "no export was made")
        rig.model.back()
        assertSame(register, rig.model.state.value, "Back does nothing on the registration's offer")
        rig.model.skipRegistration()
        assertEquals(Screen.Checklist, rig.screen, "a dice-only seed has no D: the registration leads to the checklist")
        rig.model.finishCeremony()
        assertEquals(Screen.Home, rig.screen)
        assertNoSession("Finish after the exports' Skips ended the session")
    }

    @Test
    fun noBip39PassphraseExportsThisSeedsWalletItsQrsCoresBehindTheGateThenWiped() {
        val rig = atWatchOffer()
        val wallet = done(Core.summary(), "the wallet summary")
        rig.model.showWatchOnly()
        val ask = rig.model.state.value
        assertEquals(Screen.Bip39Ask, ask.screen)
        assertFalse(isProtected(Screen.Bip39Ask))
        rig.model.back()
        assertSame(ask, rig.model.state.value, "Back does nothing on the question")
        rig.model.noBip39Passphrase()
        val summary = rig.model.state.value
        assertEquals(Screen.WatchSummary, summary.screen)
        assertFalse(isProtected(Screen.WatchSummary), "the watch-only summary is Public, as the Pi's (Q29)")
        val watch = assertNotNull(summary.watch)
        assertFalse(watch.passphraseUsed)
        assertContentEquals(wallet.fingerprint, watch.summary.fingerprint, "no passphrase: this seed's wallet")
        assertEquals(wallet.firstAddress, watch.summary.firstAddress)
        rig.model.back()
        assertSame(summary, rig.model.state.value, "Back does nothing on the watch-only summary")
        rig.model.watchSummaryDone()
        val account = rig.model.state.value
        assertEquals(Screen.WatchAccountQr, account.screen)
        assertTrue(isProtected(Screen.WatchAccountQr))
        assertTrue(account.gate, "the account QR shows through the privacy gate")
        rig.model.nextPage()
        assertSame(account, rig.model.state.value, "Next behind the gate does nothing")
        rig.model.passGate()
        assertSame(watch, rig.model.state.value.watch)
        val core = done(Core.watchOnly(null), "core's export, again")
        assertTrue(sameModules(core.account, watch.account), "the account QR is core's")
        assertTrue(sameModules(core.descriptors, watch.descriptors), "the descriptor QR is core's")
        core.wipe()
        rig.model.nextPage()
        val descriptor = rig.model.state.value
        assertEquals(Screen.WatchDescriptorQr, descriptor.screen)
        assertTrue(isProtected(Screen.WatchDescriptorQr))
        assertFalse(descriptor.gate, "Protected to Protected: no gate")
        assertSame(watch, descriptor.watch)
        rig.model.back()
        assertEquals(Screen.WatchAccountQr, rig.screen, "Back on the descriptor QR is the account QR")
        assertSame(watch, rig.model.state.value.watch)
        assertFalse(blank(watch.account), "paging keeps the export")
        rig.model.nextPage()
        rig.model.previousPage()
        assertEquals(Screen.WatchAccountQr, rig.screen, "Previous on the descriptor QR is the account QR")
        rig.model.nextPage()
        rig.model.watchDone()
        assertEquals(Screen.RegisterOffer, rig.screen)
        assertNull(rig.model.state.value.watch)
        assertTrue(blank(watch.account) && blank(watch.descriptors), "the export's QRs were wiped as the registration's offer came")
    }

    @Test
    fun aBip39PassphraseIsTypedOnTheAsciiPadBehindTheGateAndExportsThatPassphrasesWallet() {
        val rig = atWatchOffer()
        val wallet = done(Core.summary(), "the wallet summary")
        rig.model.showWatchOnly()
        rig.model.withBip39Passphrase()
        val entry = rig.model.state.value
        assertEquals(Screen.Bip39Entry, entry.screen)
        assertTrue(isProtected(Screen.Bip39Entry))
        assertTrue(entry.gate, "the entry shows through the privacy gate")
        rig.model.passGate()
        rig.model.bip39Typed()
        assertEquals(Screen.Bip39Entry, rig.screen, "Done with nothing typed does nothing")
        for (key in "x y") assertTrue(rig.model.bip39Letters.type(key))
        assertEquals("x" + '·' + "y", bip39Shown(rig.model.bip39Letters), "a space shows as a middle dot")
        rig.model.back()
        assertEquals(Screen.Bip39Ask, rig.screen, "Back on the entry is the question (the Pi's KEY2)")
        assertEquals(0, rig.model.bip39Letters.length, "the passphrase typed was wiped")
        assertTrue(rig.model.bip39Letters.zeroPastLength())
        assertNull(rig.model.state.value.watch, "no export was made")
        rig.model.withBip39Passphrase()
        rig.model.passGate()
        for (key in PASSPHRASE) rig.model.bip39Letters.type(key)
        rig.model.bip39Typed()
        val summary = rig.model.state.value
        assertEquals(Screen.WatchSummary, summary.screen)
        assertFalse(summary.gate)
        assertEquals(0, rig.model.bip39Letters.length, "the passphrase was handed over and wiped")
        assertTrue(rig.model.bip39Letters.zeroPastLength())
        val watch = assertNotNull(summary.watch)
        assertTrue(watch.passphraseUsed, "the summary says it is the passphrase's wallet")
        assertFalse(watch.summary.fingerprint.contentEquals(wallet.fingerprint), "another wallet than the seed's own")
        val core = done(Core.watchOnly(Secret(PASSPHRASE.encodeToByteArray())), "core's export of that passphrase's wallet")
        assertContentEquals(core.summary.fingerprint, watch.summary.fingerprint)
        assertEquals(core.summary.firstAddress, watch.summary.firstAddress)
        assertTrue(sameModules(core.account, watch.account) && sameModules(core.descriptors, watch.descriptors), "its QRs are core's")
        core.wipe()
    }

    @Test
    fun theRegistrationQrIsCoresBehindTheGateOnceAndInMixedModeDsOfferFollows() {
        val (rig, _) = atMixedWatchOffer()
        rig.model.skipWatchOnly()
        rig.model.showRegistration()
        val shown = rig.model.state.value
        assertEquals(Screen.RegisterQr, shown.screen)
        assertTrue(isProtected(Screen.RegisterQr))
        assertTrue(shown.gate, "the registration QR shows through the privacy gate")
        rig.model.passGate()
        val registration = assertNotNull(rig.model.state.value.registration)
        val core = done(Core.registration(), "core's registration QR")
        assertTrue(sameModules(core, registration), "the registration QR is core's")
        core.wipe()
        rig.model.back()
        assertEquals(Screen.RegisterQr, rig.screen, "Back does nothing on the registration QR")
        rig.model.registrationDone()
        val offer = rig.model.state.value
        assertEquals(Screen.RevealDOffer, offer.screen, "a mixed seed has D: its offer follows the registration")
        assertFalse(isProtected(Screen.RevealDOffer))
        assertNull(offer.registration)
        assertTrue(blank(registration), "the registration QR was wiped as D's offer came")
        rig.model.skipDeviceLeg()
        assertEquals(Screen.Checklist, rig.screen)
        rig.model.finishCeremony()
        assertNoSession("Finish ended the session")
    }

    @Test
    fun dShowsInMixedModeBehindTheGateAsSixteenGroupsWhoseCommitmentIsCThenIsWiped() {
        val (rig, commitment) = atMixedWatchOffer()
        rig.model.skipWatchOnly()
        rig.model.skipRegistration()
        assertEquals(Screen.RevealDOffer, rig.screen)
        rig.model.showDeviceLeg()
        val shown = rig.model.state.value
        assertEquals(Screen.RevealD, shown.screen)
        assertTrue(isProtected(Screen.RevealD))
        assertTrue(shown.gate, "D shows through the privacy gate")
        rig.model.passGate()
        val leg = assertNotNull(rig.model.state.value.deviceLeg)
        assertEquals(32, leg.size)
        assertTrue(HEX_GROUPS.matches(deviceLegText(leg)), "D as 16 groups of 4 hex digits, four rows as C's")
        val tag = "KCE/v1/commit".encodeToByteArray()
        val input = ByteArray(tag.size + leg.size)
        tag.copyInto(input)
        for (index in 0 until leg.size) input[tag.size + index] = leg[index]
        assertEquals(commitment, hexGroups(sha256(input)), "SHA-256(\"KCE/v1/commit\" || D) is the C the commitment screen showed")
        input.fill(0)
        rig.model.back()
        assertEquals(Screen.RevealD, rig.screen, "Back does nothing on D")
        rig.model.deviceLegDone()
        assertEquals(Screen.Checklist, rig.screen)
        assertNull(rig.model.state.value.deviceLeg)
        assertTrue(blank(leg), "D was wiped as the checklist came")
        rig.model.finishCeremony()
        assertNoSession("Finish ended the session")
    }

    @Test
    fun leavingTheAppOnAProtectedExportDiscardsAtOnceAndWipesWhatItShowed() {
        val typing = atWatchOffer()
        typing.model.appReturned()
        typing.model.showWatchOnly()
        typing.model.withBip39Passphrase()
        typing.model.passGate()
        for (key in PASSPHRASE) typing.model.bip39Letters.type(key)
        typing.model.appLeft()
        typing.assertDiscarded(Notice.Left)
        assertEquals(0, typing.model.bip39Letters.length, "the passphrase typed was wiped")
        assertTrue(typing.model.bip39Letters.zeroPastLength())
        assertNoSession("leaving the BIP39 passphrase's entry did not discard")
        typing.model.appReturned()

        val qr = atWatchOffer()
        qr.model.appReturned()
        qr.model.showWatchOnly()
        qr.model.noBip39Passphrase()
        qr.model.watchSummaryDone()
        qr.model.passGate()
        val watch = assertNotNull(qr.model.state.value.watch)
        qr.model.appLeft()
        qr.assertDiscarded(Notice.Left, "leaving the account QR")
        assertTrue(blank(watch.account) && blank(watch.descriptors), "the export was wiped")
        assertNoSession("leaving the account QR did not discard")
        qr.model.appReturned()

        val (mixed, _) = atMixedWatchOffer()
        mixed.model.appReturned()
        mixed.model.skipWatchOnly()
        mixed.model.skipRegistration()
        mixed.model.showDeviceLeg()
        mixed.model.passGate()
        val leg = assertNotNull(mixed.model.state.value.deviceLeg)
        mixed.model.appLeft()
        mixed.assertDiscarded(Notice.Left, "leaving D")
        assertTrue(blank(leg), "D was wiped")
        assertNoSession("leaving D did not discard")
    }

    @Test
    fun wipeAllWipesTheExportOnShowTheRegistrationAndD() {
        val entry = atWatchOffer()
        entry.model.showWatchOnly()
        entry.model.withBip39Passphrase()
        entry.model.passGate()
        for (key in PASSPHRASE) entry.model.bip39Letters.type(key)
        entry.model.wipeAll()
        assertEquals(0, entry.model.bip39Letters.length, "wipeAll wiped the BIP39 passphrase typed")
        assertTrue(entry.model.bip39Letters.zeroPastLength())
        assertNoSession("wipeAll left a session")

        val rig = atWatchOffer()
        rig.model.showWatchOnly()
        rig.model.noBip39Passphrase()
        val watch = assertNotNull(rig.model.state.value.watch)
        rig.model.wipeAll()
        assertTrue(blank(watch.account) && blank(watch.descriptors), "wipeAll wiped the export on the watch-only summary")
        assertNoSession("wipeAll left a session")

        val (mixed, _) = atMixedWatchOffer()
        mixed.model.skipWatchOnly()
        mixed.model.showRegistration()
        mixed.model.passGate()
        val registration = assertNotNull(mixed.model.state.value.registration)
        mixed.model.wipeAll()
        assertTrue(blank(registration), "wipeAll wiped the registration QR")
        assertNoSession("wipeAll left a session")

        val (again, _) = atMixedWatchOffer()
        again.model.skipWatchOnly()
        again.model.skipRegistration()
        again.model.showDeviceLeg()
        again.model.passGate()
        val leg = assertNotNull(again.model.state.value.deviceLeg)
        again.model.wipeAll()
        assertTrue(blank(leg), "wipeAll wiped D")
        assertNoSession("wipeAll left a session")
    }

    private companion object {
        const val DICE_50 = "dice-50-words12"

        /** A BIP39 passphrase of watchonly.json's (abandon-trezor's), typed in-process and never printed. */
        const val PASSPHRASE = "TREZOR"

        /** 32 bytes as the commitment screen lays them out: four rows of four groups of four lower-case hex digits. */
        val HEX_GROUPS = Regex("^[0-9a-f]{4}( [0-9a-f]{4}){3}(\n[0-9a-f]{4}( [0-9a-f]{4}){3}){3}$")
    }
}
