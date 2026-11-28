// A new seed of 12 words, mixed with the phone's D, checked by its typed go-ahead code and taken through every
// export to Finish, then its backup checked and About (tasks/todo.md, M6 item U1; Android's JourneyTest
// aMixedTwelveWordSeedIsCheckedByItsCode... and cannotCheckStartsAgain...'s backup): Device entropy's sentence,
// the commitment's C read from the screen, 50 rolls, Check now's check QR; Scan go-ahead QR with kcr.json's
// clear-empty-bucket handed by the Scan hook, refused (it is not this seal's), Back, and the code a checker
// builds from the drawn check QR's T and nonce (read back from its picture) typed on the code pad: the check
// passed; the 12 words (this seed's, read from the screen) and their read-back on the letter pad; the summary;
// the backup made through its gate, its passphrase read from its two pages and confirmed on the letter pad, and
// saved by the Save hook to memory (no file, rule 8), read back and verified; watch-only with watchonly.json's
// BIP39 passphrase TREZOR on the ASCII pad's second page of keys, its summary that passphrase's wallet's, the
// account and descriptor QRs behind their gate (named by their kinds); the registration QR; Reveal D behind its
// gate, whose SHA-256 under "KCE/v1/commit" is the C the commitment screen showed; the checklist and Finish;
// then Check a backup of the saved copy (the Backup file hook) with the passphrase on the letter pad, Backup
// OK, the words through the gate equal to the ceremony's, Done, and About. Every secret read from the screen
// is compared or typed, never printed. Through the UI alone but the offline path, the scan, the save and the
// open picker (the hooks).

#if KC_TEST_HOOKS
import XCTest

final class MixedJourneyUITests: XCTestCase {
    /// One cause, one failure (U2f): a journey stops at its first failure, so a lost press is not followed by
    /// every later step failing for it.
    override func setUp() {
        continueAfterFailure = false
    }

    func testAMixedSeedIsCheckedByItsCodeThroughEveryExportAndItsBackupIsChecked() throws {
        // The code's own check first: CLAUDE.md's go-ahead vector.
        let vectorTag = hexBytes("2b8103c8dd64611df5c8c28b8fbf864a1005372f5da06a5777f92708ce79cb5c")
        XCTAssertEqual(goAheadCode(vectorTag, hexBytes("0001020304050607")), "CF94BCAJ", "CLAUDE.md's go-ahead vector")
        let rolls = try JourneyVectors.seed("dice-50-words12").rolls
        let app = XCUIApplication()
        app.launchEnvironment["KC_HOOK_SCAN_TEXT"] = try JourneyVectors.proof("clear-empty-bucket")
        app.launchEnvironment["KC_HOOK_SAVE"] = "ok"
        app.launchEnvironment["KC_HOOK_BACKUP_FROM_SAVE"] = "1"
        let started = Date()
        app.toHome()
        app.press("new_seed")
        app.on("length", "Length")
        app.press("words_12")
        app.on("device_entropy", "Device entropy", timeout: 120)
        app.waitLabel("device_entropy_sentence", "Your seed is safe if either your phone or your dice are honest.")
        app.press("continue")
        app.on("commitment", "the commitment", timeout: 120)
        let commitment = hexBytes(app.element("commitment_hex").label)
        XCTAssertEqual(commitment.count, 32, "C as 32 bytes")
        app.press("continue")
        app.on("dice", "the dice")
        app.roll(rolls)
        app.press("check_now")
        app.on("seal_card", "the seal card")
        app.press("show_check_qr")
        app.on("check_qr", "the check QR")
        app.press("scan_qr")
        app.on("scan", "the scan screen")
        app.press("hook_scan")
        let refused = NSPredicate(format: "label BEGINSWITH %@", "That QR code is not the go-ahead for this seal.")
        XCTAssertTrue(app.staticTexts.matching(refused).firstMatch.waitForExistence(timeout: 30), "another seal's proof is refused, the check kept")
        app.press("back")
        app.on("check_qr", "the check QR again")
        try app.typeGoAhead()
        pass("mixed: Device entropy, C read, 50 rolls, a scanned proof of another seal refused, the typed code passed (\(Int(Date().timeIntervalSince(started))) s)")
        app.press("show_words")
        app.passGate("the words")
        app.on("words", "insert 1")
        let words = app.wordsAndReadback(12)
        let passphrase = try app.backupMadeAndSaved()
        pass("mixed: its 12 words read back, the summary, the backup made, confirmed and saved in memory, verified (\(Int(Date().timeIntervalSince(started))) s)")

        app.press("show_watch_only")
        app.on("bip39_ask", "the BIP39 question")
        app.press("with_bip39_passphrase")
        app.passGate("the BIP39 passphrase's entry")
        app.on("bip39_entry", "the BIP39 passphrase's entry")
        app.press("keys_next")
        app.waitLabel("keys_page", "Keys, page 2 of 3")
        app.ascii("TREZOR")
        app.pressEnabled("bip39_done")
        app.on("watch_summary", "the watch-only summary")
        XCTAssertTrue(app.element("passphrase_wallet").exists, "the summary is the BIP39 passphrase's wallet's")
        XCTAssertNotNil(app.element("watch_fingerprint").label.range(of: "^[0-9a-f]{8}$", options: .regularExpression))
        app.press("watch_summary_next")
        app.passGate("the account QR")
        app.on("watch_account_qr", "the account QR")
        XCTAssertTrue(app.images["Account QR code for Sparrow"].exists, "the account QR, named by its kind")
        app.press("watch_next")
        app.on("watch_descriptor_qr", "the descriptor QR")
        XCTAssertTrue(app.images["Descriptor QR code for Bitcoin Core"].exists, "the descriptor QR, named by its kind")
        app.press("watch_done")
        app.on("register_offer", "the registration's offer")
        app.press("show_registration")
        app.passGate("the registration QR")
        app.on("register_qr", "the registration QR")
        app.press("registration_done")
        app.on("reveal_d_offer", "D's offer (Mixed)")
        XCTAssertTrue(app.element("reveal_d_warning").exists)
        app.press("show_d")
        app.passGate("D")
        app.on("reveal_d", "D")
        let leg = hexBytes(app.element("kc_secret_device_leg_text").label)
        XCTAssertEqual(leg.count, 32, "D as 32 bytes")
        XCTAssertTrue(sha256(Array("KCE/v1/commit".utf8) + leg) == commitment, "SHA-256(\"KCE/v1/commit\" || D) is the C shown (neither printed)")
        app.press("d_done")
        app.checklistToFinish()
        pass("mixed: watch-only with TREZOR on the ASCII pad, its QRs, the registration QR, D committing to C, the checklist and Finish (\(Int(Date().timeIntervalSince(started))) s)")

        app.checkSavedBackup(passphrase, words)
        app.press("show_about")
        app.on("about", "About")
        app.waitLabel("about_version", "Version 0.1.0")
        app.waitLabel("about_flavour", "This build: the TEST REGISTRY app, built only in CI and never released. Registry key: the test key.")
        app.press("back")
        app.on("home", "Home")
        pass("mixed: the saved backup checked (Backup OK, its words the ceremony's), About, Home (\(Int(Date().timeIntervalSince(started))) s in all)")
    }
}
#endif
