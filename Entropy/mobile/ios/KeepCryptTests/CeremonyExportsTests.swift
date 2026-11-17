// The backup's save and the exports (tasks/todo.md, M6 item D6), ported from :screens' ExportScreensTest.kt
// and BackupScreensTest.kt over the real slot, with the payloads held to the vectors where the docs define
// them: each QR code the screens draw is read back in-process (Core Image's QR detector over a picture of
// its modules, as Android's Checker reads it with ZXing) and compared, never printed. The account QR is a
// crypto-account UR whose CBOR is BCR-2020-015's for the descriptors' xpub and the summary's fingerprint,
// and the descriptor QR the receive and change descriptors with their BIP-380 checksums; the decoders are
// first held to watchonly.json's own UR, CRC-32, account and checksum vectors. The registration QR is
// kcr.json's register text for dice-50-words12's seal code. D, in Mixed mode, hashes under "KCE/v1/commit"
// to the C the commitment screen showed, and its screen text is what verify.py's parse_hex32 reads. The
// saved backup is backup.json's age v1 file (armored, one scrypt stanza of work factor 18, within its
// limit), named as backup.json's file names are, and core opens it under its passphrase to the summary's
// fingerprint; the exporter's seam hands the model's own bytes. The backup screens' refusal and save-failure
// texts are BackupScreens.kt's. Each test leaves the slot at home.

import CommonCrypto
import XCTest

final class CeremonyExportsTests: XCTestCase {
    override func setUpWithError() throws {
        try KcrVectors.load()
        assertLiveSlot()
    }

    override func tearDown() {
        assertSlotEmptied()
    }

    /// The registry's origin in every QR's text until M9 (core's seal module; Android's Checker.ORIGIN).
    private let origin = "https://registry.invalid"

    /// vectors/kcr.json's 12-word dice-only gate seed the exports are made from.
    private let dice50 = "dice-50-words12"

    // MARK: - Reading what the screens draw

    /// Whether two matrices hold the same modules.
    private func sameModules(_ a: QrMatrix, _ b: QrMatrix) -> Bool {
        a.side == b.side && (0..<a.side).allSatisfy { y in (0..<a.side).allSatisfy { a.isDark(x: $0, y: y) == b.isDark(x: $0, y: y) } }
    }

    /// Whether matrix was wiped: no dark module left.
    private func blank(_ matrix: QrMatrix) -> Bool {
        (0..<matrix.side).allSatisfy { y in (0..<matrix.side).allSatisfy { !matrix.isDark(x: $0, y: y) } }
    }

    // MARK: - The vectors' own decoders

    private func watchOnly() throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: Vectors.resource("watchonly", "json")) as? [String: Any])
    }

    /// CRC-32/ISO-HDLC (watchonly.json's spec).
    private func crc32(_ bytes: [UInt8]) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in bytes {
            crc ^= UInt32(byte)
            for _ in 0..<8 {
                crc = crc & 1 == 1 ? (crc >> 1) ^ 0xEDB8_8320 : crc >> 1
            }
        }
        return crc ^ 0xFFFF_FFFF
    }

    /// A single-part UR's type and CBOR (BCR-2020-005, minimal Bytewords; either case), its CRC-32 checked.
    private func urDecode(_ text: String, _ words: [String]) throws -> (type: String, cbor: [UInt8]) {
        let lower = text.lowercased()
        XCTAssertTrue(lower.hasPrefix("ur:"), "not a UR")
        let rest = lower.dropFirst(3)
        let slash = try XCTUnwrap(rest.firstIndex(of: "/"), "a UR with no body")
        let type = String(rest[..<slash])
        let body = Array(rest[rest.index(after: slash)...])
        XCTAssertEqual(body.count % 2, 0, "minimal Bytewords come in pairs")
        var index: [String: UInt8] = [:]
        for (value, word) in words.enumerated() {
            index[String([word.first, word.last].compactMap { $0 })] = UInt8(value)
        }
        let bytes = try stride(from: 0, to: body.count - 1, by: 2).map { at in
            try XCTUnwrap(index[String(body[at...at + 1])], "not a byteword")
        }
        XCTAssertGreaterThan(bytes.count, 4)
        let cbor = Array(bytes.dropLast(4))
        let crc = bytes.suffix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        XCTAssertEqual(crc32(cbor), crc, "the UR's CRC-32")
        return (type, cbor)
    }

    /// BIP-380's checksum of a descriptor without one (watchonly.json's bip380 cases hold it).
    private func descriptorChecksum(_ descriptor: String) -> String? {
        let input = Array("0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ")
        let output = Array("qpzry9x8gf2tvdw0s3jn54khce6mua7l")
        let generator: [UInt64] = [0xF5_DEE5_1989, 0xA9_FDCA_3312, 0x1B_AB10_E32D, 0x37_06B1_677A, 0x64_4D62_6FFD]
        var symbols: [UInt64] = []
        var groups: [UInt64] = []
        for c in descriptor {
            guard let value = input.firstIndex(of: c) else { return nil }
            symbols.append(UInt64(value & 31))
            groups.append(UInt64(value >> 5))
            if groups.count == 3 {
                symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
                groups = []
            }
        }
        if groups.count == 1 { symbols.append(groups[0]) }
        if groups.count == 2 { symbols.append(groups[0] * 3 + groups[1]) }
        var check: UInt64 = 1
        for value in symbols + [UInt64](repeating: 0, count: 8) {
            let top = check >> 35
            check = (check & 0x7_FFFF_FFFF) << 5 ^ value
            for bit in 0..<5 where (top >> UInt64(bit)) & 1 == 1 {
                check ^= generator[bit]
            }
        }
        check ^= 1
        return String((0..<8).map { output[Int((check >> UInt64(5 * (7 - $0))) & 31)] })
    }

    /// Whether descriptor ends in '#' and its correct 8-character checksum (KeepCrypt's rule, watchonly.json).
    private func checksumValid(_ descriptor: String) -> Bool {
        guard let hash = descriptor.lastIndex(of: "#") else { return false }
        return descriptorChecksum(String(descriptor[..<hash])) == String(descriptor[descriptor.index(after: hash)...])
    }

    /// SHA-256 (CommonCrypto, the tests' own: the app does no hashing).
    private func sha256(_ bytes: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        _ = bytes.withUnsafeBytes { CC_SHA256($0.baseAddress, CC_LONG(bytes.count), &out) }
        return out
    }

    /// An xpub's 78 bytes, its Base58Check checksum checked.
    private func base58Check(_ text: String) throws -> [UInt8] {
        let alphabet = Array("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
        var number: [UInt8] = []
        for c in text {
            var carry = try XCTUnwrap(alphabet.firstIndex(of: c), "not Base58")
            for index in number.indices.reversed() {
                carry += Int(number[index]) * 58
                number[index] = UInt8(carry & 0xFF)
                carry >>= 8
            }
            while carry > 0 {
                number.insert(UInt8(carry & 0xFF), at: 0)
                carry >>= 8
            }
        }
        let zeros = text.prefix { $0 == "1" }.count
        let bytes = [UInt8](repeating: 0, count: zeros) + number
        XCTAssertEqual(bytes.count, 82, "an xpub is 78 bytes and a checksum")
        let payload = Array(bytes.prefix(78))
        XCTAssertEqual(Array(sha256(sha256(payload)).prefix(4)), Array(bytes.suffix(4)), "the xpub's checksum")
        return payload
    }

    /// BCR-2020-015's crypto-account CBOR for the account xpub under the master fingerprint (watchonly.json's
    /// spec: m/84h/0h/0h, a zero parent fingerprint left out).
    private func cryptoAccount(_ fingerprint: [UInt8], _ xpub: [UInt8]) -> [UInt8] {
        let parent = Array(xpub[5..<9])
        let chain = Array(xpub[13..<45])
        let key = Array(xpub[45..<78])
        let withParent = parent != [0, 0, 0, 0]
        var out: [UInt8] = [0xA2, 0x01, 0x1A] + fingerprint + [0x02, 0x81, 0xD9, 0x01, 0x34, 0xD9, 0x01, 0x94, 0xD9, 0x01, 0x2F]
        out += [withParent ? 0xA4 : 0xA3, 0x03, 0x58, 0x21] + key + [0x04, 0x58, 0x20] + chain
        out += [0x06, 0xD9, 0x01, 0x30, 0xA2, 0x01, 0x86, 0x18, 0x54, 0xF5, 0x00, 0xF5, 0x00, 0xF5, 0x02, 0x1A] + fingerprint
        if withParent { out += [0x08, 0x1A] + parent }
        return out
    }

    /// The decoders above against watchonly.json's own vectors: CRC-32's, the URs', every wallet's account
    /// CBOR and QR text from its xpub and fingerprint, its two descriptors' checksums, and BIP-380's cases.
    func testTheDecodersMatchWatchonlyJson() throws {
        let doc = try watchOnly()
        let words = try XCTUnwrap((doc["bytewords"] as? [String: Any])?["words"] as? [String])
        XCTAssertEqual(words.count, 256)
        for vector in try XCTUnwrap(doc["crc32"] as? [[String: Any]]) {
            let data = hexBytes(try XCTUnwrap(vector["data_hex"] as? String))
            XCTAssertEqual(String(format: "%08x", crc32(data)), vector["crc32"] as? String, "\(vector["name"] ?? "")")
        }
        for vector in try XCTUnwrap(doc["ur"] as? [[String: Any]]) {
            let decoded = try urDecode(try XCTUnwrap(vector["ur"] as? String), words)
            XCTAssertEqual(decoded.type, vector["type"] as? String)
            XCTAssertEqual(decoded.cbor, hexBytes(try XCTUnwrap(vector["cbor_hex"] as? String)), "\(vector["name"] ?? "")")
        }
        let wallets = try XCTUnwrap(doc["wallets"] as? [[String: Any]])
        XCTAssertFalse(wallets.isEmpty)
        for wallet in wallets {
            let name = try XCTUnwrap(wallet["name"] as? String)
            let fingerprint = hexBytes(try XCTUnwrap(wallet["fingerprint"] as? String))
            let xpub = try XCTUnwrap(wallet["account_xpub"] as? String)
            let account = try urDecode(try XCTUnwrap(wallet["qr_text"] as? String), words)
            XCTAssertEqual(account.type, "crypto-account", name)
            XCTAssertEqual(account.cbor, hexBytes(try XCTUnwrap(wallet["crypto_account_cbor_hex"] as? String)), name)
            XCTAssertEqual(cryptoAccount(fingerprint, try base58Check(xpub)), account.cbor, "\(name): the account from its xpub")
            let origin = "wpkh([" + fingerprintHex(fingerprint) + "/84h/0h/0h]" + xpub
            for (branch, key) in [("0", "receive_descriptor"), ("1", "change_descriptor")] {
                let descriptor = try XCTUnwrap(wallet[key] as? String)
                XCTAssertEqual(descriptor, origin + "/" + branch + "/*)#" + (descriptorChecksum(origin + "/" + branch + "/*)") ?? ""), name)
            }
            XCTAssertTrue(checksumValid(try XCTUnwrap(wallet["receive_descriptor_apostrophe"] as? String)), name)
        }
        for vector in try XCTUnwrap(doc["bip380"] as? [[String: Any]]) {
            let descriptor = try XCTUnwrap(vector["descriptor"] as? String)
            XCTAssertEqual(checksumValid(descriptor), vector["valid"] as? Bool, "\(vector["name"] ?? "")")
        }
    }

    // MARK: - The exports

    /// From Home: dice-50-words12 to the wallet summary, the backup's offer skipped: the watch-only offer.
    private func atWatchOffer() -> Rig {
        let rig = Rig().toHome().toSummary(dice50)
        rig.model.summaryDone()
        rig.model.skipBackup()
        XCTAssertEqual(rig.screen, .watchOffer)
        return rig
    }

    /// ExportScreensTest.kt's noBip39PassphraseExportsThisSeedsWalletItsQrsCoresBehindTheGateThenWiped, with
    /// the QRs' texts held to the vectors' formats.
    func testNoBip39PassphraseExportsThisSeedsWalletAndItsQrsAreTheVectorsFormats() throws {
        let rig = atWatchOffer()
        let wallet = try done(Core.shared.summary(), "the wallet summary")
        rig.model.showWatchOnly()
        XCTAssertEqual(rig.screen, .bip39Ask)
        XCTAssertFalse(Screen.bip39Ask.isProtected)
        rig.model.noBip39Passphrase()
        let summary = rig.model.state
        XCTAssertEqual(summary.screen, .watchSummary)
        XCTAssertFalse(Screen.watchSummary.isProtected, "the watch-only summary is Public, as the Pi's (Q29)")
        let watch = try XCTUnwrap(summary.watch)
        XCTAssertFalse(watch.passphraseUsed)
        XCTAssertEqual(watch.summary, wallet, "no passphrase: this seed's wallet")
        rig.model.watchSummaryDone()
        XCTAssertEqual(rig.screen, .watchAccountQr)
        XCTAssertTrue(Screen.watchAccountQr.isProtected)
        XCTAssertTrue(rig.model.state.gate, "the account QR shows through the privacy gate")
        rig.model.passGate()
        XCTAssertTrue(rig.model.state.watch?.account === watch.account)
        let core = try done(Core.shared.watchOnly(passphrase: nil), "core's export, again")
        XCTAssertTrue(sameModules(core.account, watch.account), "the account QR is core's")
        XCTAssertTrue(sameModules(core.descriptors, watch.descriptors), "the descriptor QR is core's")
        core.wipe()

        // The QRs' texts, read from the matrices the screens draw (compared, never printed).
        let words = try XCTUnwrap((try watchOnly()["bytewords"] as? [String: Any])?["words"] as? [String])
        let accountText = try qrText(watch.account)
        XCTAssertTrue(accountText.hasPrefix("UR:CRYPTO-ACCOUNT/"), "the account QR is an upper-case crypto-account UR")
        XCTAssertEqual(accountText, accountText.uppercased())
        let account = try urDecode(accountText, words)
        XCTAssertEqual(account.type, "crypto-account")
        let lines = try qrText(watch.descriptors).split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        XCTAssertEqual(lines.count, 2, "the receive and change descriptors, one a line")
        let origin = "wpkh([" + fingerprintHex(wallet.fingerprint) + "/84h/0h/0h]"
        var xpubs: [String] = []
        for (line, branch) in zip(lines, ["0", "1"]) {
            XCTAssertTrue(line.hasPrefix(origin + "xpub"), "under the summary's fingerprint, m/84h/0h/0h")
            let tail = "/" + branch + "/*)#"
            let end = try XCTUnwrap(line.range(of: tail), "branch " + branch)
            XCTAssertTrue(checksumValid(line), "branch \(branch): its BIP-380 checksum")
            xpubs.append(String(line[line.index(line.startIndex, offsetBy: origin.count)..<end.lowerBound]))
        }
        XCTAssertEqual(xpubs.count, 2)
        XCTAssertEqual(xpubs.first, xpubs.last, "both descriptors carry the account's xpub")
        let xpub = try base58Check(try XCTUnwrap(xpubs.first))
        XCTAssertEqual(Array(xpub.prefix(4)), [0x04, 0x88, 0xB2, 0x1E], "a mainnet xpub")
        XCTAssertEqual(xpub[4], 3, "the account's depth")
        XCTAssertEqual(Array(xpub[9..<13]), [0x80, 0, 0, 0], "account 0h")
        XCTAssertEqual(account.cbor, cryptoAccount(wallet.fingerprint, xpub), "the account QR is BCR-2020-015's for that xpub")

        rig.model.nextPage()
        XCTAssertEqual(rig.screen, .watchDescriptorQr)
        XCTAssertFalse(rig.model.state.gate, "Protected to Protected: no gate")
        rig.model.back()
        XCTAssertEqual(rig.screen, .watchAccountQr, "Back on the descriptor QR is the account QR")
        rig.model.nextPage()
        rig.model.previousPage()
        XCTAssertEqual(rig.screen, .watchAccountQr, "Previous on the descriptor QR is the account QR")
        XCTAssertFalse(blank(watch.account), "paging keeps the export")
        rig.model.nextPage()
        rig.model.watchDone()
        XCTAssertEqual(rig.screen, .registerOffer)
        XCTAssertNil(rig.model.state.watch)
        XCTAssertTrue(blank(watch.account) && blank(watch.descriptors), "the export's QRs were wiped as the registration's offer came")
        rig.model.skipRegistration()
        XCTAssertEqual(rig.screen, .checklist, "a dice-only seed has no D: the checklist")
        XCTAssertFalse(rig.model.state.twoDevices)
        rig.model.finishCeremony()
        XCTAssertEqual(rig.screen, .home)
    }

    /// ExportScreensTest.kt's aBip39PassphraseIsTypedOnTheAsciiPadBehindTheGateAndExportsThatPassphrasesWallet.
    func testABip39PassphraseIsTypedOnTheAsciiPadAndExportsThatPassphrasesWallet() throws {
        let rig = atWatchOffer()
        let wallet = try done(Core.shared.summary(), "the wallet summary")
        rig.model.showWatchOnly()
        rig.model.withBip39Passphrase()
        XCTAssertEqual(rig.screen, .bip39Entry)
        XCTAssertTrue(Screen.bip39Entry.isProtected)
        XCTAssertTrue(rig.model.state.gate, "the entry shows through the privacy gate")
        rig.model.passGate()
        XCTAssertEqual(keysPageText(rig.model.state.page), "Keys, page 1 of 3")
        for key in "x y" {
            XCTAssertTrue(rig.model.bip39Letters.type(key))
        }
        XCTAssertEqual(bip39Shown(rig.model.bip39Letters), "x\u{00B7}y", "a space shows as a middle dot")
        rig.model.back()
        XCTAssertEqual(rig.screen, .bip39Ask, "Back on the entry is the question (the Pi's KEY2)")
        XCTAssertEqual(rig.model.bip39Letters.length, 0, "the passphrase typed was wiped")
        XCTAssertNil(rig.model.state.watch, "no export was made")
        rig.model.withBip39Passphrase()
        rig.model.passGate()
        // watchonly.json's abandon-trezor passphrase, typed in-process and never printed.
        for key in "TREZOR" {
            XCTAssertTrue(rig.model.bip39Letters.type(key))
        }
        rig.model.bip39Typed()
        XCTAssertEqual(rig.screen, .watchSummary)
        XCTAssertEqual(rig.model.bip39Letters.length, 0, "the passphrase was handed over and wiped")
        let watch = try XCTUnwrap(rig.model.state.watch)
        XCTAssertTrue(watch.passphraseUsed, "the summary says it is the passphrase's wallet")
        XCTAssertNotEqual(watch.summary.fingerprint, wallet.fingerprint, "another wallet than the seed's own")
        let core = try done(Core.shared.watchOnly(passphrase: Secret(taking: Array("TREZOR".utf8))), "that wallet's export")
        XCTAssertEqual(core.summary, watch.summary)
        XCTAssertTrue(sameModules(core.account, watch.account) && sameModules(core.descriptors, watch.descriptors), "its QRs are core's")
        core.wipe()
        let lines = try qrText(watch.descriptors).split(separator: "\n").map(String.init)
        XCTAssertTrue(lines.allSatisfy { $0.hasPrefix("wpkh([" + fingerprintHex(watch.summary.fingerprint) + "/84h/0h/0h]xpub") && checksumValid($0) })
        rig.model.watchSummaryDone()
        rig.model.passGate()
        rig.model.nextPage()
        rig.model.watchDone()
        rig.model.skipRegistration()
        rig.model.finishCeremony()
        XCTAssertEqual(rig.screen, .home)
    }

    /// ExportScreensTest.kt's registration QR, with its text: kcr.json's register text for the seed's seal code.
    func testTheRegistrationQrIsCoresRegisterTextForTheSealCode() throws {
        let rig = atWatchOffer()
        rig.model.skipWatchOnly()
        XCTAssertFalse(Screen.registerOffer.isProtected)
        rig.model.showRegistration()
        XCTAssertEqual(rig.screen, .registerQr)
        XCTAssertTrue(Screen.registerQr.isProtected)
        XCTAssertTrue(rig.model.state.gate, "the registration QR shows through the privacy gate")
        rig.model.passGate()
        let registration = try XCTUnwrap(rig.model.state.registration)
        let core = try done(Core.shared.registration(), "core's registration QR")
        XCTAssertTrue(sameModules(core, registration), "the registration QR is core's")
        core.wipe()
        let code = try XCTUnwrap(try Vectors.seed(dice50)["seal_code_hashed"] as? String)
        XCTAssertEqual(try qrText(registration), origin + "/register#c=" + code, "kcr.json's seal code, as the register text")
        rig.model.back()
        XCTAssertEqual(rig.screen, .registerQr, "Back does nothing on the registration QR")
        rig.model.registrationDone()
        XCTAssertEqual(rig.screen, .checklist)
        XCTAssertNil(rig.model.state.registration)
        XCTAssertTrue(blank(registration), "the registration QR was wiped as the checklist came")
        rig.model.finishCeremony()
        XCTAssertEqual(rig.screen, .home)
    }

    /// ExportScreensTest.kt's dShowsInMixedModeBehindTheGateAsSixteenGroupsWhoseCommitmentIsCThenIsWiped, and
    /// D's screen text as verify.py's parse_hex32 reads it typed on one line.
    func testDShowsInMixedModeWhoseCommitmentIsCAndVerifyPyReadsItsText() throws {
        let rig = Rig().toHome()
        let commitment = try XCTUnwrap(rig.toMixedSummary(), "C on the commitment screen")
        rig.model.summaryDone()
        rig.model.skipBackup()
        rig.model.skipWatchOnly()
        rig.model.showRegistration()
        rig.model.passGate()
        rig.model.registrationDone()
        XCTAssertEqual(rig.screen, .revealDOffer, "a mixed seed has D: its offer follows the registration")
        XCTAssertFalse(Screen.revealDOffer.isProtected)
        rig.model.showDeviceLeg()
        XCTAssertEqual(rig.screen, .revealD)
        XCTAssertTrue(Screen.revealD.isProtected)
        XCTAssertTrue(rig.model.state.gate, "D shows through the privacy gate")
        rig.model.passGate()
        let leg = try XCTUnwrap(rig.model.state.deviceLeg)
        XCTAssertEqual(leg.count, 32)
        let shown = deviceLegText(leg)
        XCTAssertNotNil(
            shown.range(of: "^[0-9a-f]{4}( [0-9a-f]{4}){3}(\n[0-9a-f]{4}( [0-9a-f]{4}){3}){3}$", options: .regularExpression),
            "D as 16 groups of 4 hex digits, four rows as C's")
        let bytes = (0..<leg.count).map { leg[$0] }
        XCTAssertEqual(hexGroups(Secret(taking: sha256(Array("KCE/v1/commit".utf8) + bytes))), commitment, "SHA-256(\"KCE/v1/commit\" || D) is C")
        // verify.py's parse_hex32: spaces, tabs and hyphens removed, 64 hex digits left; the rows typed on one line.
        let typed = shown.replacingOccurrences(of: "\n", with: " ").filter { !" \t-".contains($0) }
        XCTAssertEqual(typed.count, 64)
        XCTAssertEqual(hexBytes(typed), bytes, "verify.py reads D's screen text as D")
        rig.model.back()
        XCTAssertEqual(rig.screen, .revealD, "Back does nothing on D")
        rig.model.deviceLegDone()
        XCTAssertEqual(rig.screen, .checklist)
        XCTAssertNil(rig.model.state.deviceLeg)
        XCTAssertTrue(zeroed(leg), "D was wiped as the checklist came")
        rig.model.finishCeremony()
        XCTAssertEqual(rig.screen, .home)
    }

    // MARK: - The backup

    /// Save hands the exporter core's suggested name (backup.json's file names' form) and the model's own
    /// bytes, the same Secret the place is then asked to have written; then "Backup verified".
    func testSaveHandsTheExporterCoresNameAndTheModelsOwnBytes() throws {
        let rig = Rig().toHome().toSummary(dice50)
        let passphrase = rig.toConfirm()
        rig.confirm(passphrase)
        XCTAssertEqual(rig.screen, .backupSave)
        let name = try XCTUnwrap(rig.model.state.backupName)
        XCTAssertNotNil(name.range(of: "^keepcrypt-backup-[0-9a-f]{8}\\.age$", options: .regularExpression), "backup.json's file names' form")
        let pickers = FakePickers()
        rig.model.saveBackup(pickers)
        XCTAssertEqual(pickers.created, [name])
        let handed = try XCTUnwrap(pickers.handed.first)
        let place = FakePlace()
        rig.model.backupPlaced(place)
        XCTAssertTrue(place.handed === handed, "write is asked about the very bytes the exporter was given")
        rig.worker.run()
        XCTAssertEqual(rig.screen, .backupVerified)
        rig.model.backupVerifiedDone()
        XCTAssertTrue(zeroed(handed), "the encrypted file was wiped once the save was over")
        rig.skipExports()
        rig.model.finishCeremony()
    }

    /// The saved backup is backup.json's age v1 file: armored in 64 columns, one scrypt stanza of work factor
    /// 18 with a 16-byte salt, within backup.json's limit for 12 words; core opens it with its passphrase's
    /// first four letters to the wallet summary's fingerprint (the round trip).
    func testTheSavedBackupIsAnAgeV1FileOfWorkFactor18ThatCoreOpens() throws {
        let saved = SavedBackup.shared
        let backup = try XCTUnwrap(JSONSerialization.jsonObject(with: Vectors.resource("backup", "json")) as? [String: Any])
        let constants = try XCTUnwrap(backup["constants"] as? [String: Any])
        let limits = try XCTUnwrap(backup["limits"] as? [String: Any])
        XCTAssertLessThanOrEqual(saved.file.count, try XCTUnwrap(limits["max_armored_bytes_12"] as? Int))
        let text = try XCTUnwrap(String(bytes: saved.file, encoding: .ascii), "an armored file is ASCII")
        var lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        XCTAssertEqual(lines.first, constants["armor_begin"] as? String)
        XCTAssertEqual(lines.last, "", "the file ends in a line feed")
        lines.removeLast()
        XCTAssertEqual(lines.last, constants["armor_end"] as? String)
        let body = lines.dropFirst().dropLast()
        let columns = try XCTUnwrap(constants["columns"] as? Int)
        XCTAssertTrue(body.dropLast().allSatisfy { $0.count == columns } && (body.last?.count ?? 0) <= columns, "64 columns")
        let decoded = try XCTUnwrap(Data(base64Encoded: body.joined()), "the armor's base64")
        // The binary file's header lines (its payload after them is not text).
        let headerLines = String(decoding: decoded, as: UTF8.self).components(separatedBy: "\n")
        XCTAssertGreaterThan(headerLines.count, 4)
        XCTAssertEqual(headerLines.first, constants["version_line"] as? String)
        let stanza = headerLines[1].split(separator: " ").map(String.init)
        XCTAssertEqual(stanza.count, 4, "-> scrypt salt work-factor")
        XCTAssertEqual(Array(stanza.prefix(2)), ["->", "scrypt"])
        XCTAssertEqual(Data(base64Encoded: stanza[2] + "==")?.count, 16, "a 16-byte salt")
        XCTAssertEqual(Int(stanza[3]), constants["work_factor"] as? Int, "work factor 18")
        XCTAssertEqual(headerLines[2].count, 43, "the stanza's body: 32 bytes, unpadded base64")
        XCTAssertTrue(headerLines[3].hasPrefix("--- "), "one stanza, then the MAC")
        XCTAssertEqual(saved.passphrase.count, constants["passphrase_words"] as? Int)

        let entries = saved.passphrase.map { Secret(taking: Array($0.prefix(4).utf8)) }
        let opened = try done(Core.shared.openBackup(entries: entries, file: Secret(taking: saved.file)), "core opens the saved file")
        XCTAssertEqual(opened.fingerprint, saved.fingerprint, "the file holds the seed the wallet summary showed")
        XCTAssertTrue(isDone(Core.shared.end()))
    }

    /// The passphrase's page lines (backup.json's generate vector "stream"'s passphrase), the confirm's lines,
    /// and the save's failure lines, as BackupScreens.kt lays them out.
    func testThePassphrasePagesAndTheSaveFailuresLines() throws {
        let backup = try XCTUnwrap(JSONSerialization.jsonObject(with: Vectors.resource("backup", "json")) as? [String: Any])
        let generate = try XCTUnwrap((backup["generate"] as? [[String: Any]])?.first)
        let words = try XCTUnwrap(generate["passphrase"] as? String).split(separator: " ").map(String.init)
        XCTAssertEqual(words.count, passphraseWords)
        for page in 0..<2 {
            let part = words[page * passphrasePageWords..<(page + 1) * passphrasePageWords]
            let text = Secret(taking: Array(part.joined(separator: " ").utf8))
            let expected = part.enumerated().map { String(page * passphrasePageWords + $0.offset + 1) + " " + $0.element }
            XCTAssertEqual(passphraseLines(page, text), expected)
            XCTAssertEqual(passphraseText(page, text), expected.joined(separator: "\n"))
        }
        XCTAssertEqual(passphrasePageText(0), "Words 1-4 of 8")
        XCTAssertEqual(passphrasePageText(1), "Words 5-8 of 8")
        XCTAssertEqual(confirmQuestionText(1), "Check your copy: question 2 of 2")
        XCTAssertEqual(whichWordText(7), "Which is word 7?")
        XCTAssertEqual(choiceText(Secret(taking: Array("nasty".utf8))), "nasty")
        XCTAssertEqual(saveFailureText(SaveFailure(step: .write)), "Backup not saved: writing the file failed.")
        XCTAssertEqual(saveFailureText(SaveFailure(step: .readBack)), "Backup not saved: reading the file back failed.")
        XCTAssertEqual(
            saveFailureText(SaveFailure(step: .verify, refusal: .readbackMismatch)),
            "Backup not saved: the file read back does not verify (the backup does not hold this seed).")
    }
}
