// What U1's journeys share (tasks/todo.md, M6 item U1; Android's Journeys.kt and Ui.kt), each step a press on
// the screen by its identifier or its label, as a person makes it: the way to Home, the dice pressed face by
// face, the privacy gate passed, the words read from the screen (kc_secret_insert_word, inside SecureLayer, reachable
// to the accessibility tree as M6-16 found) and read back on the letter pad, the backup made and saved through
// the Save hook, Check a backup of the saved copy, and the go-ahead code a checker builds from the check QR,
// read back from a picture of the drawn QR (Core Image's QR detector) and typed on the code pad. Every seed is
// a vectors/kcr.json gate seed (rule 12) or a new one made on the screen; a secret read from the screen is
// compared and typed, never printed (each journey's pass line names its path alone). The system's own UI is
// the hooks' (TestHooks.swift): the offline path, the scan, the pickers and the halt.

#if KC_TEST_HOOKS
import CommonCrypto
import CoreImage
import UIKit
import XCTest

/// The UI tests' vectors (rule 12): kcr.json's and backup.json's, bundled.
enum JourneyVectors {
    private final class Anchor {}

    static func json(_ name: String) throws -> [String: Any] {
        let file = try XCTUnwrap(Bundle(for: Anchor.self).url(forResource: name, withExtension: "json"))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
    }

    /// kcr.json's entry named name in list (seeds, proofs or snapshots).
    static func kcr(_ list: String, _ name: String) throws -> [String: Any] {
        let entries = try XCTUnwrap(try json("kcr")[list] as? [[String: Any]])
        return try XCTUnwrap(entries.first { $0["name"] as? String == name }, name)
    }

    /// A gate seed's rolls, words and Seal ID.
    static func seed(_ name: String) throws -> (rolls: String, words: [String], sealId: String) {
        let entry = try kcr("seeds", name)
        let words = try XCTUnwrap(entry["mnemonic"] as? String).split(separator: " ").map(String.init)
        return (try XCTUnwrap(entry["rolls"] as? String), words, try XCTUnwrap(entry["seal_id"] as? String))
    }

    /// A proof's go-ahead QR text (its UR).
    static func proof(_ name: String) throws -> String {
        try XCTUnwrap(try kcr("proofs", name)["ur"] as? String, name)
    }

    /// A snapshot's bytes in hex.
    static func snapshotHex(_ name: String) throws -> String {
        try XCTUnwrap(try kcr("snapshots", name)["kcr_hex"] as? String, name)
    }
}

/// The journey's pass line: its path, in the test's log (XCTest prints an activity's name), never a secret.
func pass(_ line: String) {
    XCTContext.runActivity(named: "pass: " + line) { _ in }
}

/// SHA-256 (CommonCrypto, the tests' own).
func sha256(_ bytes: [UInt8]) -> [UInt8] {
    var out = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
    _ = bytes.withUnsafeBytes { CC_SHA256($0.baseAddress, CC_LONG(bytes.count), &out) }
    return out
}

/// hex's bytes, every space and line feed left out.
func hexBytes(_ hex: String) -> [UInt8] {
    let digits = Array(hex.filter { !" \n\t".contains($0) }.utf8)
    return stride(from: 0, to: digits.count - 1, by: 2).compactMap { UInt8(String(decoding: digits[$0...$0 + 1], as: UTF8.self), radix: 16) }
}

/// The go-ahead code a checker builds (CLAUDE.md's domain constants): Crockford base32 of the first 40 bits of
/// SHA-256("KCE/v1/go" || T || n), 8 symbols.
func goAheadCode(_ tag: [UInt8], _ nonce: [UInt8]) -> String {
    let digest = sha256(Array("KCE/v1/go".utf8) + tag + nonce)
    var bits: UInt64 = 0
    for index in 0..<5 {
        bits = bits << 8 | UInt64(digest[index])
    }
    let symbols = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    return String((0..<8).map { symbols[Int((bits >> UInt64(35 - 5 * $0)) & 31)] })
}

extension XCUIApplication {
    /// Waits for the element id (a screen's root, or any), then past the press guard.
    func on(_ id: String, _ what: String, timeout: TimeInterval = 60, file: StaticString = #filePath, line: UInt = #line) {
        if !element(id).waitForExistence(timeout: timeout) {
            XCTFail(what + " never came; touches \(touchCounts()); " + facts(), file: file, line: line)
        }
        pastPressGuard()
    }

    /// The button id pressed as a person presses it, its effect a new screen (screen's root showing, or one it
    /// passes on the way, Working by default): classified as pressUntil classifies a press that did nothing (U2g).
    func pressTo(
        _ id: String, _ screen: String, passing: [String] = ["working"], file: StaticString = #filePath, line: UInt = #line
    ) {
        let button = buttons[id]
        XCTAssertTrue(button.waitForExistence(timeout: 30), "no button " + id + "; " + facts(), file: file, line: line)
        pressUntil(button, id + " to " + screen, placed: true, file: file, line: line) {
            ([screen] + passing).contains { self.element($0).exists }
        }
        on(screen, screen + " after " + id, file: file, line: line)
    }

    /// The button id pressed, once it is there.
    func press(_ id: String, file: StaticString = #filePath, line: UInt = #line) {
        let button = buttons[id]
        XCTAssertTrue(button.waitForExistence(timeout: 30), "no button " + id, file: file, line: line)
        button.tap()
    }

    /// Waits until the element id's label is label.
    func waitLabel(_ id: String, _ label: String, timeout: TimeInterval = 30, file: StaticString = #filePath, line: UInt = #line) {
        let element = self.element(id)
        let shows = NSPredicate(format: "label == %@", label)
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if element.exists, shows.evaluate(with: element) { return }
            usleep(100_000)
        }
        XCTFail("\(id) never read as expected", file: file, line: line)
    }

    /// Launched, past First launch and the self-test, the offline path reported, Start: Home.
    func toHome() {
        launchedToGoOffline()
        buttons["hook_path_none"].tap()
        pastPressGuard()
        press("start")
        on("home", "Home")
    }

    /// The privacy gate before a Protected screen, passed.
    func passGate(_ what: String) {
        on("privacy_gate", "the privacy gate before " + what)
        press("pass_gate")
    }

    /// Whether effect holds within seconds, looked at every 0.1 s (a wait for the screen, not a sleep).
    func within(_ seconds: TimeInterval, _ effect: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        repeat {
            if effect() { return true }
            usleep(100_000)
        } while Date() < deadline
        return false
    }

    /// The scroll view whose column holds the control id, if the control scrolls with one (a KitScreen's
    /// actions do once they are taller than half the screen).
    func scrollViewHolding(_ id: String) -> XCUIElement? {
        let scroll = scrollViews.containing(.button, identifier: id).firstMatch
        return scroll.exists ? scroll : nil
    }

    /// Where control lies, the scroll view that clips it and the TestHooks panel (U2g, U2h): frames in points,
    /// of a public control alone (never a pad's key: its place names the key). "gone" for a control, or a
    /// panel, no longer there, without asking a missing element its frame (which fails the test there).
    func place(_ control: XCUIElement) -> String {
        func text(_ frame: CGRect) -> String {
            "\(Int(frame.minX)),\(Int(frame.minY)) \(Int(frame.width))x\(Int(frame.height))"
        }
        guard control.exists else { return "gone" }
        var line = "at " + text(control.frame)
        if let scroll = scrollViewHolding(control.identifier) {
            line += ", its scroll view at " + text(scroll.frame)
        } else {
            line += ", in no scroll view"
        }
        let panel = element("hook_panel")
        line += panel.exists ? ", the hooks panel at " + text(panel.frame) : ", the hooks panel gone"
        return line
    }

    /// The region the screens show around control (U2h): its scroll view's frame, or the app's for a control in
    /// none, cut at the TestHooks panel's top. The screens' scroll views run on under the panel (it is a bottom
    /// safe-area inset), and the screens' touch guard ends at its top, so a tap below that lands on the panel.
    func shownRegion(_ control: XCUIElement) -> CGRect {
        var region = scrollViewHolding(control.identifier)?.frame ?? frame
        let panel = element("hook_panel")
        if panel.exists {
            region.size.height = max(0, min(region.maxY, panel.frame.minY) - region.minY)
        }
        return region
    }

    /// Whether control, if there, lies wholly above the TestHooks panel's top and below the app's: the cheap look
    /// before every press (two frames), the scroll view asked only when it fails.
    func abovePanel(_ control: XCUIElement) -> Bool {
        guard control.exists else { return true }
        let panel = element("hook_panel")
        let top = panel.exists ? panel.frame.minY : frame.maxY
        let bounds = control.frame
        return bounds.maxY <= top + 1 && bounds.minY >= frame.minY - 1
    }

    /// Whether control is there and wholly inside the region the screens show (a point's rounding allowed).
    func wholeInView(_ control: XCUIElement) -> Bool {
        control.exists && shownRegion(control).insetBy(dx: -1, dy: -1).contains(control.frame)
    }

    /// control, where it scrolls with a column and is not wholly shown, dragged into view as a person scrolls a
    /// half-shown button: slowly and held (no glide), from the column's left margin (24 pt, no control there)
    /// inside the shown region, by what is cut and a margin, at most half the region a drag, at most six. Each
    /// drag logs a probe line named what, with the control's place only when placed (a public control).
    func bringIntoView(_ control: XCUIElement, _ what: String, placed: Bool) {
        guard control.exists, let scroll = scrollViewHolding(control.identifier) else { return }
        var drags = 0
        while control.exists, !wholeInView(control), drags < 6 {
            pass("probe: \(what): not wholly shown above the hooks panel" + (placed ? " (" + place(control) + ")" : "") + "; dragged into view")
            let shown = shownRegion(control)
            let frame = control.frame
            let lift = frame.maxY > shown.maxY
                ? min(frame.maxY - shown.maxY + 16, shown.height / 2)
                : -min(shown.minY - frame.minY + 16, shown.height / 2)
            let start = scroll.coordinate(withNormalizedOffset: CGVector(dx: 0, dy: 0))
                .withOffset(CGVector(dx: 8, dy: shown.midY - scroll.frame.minY))
            start.press(
                forDuration: 0.1, thenDragTo: start.withOffset(CGVector(dx: 0, dy: -lift)), withVelocity: .slow,
                thenHoldForDuration: 0.3)
            drags += 1
        }
    }

    /// The TestHooks panel's touch counts: the touches the screens' touch guard saw, and those its press guard
    /// refused (TestHooks.swift).
    func touchCounts() -> (seen: Int, refused: Int) {
        (Int(element("hook_touches_seen").label) ?? -1, Int(element("hook_touches_refused").label) ?? -1)
    }

    /// The TestHooks panel's facts line (U1f): what the model holds, by fixed names, counts and yes or no
    /// alone, nothing secret (TestHooks.swift, the model's hookFacts).
    func facts() -> String {
        element("hook_facts").label
    }

    /// button pressed as a person presses it (U1d): once, then its effect awaited. Before each press, a button
    /// not wholly shown above the TestHooks panel is dragged into view first (U2h: XCUITest calls a control under
    /// the panel hittable, and its tap lands on the panel). A press that does nothing is told apart by the
    /// panel's touch counts: one the press guard refused (a view shown under 300 ms before, the app working as
    /// designed) or one that never reached the app's window is pressed again, the screen settled by then, each
    /// named in a probe line; one the app saw and admitted that did nothing is the app's defect, and fails the
    /// test there. At most three presses. placed: a public control, whose place the lines may give; a pad's key
    /// (a face, a letter, a symbol) is never placed, its place naming the key.
    func pressUntil(
        _ button: XCUIElement, _ what: String, placed: Bool = false, file: StaticString = #filePath, line: UInt = #line,
        effect: () -> Bool
    ) {
        for attempt in 1...3 {
            if !abovePanel(button) {
                bringIntoView(button, what + ", press \(attempt)", placed: placed)
            }
            let before = touchCounts()
            button.tap()
            if effect() || within(5, effect) { return }
            let after = touchCounts()
            // The facts first, then the button: a button gone with its screen is asked nothing that fails.
            var held = facts() + "; the button "
            held += button.exists
                ? "enabled \(button.isEnabled ? "yes" : "no"), hittable \(button.isHittable ? "yes" : "no")" : "gone"
            if placed { held += ", " + place(button) }
            if after.refused > before.refused {
                pass("probe: \(what): press \(attempt) refused by the press guard (touches \(before) to \(after)); \(held); pressed again")
            } else if after.seen == before.seen {
                pass("probe: \(what): press \(attempt) never reached the app (touches \(before) to \(after)); \(held); pressed again")
            } else {
                XCTFail(
                    "\(what): press \(attempt) reached the app and was admitted, and did nothing (touches \(before) to \(after)); \(held)",
                    file: file, line: line)
                return
            }
        }
        XCTFail("\(what): three presses did nothing", file: file, line: line)
    }

    /// The button id pressed once it is enabled, as a person presses a control that is offered.
    func pressEnabled(_ id: String, file: StaticString = #filePath, line: UInt = #line) {
        let button = buttons[id]
        XCTAssertTrue(within(30) { button.exists && button.isEnabled }, id + " never enabled; " + facts(), file: file, line: line)
        button.tap()
    }

    /// rolls pressed on the dice pad, then Done once enabled: the check prompt.
    func roll(_ rolls: String, file: StaticString = #filePath, line: UInt = #line) {
        rollFaces(rolls, file: file, line: line)
        pressEnabled("dice_done", file: file, line: line)
        on("check_prompt", "the check prompt", file: file, line: line)
    }

    /// rolls pressed on the dice pad, a face and Confirm each, each awaited (the face picked, which enables
    /// Confirm, then the count at that roll), one look at the screen a press.
    func rollFaces(_ rolls: String, file: StaticString = #filePath, line: UInt = #line) {
        let confirm = buttons["confirm"]
        let pick = element("kc_secret_dice_pick")
        let count = element("dice_count")
        for (index, face) in rolls.enumerated() {
            let roll = index + 1
            pressUntil(buttons["key_" + String(face)], "roll \(roll)'s face", file: file, line: line) {
                pick.label == String(face)
            }
            pressUntil(confirm, "roll \(roll)'s Confirm", file: file, line: line) { count.label.hasPrefix(String(roll) + " / ") }
        }
    }

    /// The letters typed on the letter pad so far (its secret node, kc_secret_typed_letters: each letter, then a
    /// dash for each face to come).
    func typedCount() -> Int {
        element("kc_secret_typed_letters").label.filter { $0 != "-" }.count
    }

    /// A word's first four letters (a three-letter word's three) pressed on the letter pad, each awaited.
    func letters(_ word: String, file: StaticString = #filePath, line: UInt = #line) {
        let start = typedCount()
        for (index, letter) in word.prefix(4).enumerated() {
            pressUntil(buttons[String(letter)], "letter \(index + 1) of a word", file: file, line: line) { self.typedCount() == start + index + 1 }
        }
    }

    /// keys pressed on the ASCII pad's page on show, each awaited on the BIP39 passphrase's entry (its secret
    /// node, kc_secret_bip39_text).
    func ascii(_ keys: String, file: StaticString = #filePath, line: UInt = #line) {
        let shown = element("kc_secret_bip39_text")
        let start = shown.label.count
        for (index, key) in keys.enumerated() {
            pressUntil(buttons[String(key)], "ASCII key \(index + 1)", file: file, line: line) { shown.label.count == start + index + 1 }
        }
    }

    /// The check QR on show read back from its picture: T and the nonce (the check request's text).
    func checkRequest(file: StaticString = #filePath, line: UInt = #line) throws -> (tag: [UInt8], nonce: [UInt8]) {
        let qr = element("check_request")
        XCTAssertTrue(qr.waitForExistence(timeout: 30), "the check QR", file: file, line: line)
        let picture = try XCTUnwrap(CIImage(image: qr.screenshot().image), file: file, line: line)
        let detector = try XCTUnwrap(
            CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]))
        let text = try XCTUnwrap((detector.features(in: picture).first as? CIQRCodeFeature)?.messageString, "no QR read", file: file, line: line)
        let pattern = try NSRegularExpression(pattern: "^https://registry\\.invalid/check#t=([0-9a-f]{64})&n=([0-9a-f]{16})$")
        let match = try XCTUnwrap(pattern.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)), "not a check request", file: file, line: line)
        let tag = String(text[try XCTUnwrap(Range(match.range(at: 1), in: text))])
        let nonce = String(text[try XCTUnwrap(Range(match.range(at: 2), in: text))])
        return (hexBytes(tag), hexBytes(nonce))
    }

    /// On the check QR: its go-ahead code typed on the code pad (Type go-ahead code), Done: the result.
    func typeGoAhead() throws {
        let (tag, nonce) = try checkRequest()
        let code = goAheadCode(tag, nonce)
        press("type_code")
        on("code_entry", "the code entry")
        let shown = element("code")
        for (index, symbol) in code.enumerated() {
            pressUntil(buttons["key_" + String(symbol)], "the code's symbol \(index + 1)") {
                shown.label.filter { $0 != "_" && $0 != "-" }.count == index + 1
            }
        }
        pressEnabled("code_done")
        on("check_result", "the check passed")
    }

    /// From the first insert (its gate passed): every insert's word read from the screen (with the device swap
    /// and its gate before word 13 of 24), equal to expected when given; the read-back of each, its first four
    /// letters on the letter pad, each a match; the read-back's end and the wallet summary. The words, in order.
    @discardableResult
    func wordsAndReadback(_ count: Int, expected: [String]? = nil, file: StaticString = #filePath, line: UInt = #line) -> [String] {
        var words: [String] = []
        let devices = count > 12 ? 2 : 1
        for position in 1...count {
            let device = position > 12 ? 2 : 1
            if position == 13 {
                press("next")
                on("device_swap", "the device swap", file: file, line: line)
                waitLabel("device_swap_text", "Words 13-24 go on device 2 of 2.", file: file, line: line)
                press("continue")
                passGate("word 13")
                on("words", "insert 13", file: file, line: line)
            } else if position > 1 {
                press("next")
            }
            waitLabel("insert_header", String(format: "Insert %02d \u{00B7} device %d of %d", position, device, devices), file: file, line: line)
            words.append(element("kc_secret_insert_word").label)
        }
        if let expected {
            XCTAssertTrue(words == expected, "the inserts are not the seed's words (none printed)", file: file, line: line)
        }
        press("start_readback")
        on("readback_entry", "the read-back's entry", file: file, line: line)
        for (index, word) in words.enumerated() {
            let position = index + 1
            let device = position > 12 ? 2 : 1
            waitLabel(
                "readback_header", String(format: "Read back insert %02d \u{00B7} device %d of %d", position, device, devices),
                file: file, line: line)
            letters(word, file: file, line: line)
            pressEnabled("letters_done", file: file, line: line)
            XCTAssertTrue(element("readback_matched").waitForExistence(timeout: 10), "insert \(position) matches", file: file, line: line)
            press("readback_next")
        }
        on("readback_done", "the read-back's end", file: file, line: line)
        press("show_summary")
        on("wallet", "the wallet summary", file: file, line: line)
        XCTAssertNotNil(element("fingerprint").label.range(of: "^[0-9a-f]{8}$", options: .regularExpression), "the fingerprint")
        return words
    }

    /// From the wallet summary: the backup made through its gate, the passphrase's two pages read from the
    /// screen, both questions answered on the letter pad, and Save answered by the Save hook (in memory, no
    /// file): "Backup verified", then the watch-only offer. The passphrase's eight words.
    func backupMadeAndSaved(verified: Bool = true, file: StaticString = #filePath, line: UInt = #line) throws -> [String] {
        press("summary_next")
        on("backup_offer", "the backup's offer", file: file, line: line)
        press("make_backup")
        passGate("the backup passphrase")
        on("backup_passphrase", "the backup passphrase", file: file, line: line)
        var words: [String] = []
        for page in 0..<2 {
            if page == 1 {
                press("next")
                waitLabel("passphrase_page", "Words 5-8 of 8", file: file, line: line)
            }
            let lines = element("kc_secret_passphrase_text").label.split(separator: "\n").map(String.init)
            XCTAssertEqual(lines.count, 4, "four words a page", file: file, line: line)
            for (index, text) in lines.enumerated() {
                let number = String(page * 4 + index + 1) + " "
                XCTAssertTrue(text.hasPrefix(number), "the page's numbering", file: file, line: line)
                words.append(String(text.dropFirst(number.count)))
            }
        }
        press("passphrase_written")
        on("backup_confirm", "the confirm", file: file, line: line)
        for question in 1...2 {
            waitLabel("confirm_question", "Check your copy: question \(question) of 2", file: file, line: line)
            let heading = staticTexts.matching(NSPredicate(format: "label BEGINSWITH %@", "Which is word ")).firstMatch
            XCTAssertTrue(heading.waitForExistence(timeout: 10), "the question", file: file, line: line)
            let position = try XCTUnwrap(Int(heading.label.dropFirst("Which is word ".count).dropLast()), file: file, line: line)
            letters(words[position - 1], file: file, line: line)
            pressEnabled("confirm_done", file: file, line: line)
        }
        on("backup_save", "the save", timeout: 120, file: file, line: line)
        XCTAssertNotNil(element("backup_name").label.range(of: "^keepcrypt-backup-[0-9a-f]{8}\\.age$", options: .regularExpression))
        press("save_backup")
        press("hook_save")
        if verified {
            on("backup_verified", "Backup verified", timeout: 120, file: file, line: line)
            press("backup_next")
        } else {
            on("save_failure", "the save's failure", timeout: 120, file: file, line: line)
            XCTAssertTrue(
                element("save_failure").label.hasPrefix("Backup not saved: the file read back does not verify ("),
                "the verify's refusal named", file: file, line: line)
            press("skip_backup")
        }
        on("watch_offer", "the watch-only offer", file: file, line: line)
        return words
    }

    /// From Home: Check a backup, its picker answered by the Backup file hook with the copy the Save hook kept,
    /// the gate, passphrase's first fours on the letter pad, Backup OK, the words through the gate, each equal to
    /// words, and Done: Home.
    func checkSavedBackup(_ passphrase: [String], _ words: [String], file: StaticString = #filePath, line: UInt = #line) {
        press("check_backup")
        press("hook_backup_file")
        passGate("the passphrase's entry")
        on("backup_check_entry", "the passphrase's entry", file: file, line: line)
        for (index, word) in passphrase.enumerated() {
            waitLabel("entry_word", "Backup passphrase, word \(index + 1) of 8", file: file, line: line)
            letters(word, file: file, line: line)
            pressEnabled("entry_done", file: file, line: line)
        }
        on("backup_check_result", "Backup OK", timeout: 120, file: file, line: line)
        press("show_backup_words")
        passGate("the backup's words")
        on("words", "the backup's insert 1", file: file, line: line)
        var read: [String] = []
        for position in 1...words.count {
            if position > 1 { press("next") }
            waitLabel("insert_header", String(format: "Insert %02d \u{00B7} device 1 of 1", position), file: file, line: line)
            read.append(element("kc_secret_insert_word").label)
        }
        XCTAssertTrue(read == words, "the checked backup holds the ceremony's words (none printed)", file: file, line: line)
        press("backup_words_done")
        on("backup_check_result", "back to the result", file: file, line: line)
        press("backup_done")
        on("home", "Home", file: file, line: line)
    }

    /// The notice line above the start screens: why the session was wiped (Ceremony.swift's noticeLine).
    func waitNotice(_ text: String, file: StaticString = #filePath, line: UInt = #line) {
        waitLabel("notice", text, timeout: 60, file: file, line: line)
    }

    /// From Home: a dice-only 12-word seed's dice, with rolls pressed (a session held from the start).
    func toDice(rolls: String = "", file: StaticString = #filePath, line: UInt = #line) {
        press("dice_only_seed")
        on("length", "Length", file: file, line: line)
        press("words_12")
        on("dice", "the dice", file: file, line: line)
        if !rolls.isEmpty { rollFaces(rolls, file: file, line: line) }
    }

    /// From the checklist: its two-devices line when the seed has two, and Finish: Home.
    func checklistToFinish(twoDevices: Bool = false, file: StaticString = #filePath, line: UInt = #line) {
        on("checklist", "the checklist", file: file, line: line)
        XCTAssertEqual(element("two_devices").exists, twoDevices, "the checklist's devices line", file: file, line: line)
        press("finish")
        on("home", "Home after Finish", file: file, line: line)
    }

    /// From the wallet summary, every export skipped: the backup, watch-only and the registration, to the
    /// checklist.
    func skipExports(file: StaticString = #filePath, line: UInt = #line) {
        press("summary_next")
        on("backup_offer", "the backup's offer", file: file, line: line)
        press("skip_backup")
        on("watch_offer", "the watch-only offer", file: file, line: line)
        press("skip_watch_only")
        on("register_offer", "the registration's offer", file: file, line: line)
        press("skip_registration")
    }
}
#endif
