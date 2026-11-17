// The screens' words are Android's (tasks/todo.md, M6 item D3): every fixed text the iPhone's start screens,
// overlays, notices and stop screen show (Texts.swift, Ceremony.swift's noticeLine and stopLine) is pinned
// against :screens' own Kotlin sources, bundled as file references (FirstLaunch.kt, StartScreens.kt,
// Screens.kt, HomeScreens.kt, Kit.kt, BackupScreens.kt, and from D4 CheckScreens.kt, Drawing.kt and
// WordsScreens.kt), as WireTests pins Wire.swift against wire.rs: each
// text is a string literal there, once Kotlin's "a " + "b" splits over lines are joined. So a wording
// change on either side fails here until both agree. The iPhone's own lines (the offline check's, a
// screenshot's notice) are named and checked to be no Kotlin literal. Also the laid-out values: the dice
// line and C's hex groups against StartScreensTest.kt's specimens, and Home's lines against Android's.

import XCTest

final class ScreenTextsTests: XCTestCase {
    /// The bundled Kotlin sources, each with its string literals' line splits joined.
    private func kotlin() throws -> String {
        var joined = ""
        for name in ["FirstLaunch", "StartScreens", "Screens", "HomeScreens", "Kit", "BackupScreens", "CheckScreens", "Drawing", "WordsScreens"] {
            let text = try XCTUnwrap(String(data: Vectors.resource(name, "kt"), encoding: .utf8), "\(name).kt")
            joined += text + "\n"
        }
        // "a " +\n    "b" is the literal "a b".
        let split = try NSRegularExpression(pattern: "\"\\s*\\+\\s*\\n\\s*\"")
        return split.stringByReplacingMatches(in: joined, range: NSRange(joined.startIndex..., in: joined), withTemplate: "")
    }

    /// Every text the start screens and the shell show that Android shows too.
    private var shared: [String] {
        [
            StartTexts.firstLaunchMakes, StartTexts.firstLaunchPi, StartTexts.firstLaunchCannotStop,
            StartTexts.firstLaunchOffline, StartTexts.continueButton, StartTexts.selfTestRunning, StartTexts.selfTestFailure,
            StartTexts.goOfflineNeeds, StartTexts.start, StartTexts.homeModes, StartTexts.newSeed, StartTexts.diceOnlySeed,
            StartTexts.checkBackup, StartTexts.loadSnapshot, StartTexts.about, StartTexts.noSnapshot, StartTexts.lengthNote,
            StartTexts.twelveWords, StartTexts.twentyFourWords, StartTexts.safeIfEither, StartTexts.deviceEntropyNote,
            StartTexts.commitmentNote, StartTexts.picked, StartTexts.undo, StartTexts.confirm, StartTexts.done,
            StartTexts.diceMinimum, StartTexts.diceCap, StartTexts.diceHow, StartTexts.diceOnly, appName,
            ShellTexts.working, ShellTexts.stopped, ShellTexts.stopNote, ShellTexts.closeApp, ShellTexts.coverLine,
            ShellTexts.warningLine, ShellTexts.testRegistry, ShellTexts.moreBelow, privacyGateTitle, coverTitle,
            idleWarningTitle, noticeLine(.left), noticeLine(.offline), noticeLine(.idle), noticeLine(.background),
            fileRefusalText(.noSize), fileRefusalText(.tooLarge), fileRefusalText(.snapshotTooLarge),
            fileRefusalText(.unreadable),
            CheckTexts.question, CheckTexts.prompt, CheckTexts.checkNow, CheckTexts.skip, CheckTexts.skipConfirm,
            CheckTexts.skipAction, CheckTexts.skipped, CheckTexts.sealCardNote, CheckTexts.showCheckQr, CheckTexts.scanQr,
            CheckTexts.typeCode, CheckTexts.matchFound, CheckTexts.cannotCheck, CheckTexts.checkQrNote, CheckTexts.actions,
            CheckTexts.back, CheckTexts.codeHow, CheckTexts.codeRefused, CheckTexts.delete, CheckTexts.matchFoundConsequence,
            CheckTexts.destroy, CheckTexts.cannotCheckConsequence, CheckTexts.startAgain, CheckTexts.collisionFound,
            CheckTexts.collisionSuspect, CheckTexts.collisionNext, CheckTexts.showReport, CheckTexts.reportNote,
            CheckTexts.addFreshEntropy, CheckTexts.checkSkipped, CheckTexts.checkPassed, CheckTexts.wordsNext,
            CheckTexts.showWords, CheckTexts.stale, CheckTexts.future, CheckTexts.scanGuide, CheckTexts.scanning,
            CheckTexts.scanRefused, CheckTexts.scanMissing, CheckTexts.scanFailed, CheckTexts.scanNotAccepted,
            CheckTexts.scanNoRegistryKey, CheckTexts.snapshotNotLoaded, CheckTexts.snapshotLoaded,
            CheckTexts.snapshotLoadedNote, CheckTexts.snapshotRejected, CheckTexts.snapshotNoRegistryKey, GateTexts.line,
            GateTexts.action, GateTexts.headphones, GateTexts.seedBookRules, ShellTexts.redacted,
            WordsTexts.readbackHow, WordsTexts.readbackMatched, WordsTexts.mirrors, WordsTexts.reviewing,
            WordsTexts.readbackComplete, WordsTexts.deviceSwap, WordsTexts.deviceSwapWords, WordsTexts.compareAfterRestore,
            WordsTexts.backToReadback, WordsTexts.previous, WordsTexts.next, WordsTexts.overview, WordsTexts.startReadback,
            WordsTexts.insertView, WordsTexts.overviewNote, WordsTexts.readAgain, WordsTexts.showInsert,
            WordsTexts.fingerprint, WordsTexts.firstAddress, faceLabel(blank: true, mirror: false),
            faceLabel(blank: false, mirror: true),
        ] + HaltReason.allCases.map(stopLine) + QrKind.allCases.map(\.spoken)
    }

    func testEveryTextIsAndroidsLiteral() throws {
        let source = try kotlin()
        for text in shared {
            XCTAssertTrue(source.contains("\"" + text + "\""), "not Android's: " + text)
        }
        XCTAssertEqual(stopLine(nil), stopLine(.internal), "no reason: internal's line, as Android's")
        // Built from parts there: the version, and the two file names' suffixes.
        XCTAssertTrue(source.contains("const val APP_VERSION = \"" + appVersion + "\""))
        XCTAssertTrue(source.contains("\"$APP_VERSION development build: do not use for real funds.\""))
        XCTAssertEqual(developmentBuild, "0.0.0 development build: do not use for real funds.")
        XCTAssertEqual(fileRefusalText(.notAge), "That file was not opened: a KeepCrypt backup's name ends in .age.")
        XCTAssertTrue(source.contains("\"That file was not opened: a KeepCrypt backup's name ends in \" + Core.BACKUP_SUFFIX + \".\""))
        XCTAssertEqual(fileRefusalText(.notKcr), "That file was not opened: a registry snapshot's name ends in .kcr.")
        XCTAssertTrue(source.contains("\"That file was not opened: a registry snapshot's name ends in \" + Core.SNAPSHOT_SUFFIX + \".\""))
        XCTAssertTrue(source.contains("\"Snapshot No. ${loaded.number}, dated ${registryDate(loaded.date)}\""))
        XCTAssertTrue(source.contains("\"$rolls / $minimum rolls, ${tenths / 10}.${tenths % 10} bits\""))
        XCTAssertTrue(source.contains("\"Snapshot No. ${header.number}, dated ${registryDate(header.date)}, ${header.count} entries.\""))
        XCTAssertTrue(source.contains("\"Proof from snapshot No. ${header.number}, dated ${registryDate(header.date)}: $entries in this seal's bucket.\""))
        XCTAssertTrue(source.contains("\"No collision for seal $sealId, as of the date your checker showed.\""))
        XCTAssertTrue(source.contains("\"No collision for seal $sealId as of ${registryDate(registry.date)}.\""))
        // The words' headers, as WordsScreens.kt builds them.
        XCTAssertTrue(source.contains("private const val PARTS = \" \u{00B7} \""))
        XCTAssertTrue(source.contains("\"Insert \" + digits(insert.position, 2) + PARTS + deviceText(insert)"))
        XCTAssertTrue(source.contains("\"Read back insert \" + digits(insert.position, 2) + PARTS + deviceText(insert)"))
        XCTAssertTrue(source.contains("\" does not match\" + PARTS"))
        XCTAssertTrue(source.contains("\"SeedBook \" + digits(number, 4)"))
        XCTAssertTrue(source.contains("\"Face 6: the engraved number \" + digits(sequence, 2)"))
        for verdict in ["\"ok\"", "\"mirror misread\"", "\"should be blank\"", "\"should have a letter\"", "\"wrong letter: missing\"", "\", extra\"", "\" none\""] {
            XCTAssertTrue(source.contains(verdict), "WordsScreens.kt's verdict text " + verdict)
        }
        for (refusal, tail) in [(Refusal.badSignature, "bad signature"), (.proofCount, "more bucket entries than the snapshot holds")] {
            XCTAssertEqual(snapshotRefusalText(refusal), CheckTexts.snapshotRejected + tail)
            XCTAssertTrue(source.contains("SNAPSHOT_REJECTED + \"" + tail + "\""))
        }
    }

    func testTheIphonesOwnLinesAreNoAndroidLiteral() throws {
        let source = try kotlin()
        for text in [StartTexts.pathNone, StartTexts.pathUsable, StartTexts.startDisabled, noticeLine(.screenshot), CheckTexts.openSettings] {
            XCTAssertFalse(source.contains("\"" + text + "\""), "an Android text marked the iPhone's own: " + text)
        }
        XCTAssertTrue(source.contains("\"Start stays disabled until airplane mode is on and Wi-Fi is off.\""), "Android's line the iPhone's stands for")
    }

    /// StartScreensTest.kt's hexGroupsAndTheDiceLineMatchThePi.
    func testHexGroupsAndTheDiceLineMatchThePi() {
        let specimen = Secret(taking: (0..<32).map { UInt8($0) })
        XCTAssertEqual(hexGroups(specimen), "0001 0203 0405 0607\n0809 0a0b 0c0d 0e0f\n1011 1213 1415 1617\n1819 1a1b 1c1d 1e1f")
        XCTAssertEqual(hexGroups(Secret(taking: [UInt8](repeating: 0xFF, count: 32))), "ffff ffff ffff ffff\nffff ffff ffff ffff\nffff ffff ffff ffff\nffff ffff ffff ffff")
        XCTAssertEqual(diceText(37, 50, 37 * 2_585), "37 / 50 rolls, 95.6 bits")
        XCTAssertEqual(diceText(0, 50, 0), "0 / 50 rolls, 0.0 bits")
        XCTAssertEqual(diceText(99, 99, 99 * 2_585), "99 / 99 rolls, 255.9 bits")
        XCTAssertEqual(diceText(256, 99, 256 * 2_585), "256 / 99 rolls, 661.7 bits")
    }

    /// Home's snapshot line and the registry date, as HomeScreens.kt and CheckScreens.kt lay them out.
    func testHomesSnapshotLine() {
        XCTAssertEqual(homeSnapshotLine(nil), "No registry snapshot loaded")
        XCTAssertEqual(homeSnapshotLine(RegistryHeader(number: 7, date: 20_260_301, count: 3, freshness: .current)), "Snapshot No. 7, dated 2026-03-01")
        XCTAssertEqual(registryDate(301), "0000-03-01")
    }
}
