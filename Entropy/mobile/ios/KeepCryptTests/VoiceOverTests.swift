// What VoiceOver is told (tasks/todo.md, M6 item D8), held to Android's semantics in :screens' Kotlin sources
// (bundled, as ScreenTextsTests reads them): VoiceOver.swift's table, kind by kind (a heading and the title
// are headers, as Kit.kt's heading(); a live line and the notice polite, as its LiveRegionMode.Polite; a QR
// code an image named by its kind, as Drawing.kt's Role.Image and contentDescription; a pad's key a button
// named by its label, as Pads.kt's Role.Button and text; the overlays a button, as their clickable); the live
// lines, tag for tag with Android's live = true, and the iPhone's one more; the QR codes' names and the keys'
// labels as Android's; and Android using no stateDescription. No slot is used.

import XCTest

final class VoiceOverTests: XCTestCase {
    /// The bundled Kotlin sources, joined.
    private func kotlin() throws -> String {
        var joined = ""
        for name in ["FirstLaunch", "StartScreens", "Screens", "HomeScreens", "Kit", "BackupScreens", "CheckScreens", "Drawing", "WordsScreens", "ExportScreens", "Pads"] {
            let text = try XCTUnwrap(String(data: Vectors.resource(name, "kt"), encoding: .utf8), "\(name).kt")
            joined += text + "\n"
        }
        return joined
    }

    func testTheTableIsAndroidsSemanticsKindByKind() throws {
        let source = try kotlin()
        XCTAssertEqual(spokenSemantics(.heading), SpokenSemantics(header: true))
        XCTAssertEqual(spokenSemantics(.title), SpokenSemantics(header: true))
        XCTAssertTrue(source.contains("fun Heading(text: String) {\n    BasicText(text, Modifier.padding(vertical = 6.dp).semantics { heading() }"))
        XCTAssertTrue(source.contains("fun Title(text: String) {\n    BasicText(text, Modifier.padding(vertical = 6.dp).semantics { heading() }"))
        XCTAssertTrue(source.contains("BasicText(\"Working...\", Modifier.semantics { heading() }"), "Working's heading")

        XCTAssertEqual(spokenSemantics(.liveLine), SpokenSemantics(updatesFrequently: true, announced: true))
        XCTAssertEqual(spokenSemantics(.notice), spokenSemantics(.liveLine))
        XCTAssertTrue(source.contains("val spoken = if (live) padded.semantics { liveRegion = LiveRegionMode.Polite } else padded"))
        XCTAssertTrue(source.contains(".semantics { liveRegion = LiveRegionMode.Polite }\n            .testTag(\"notice\")"), "the notice is polite")

        XCTAssertEqual(spokenSemantics(.qrCode), SpokenSemantics(image: true, labelled: true))
        XCTAssertTrue(source.contains("contentDescription = kind.spoken\n            role = Role.Image"))

        XCTAssertEqual(spokenSemantics(.padKey), SpokenSemantics(button: true, labelled: true))
        XCTAssertTrue(source.contains("role = Role.Button\n            text = AnnotatedString(label)\n            isSensitiveData = true"), "a Protected key")
        XCTAssertTrue(source.contains("cell.semantics { role = Role.Button }.testTag(\"key_$label\")"), "a Public key")

        XCTAssertEqual(spokenSemantics(.overlay), SpokenSemantics(button: true))
        XCTAssertTrue(source.contains(".clickable(onClick = dismiss)\n            .semantics { paneTitle = title }"), "an overlay")

        XCTAssertFalse(source.contains("stateDescription"), "Android uses no stateDescription, so nothing stands for it")
        XCTAssertEqual(Set(Spoken.allCases.map(spokenSemantics)).count, 5, "five kinds of semantics")
    }

    func testTheLiveLinesAreAndroidsTagForTag() throws {
        let source = try kotlin()
        let pattern = try NSRegularExpression(pattern: "tag = \"([a-z_]+)\", live = true")
        var android = Set<String>()
        for match in pattern.matches(in: source, range: NSRange(source.startIndex..., in: source)) {
            if let range = Range(match.range(at: 1), in: source) { android.insert(String(source[range])) }
        }
        XCTAssertTrue(source.contains("tag = MORE_BELOW_TAG, live = true"))
        XCTAssertTrue(source.contains("const val MORE_BELOW_TAG = \"more_below\""))
        android.insert("more_below")
        XCTAssertEqual(androidLiveLineIds, android, "Android's live lines")
        XCTAssertEqual(liveLineIds.subtracting(androidLiveLineIds), ["network_state"], "the iPhone's own")
        XCTAssertFalse(source.contains("tag = \"network_state\""), "network_state is the iPhone's own line")
    }

    func testTheQrCodesAreNamedByKindAndTheKeysByTheirLabels() throws {
        let source = try kotlin()
        let names = QrKind.allCases.map(\.spoken)
        XCTAssertEqual(Set(names).count, QrKind.allCases.count, "each kind its own name")
        for name in names {
            XCTAssertTrue(name.contains("QR code"), "named as a QR code: " + name)
            XCTAssertTrue(source.contains("(\"" + name + "\")"), "Drawing.kt's QrKind: " + name)
        }
        XCTAssertEqual(QrKind.allCases.count, 6, "check, collision report, account, descriptor, registration, re-check")
        XCTAssertTrue(source.contains("fun keyLabel(key: Char): String = if (key == ' ') \"space\" else key.toString()"))
        XCTAssertEqual(keyLabel(" "), "space")
        for key in letterKeys + asciiKeys where key != " " {
            XCTAssertEqual(keyLabel(key), String(key), "a key's label is its letter")
        }
    }
}
