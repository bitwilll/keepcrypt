// The capture layers' own parts (tasks/todo.md, M6 item C5): which cover the scene needs in each state,
// and Q88's secure layer, which must host its content inside the secure field's drawing view and never
// take input. The covers and the screenshot discard in the running app are CaptureUITests'.

import SwiftUI
import UIKit
import XCTest

@MainActor
final class CaptureLayerTests: XCTestCase {
    func testTheCoverForEachState() {
        XCTAssertNil(CaptureCover.of(captured: false, active: true), "active and not captured: the content")
        XCTAssertEqual(CaptureCover.of(captured: false, active: false), .privacy, "the app switcher's snapshot")
        XCTAssertEqual(CaptureCover.of(captured: true, active: true), .capture)
        XCTAssertEqual(CaptureCover.of(captured: true, active: false), .capture, "capture first")
    }

    func testTheSecureLayerHostsItsContentInsideTheSecureField() throws {
        let layer = SecureLayerView(content: AnyView(Text("secure layer probe")))
        layer.frame = CGRect(x: 0, y: 0, width: 320, height: 120)
        layer.layoutIfNeeded()
        XCTAssertTrue(layer.field.isSecureTextEntry)
        XCTAssertFalse(layer.field.isUserInteractionEnabled, "no touch reaches the field")
        XCTAssertFalse(layer.field.isFirstResponder, "never first responder, so no keyboard")
        XCTAssertFalse(layer.field.isAccessibilityElement)
        XCTAssertTrue(layer.field.superview === layer)
        let canvas = try XCTUnwrap(layer.canvas, "the secure field's drawing view")
        XCTAssertTrue(canvas.superview === layer.field, "the field's own subview")
        XCTAssertTrue(layer.host.view.superview === canvas, "the content inside it")
        XCTAssertEqual(layer.field.frame.size, layer.bounds.size, "the field fills the layer")
    }
}
