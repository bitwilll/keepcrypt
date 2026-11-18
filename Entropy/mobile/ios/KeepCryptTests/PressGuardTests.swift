// The press guard's rule (tasks/todo.md, M6 item D2), ported from :screens' PressGuardTest.kt test for test
// (Stage U's U2i; lead decision M5-79): a new view (screen, gate or overlay) admits no touch while it has not
// been shown nor in the 300 ms after it was, and every touch from then on, judged by the touch's own time; a
// view that stays keeps its first showing's time. No slot is used.

import XCTest

final class PressGuardTests: XCTestCase {
    private let prompt = ShownView(screen: .checkPrompt, gate: false, overlay: nil)
    private let confirm = ShownView(screen: .skipConfirm, gate: false, overlay: nil)
    private let gated = ShownView(screen: .words, gate: true, overlay: nil)
    private let words = ShownView(screen: .words, gate: false, overlay: nil)
    private let covered = ShownView(screen: .words, gate: false, overlay: .cover)

    /// PressGuardTest.kt's nothingIsAdmittedBeforeAnyViewIsComposed.
    func testNothingIsAdmittedBeforeAnyViewIsShown() {
        let guarded = PressGuard()
        XCTAssertFalse(guarded.admits(prompt, 0), "a touch at the start")
        XCTAssertFalse(guarded.admits(prompt, 10_000), "a touch long after, no view shown")
    }

    /// PressGuardTest.kt's aNewViewAdmitsTouchesFrom300msAfterTheFrameThatComposedIt.
    func testANewViewAdmitsTouchesFrom300msAfterItWasShown() {
        let guarded = PressGuard()
        guarded.composed(prompt, 1_000)
        XCTAssertFalse(guarded.admits(prompt, 1_000), "as it was shown")
        XCTAssertFalse(guarded.admits(prompt, 1_299), "299 ms after it")
        XCTAssertTrue(guarded.admits(prompt, 1_300), "300 ms after it")
        XCTAssertTrue(guarded.admits(prompt, 60_000), "long after it")
    }

    /// PressGuardTest.kt's aDoubleTapsSecondTouchOnTheNextScreenDoesNothing.
    func testADoubleTapsSecondTouchOnTheNextScreenDoesNothing() {
        let guarded = PressGuard()
        guarded.composed(prompt, 0)
        XCTAssertTrue(guarded.admits(prompt, 5_000), "the first touch: Skip")
        guarded.composed(confirm, 5_016)
        XCTAssertFalse(guarded.admits(confirm, 5_060), "the second touch, 60 ms after the first, on the confirm screen")
        XCTAssertTrue(guarded.admits(confirm, 5_316), "a deliberate press once the confirm has been seen")
    }

    /// PressGuardTest.kt's aSecondTouchHandledLateIsJudgedByItsOwnTime.
    func testASecondTouchHandledLateIsJudgedByItsOwnTime() {
        let guarded = PressGuard()
        guarded.composed(prompt, 0)
        guarded.composed(confirm, 5_016)
        XCTAssertFalse(guarded.admits(confirm, 5_060), "the touch's time, not the time it is handled, decides")
    }

    /// PressGuardTest.kt's aTouchOnAViewNotYetComposedIsRefused.
    func testATouchOnAViewNotYetShownIsRefused() {
        let guarded = PressGuard()
        guarded.composed(prompt, 0)
        XCTAssertFalse(guarded.admits(confirm, 5_000), "the model shows the confirm, not yet shown")
        XCTAssertTrue(guarded.admits(prompt, 5_000), "a touch on the view shown and held")
    }

    /// PressGuardTest.kt's theGatePassedTheCoverAndItsRemovalAreEachANewView.
    func testTheGatePassedTheCoverAndItsRemovalAreEachANewView() {
        let guarded = PressGuard()
        guarded.composed(gated, 0)
        XCTAssertTrue(guarded.admits(gated, 400), "the gate's own button, once seen")
        guarded.composed(words, 410)
        XCTAssertFalse(guarded.admits(words, 470), "the words just past the gate")
        guarded.composed(covered, 31_000)
        XCTAssertFalse(guarded.admits(covered, 31_100), "the cover just up")
        guarded.composed(words, 32_000)
        XCTAssertFalse(guarded.admits(words, 32_050), "the words just uncovered")
        XCTAssertTrue(guarded.admits(words, 32_300))
    }

    /// PressGuardTest.kt's aViewThatStaysKeepsTheTimeItWasFirstComposed.
    func testAViewThatStaysKeepsTheTimeItWasFirstShown() {
        let guarded = PressGuard()
        guarded.composed(words, 0)
        guarded.composed(words, 10_000)
        XCTAssertTrue(guarded.admits(words, 400), "a redraw of the same view (a page, a roll, a key) reopened the guard")
    }

    /// M6-23: a press's action runs only if the touch that made it was admitted. iOS 26 runs a SwiftUI Button's
    /// action for a touch the touch guard refused (run 44326338905: a double tap's second touch, refused on the
    /// passphrase's entry, ran its Back 248 ms later), so the guard decides again when the action comes.
    func testAnActionAfterARefusedDownDoesNothing() {
        let guarded = PressGuard()
        guarded.composed(prompt, 0)
        guarded.composed(confirm, 5_016)
        guarded.noteDown(confirm, admitted: guarded.admits(confirm, 5_060))
        XCTAssertTrue(guarded.lastDownRefused, "the second touch, 44 ms after the confirm was shown, refused")
        XCTAssertFalse(guarded.permits(confirm, 5_308), "its action, 248 ms on, does nothing")
        XCTAssertFalse(guarded.permits(confirm, 60_000), "nor any action before the next touch")
    }

    func testAnActionAfterAnAdmittedDownRuns() {
        let guarded = PressGuard()
        guarded.composed(prompt, 0)
        guarded.noteDown(prompt, admitted: guarded.admits(prompt, 5_000))
        XCTAssertFalse(guarded.lastDownRefused)
        XCTAssertTrue(guarded.permits(prompt, 5_080), "a deliberate press's action")
    }

    func testAnAdmittedDownThenARefusedOneDropsTheActionThatComesAfterBoth() {
        let guarded = PressGuard()
        guarded.composed(gated, 0)
        guarded.noteDown(gated, admitted: guarded.admits(gated, 5_000))
        guarded.composed(words, 5_050)
        guarded.noteDown(words, admitted: guarded.admits(words, 5_120))
        XCTAssertFalse(guarded.permits(words, 5_370), "an action after an admitted down and a refused one")
    }

    func testARefusedDownOnAViewNotYetShownStillDropsTheActionOnceItIsShown() {
        let guarded = PressGuard()
        guarded.composed(gated, 0)
        guarded.noteDown(words, admitted: guarded.admits(words, 5_000))
        guarded.composed(words, 5_010)
        XCTAssertFalse(guarded.permits(words, 5_400), "the touch went down before the words were shown")
    }

    func testTheNextAdmittedDownOrAnotherViewEndsARefusal() {
        let guarded = PressGuard()
        guarded.composed(words, 0)
        guarded.noteDown(words, admitted: guarded.admits(words, 100))
        guarded.noteDown(words, admitted: guarded.admits(words, 2_000))
        XCTAssertTrue(guarded.permits(words, 2_080), "a later, admitted touch's action")
        guarded.noteDown(words, admitted: false)
        guarded.composed(covered, 31_000)
        XCTAssertFalse(guarded.lastDownRefused, "the refused touch's buttons are gone with its view")
        XCTAssertTrue(guarded.permits(covered, 31_400), "the cover's tap, once it was seen (an accessibility action, no touch)")
        XCTAssertFalse(guarded.permits(covered, 31_100), "an action within 300 ms of a new view, no touch: refused too")
    }

    /// The probe line names fixed names and times alone (PressGuard.kt's facts).
    func testTheFactsNameTheViewsAndTheirAge() {
        let guarded = PressGuard()
        XCTAssertEqual(guarded.facts(prompt, 0), "the press guard holds none; the model shows check_prompt")
        guarded.composed(gated, 100)
        XCTAssertEqual(guarded.facts(covered, 350), "the press guard holds words behind its gate, composed 250 ms ago; the model shows words under Cover")
    }
}
