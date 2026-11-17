// Every timer rule and boundary on a fake clock (tasks/todo.md, M6 item D2), ported from :screens'
// TimersTest.kt test for test: the cover at 30 s on a Protected screen, the warning at 9 minutes and the idle
// wipe at 10 while a session is held, the background wipe at 60 s away (59 s keeps, 60 s wipes), and the
// picker rule, whose exemption ends at the app's next resume. No slot is used.

import XCTest

final class TimersTests: XCTestCase {
    private let clock = FakeClock()
    private lazy var timers = Timers(clock: clock)

    /// The timers made at time 0, as TimersTest.kt's are with its class.
    override func setUp() {
        _ = timers
    }

    private func at(_ millis: Int64, onProtected: Bool, holdsSecrets: Bool) -> TimerStep? {
        clock.now = millis
        return timers.step(onProtected: onProtected, holdsSecrets: holdsSecrets)
    }

    /// TimersTest.kt's aProtectedScreenIsCoveredAt30sAndAPublicOneNever.
    func testAProtectedScreenIsCoveredAt30sAndAPublicOneNever() {
        XCTAssertNil(at(29_999, onProtected: true, holdsSecrets: false))
        XCTAssertEqual(at(30_000, onProtected: true, holdsSecrets: false), .cover)
        XCTAssertEqual(at(30_000, onProtected: true, holdsSecrets: true), .cover)
        XCTAssertNil(at(30_000, onProtected: false, holdsSecrets: true))
        XCTAssertNil(at(539_999, onProtected: false, holdsSecrets: false))
    }

    /// TimersTest.kt's theWarningComesAt9MinutesOnlyWhileASessionIsHeld.
    func testTheWarningComesAt9MinutesOnlyWhileASessionIsHeld() {
        XCTAssertNil(at(539_999, onProtected: false, holdsSecrets: true))
        XCTAssertEqual(at(540_000, onProtected: false, holdsSecrets: true), .warn)
        XCTAssertEqual(at(540_000, onProtected: true, holdsSecrets: true), .warn)
        XCTAssertNil(at(540_000, onProtected: false, holdsSecrets: false))
        XCTAssertEqual(at(540_000, onProtected: true, holdsSecrets: false), .cover)
    }

    /// TimersTest.kt's theIdleWipeComesAt10MinutesWithASessionOrOnAProtectedScreen.
    func testTheIdleWipeComesAt10MinutesWithASessionOrOnAProtectedScreen() {
        XCTAssertEqual(at(599_999, onProtected: false, holdsSecrets: true), .warn)
        XCTAssertEqual(at(600_000, onProtected: false, holdsSecrets: true), .idleWipe)
        XCTAssertEqual(at(599_999, onProtected: true, holdsSecrets: false), .cover)
        XCTAssertEqual(at(600_000, onProtected: true, holdsSecrets: false), .idleWipe)
        XCTAssertNil(at(600_000, onProtected: false, holdsSecrets: false))
        XCTAssertNil(at(6_000_000, onProtected: false, holdsSecrets: false))
    }

    /// TimersTest.kt's inputStartsTheIdleTimeAgain.
    func testInputStartsTheIdleTimeAgain() {
        clock.now = 500_000
        timers.input()
        XCTAssertNil(at(529_999, onProtected: true, holdsSecrets: true))
        XCTAssertEqual(at(530_000, onProtected: true, holdsSecrets: true), .cover)
        XCTAssertEqual(at(1_040_000, onProtected: false, holdsSecrets: true), .warn)
        XCTAssertEqual(at(1_100_000, onProtected: false, holdsSecrets: true), .idleWipe)
    }

    /// TimersTest.kt's sixtySecondsAwayWipesAndFiftyNineKeeps.
    func testSixtySecondsAwayWipesAndFiftyNineKeeps() {
        clock.now = 10_000
        timers.input()
        XCTAssertTrue(timers.left())
        XCTAssertNil(at(69_000, onProtected: false, holdsSecrets: true))
        XCTAssertNil(at(69_999, onProtected: false, holdsSecrets: true))
        XCTAssertEqual(at(70_000, onProtected: false, holdsSecrets: true), .backgroundWipe)
        XCTAssertNil(at(70_000, onProtected: false, holdsSecrets: false), "with nothing held there is nothing to wipe")
        XCTAssertEqual(at(600_000, onProtected: false, holdsSecrets: true), .backgroundWipe, "before a warning due at the same time")
    }

    /// TimersTest.kt's aReturnWithin60sEndsTheBackgroundTime.
    func testAReturnWithin60sEndsTheBackgroundTime() {
        XCTAssertTrue(timers.left())
        clock.now = 59_000
        timers.returned()
        XCTAssertNil(at(60_000, onProtected: false, holdsSecrets: true))
        XCTAssertNil(at(120_000, onProtected: false, holdsSecrets: true))
        XCTAssertTrue(timers.left(), "leaving again starts it afresh")
        XCTAssertNil(at(179_999, onProtected: false, holdsSecrets: true))
        XCTAssertEqual(at(180_000, onProtected: false, holdsSecrets: true), .backgroundWipe)
    }

    /// TimersTest.kt's aPickerTheAppOpenedIsForegroundTimeUnderTheIdleRules.
    func testAPickerTheAppOpenedIsForegroundTimeUnderTheIdleRules() {
        timers.pickerOpened()
        XCTAssertFalse(timers.left(), "a picker the app opened is no leaving")
        XCTAssertNil(at(60_000, onProtected: false, holdsSecrets: true), "no background wipe however long it stays up")
        XCTAssertNil(at(539_999, onProtected: false, holdsSecrets: true))
        XCTAssertEqual(at(540_000, onProtected: false, holdsSecrets: true), .warn, "its time counts under the 10-minute rule")
        XCTAssertEqual(at(600_000, onProtected: false, holdsSecrets: true), .idleWipe)
        timers.returned()
        clock.now = 700_000
        timers.input()
        XCTAssertTrue(timers.left(), "back from the picker, the next leaving is leaving again")
        XCTAssertEqual(at(760_000, onProtected: false, holdsSecrets: true), .backgroundWipe)
    }

    /// TimersTest.kt's aPickerOpenedThatNoStopFollowedEndsAtTheNextResume.
    func testAPickerOpenedThatNoLeavingFollowedEndsAtTheNextResume() {
        timers.pickerOpened()
        timers.resumed()
        XCTAssertTrue(timers.left(), "the next leaving is leaving again")
        XCTAssertNil(at(59_999, onProtected: false, holdsSecrets: true))
        XCTAssertEqual(at(60_000, onProtected: false, holdsSecrets: true), .backgroundWipe)
    }
}
