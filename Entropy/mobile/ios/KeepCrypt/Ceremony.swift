// The Swift CeremonyModel's file (tasks/todo.md, M6 items A2, C3 and C5; lead decision M6-6). In Stage C
// it holds the one way the app ends itself, Ceremony.halt, the start-up self-test's outcome, and the
// model of Stage C's screens: the start-up self-test, Go offline and Home, with the two rules that act
// on every screen, the screenshot discard and going online. The ceremony's screens and the rest of the
// model come in Stage D.

import Combine
import Foundation

/// The app's end (rule 3, fail closed; docs/mobile-apps.md, "When something fails"): every error the
/// app cannot answer with a screen ends here, and so does the stop screen's one action. The gate
/// allows no other type of this name and no other halt, and every error handler under mobile/ios
/// ends in this call or a rethrow.
enum Ceremony {
    /// Why the app ends: fixed cases, never a message (rule 5).
    enum End {
        /// The stop screen's "Close app".
        case closed
        /// The bridge or the app broke its own contract: a value the app cannot have made, a wipe
        /// that did not happen.
        case bridge
    }

    /// Halts the slot, which drops everything it held, wipes Core's reply buffer and ends the process
    /// at once: no dialog and no message (a message could hold a secret). The next start runs the
    /// self-test again before anything else.
    static func halt(_ end: End) -> Never {
        let wiped = Core.shared.endForExit()
        exit(end == .closed && wiped ? 0 : 1)
    }
}

/// What the app shows once the start-up self-test has run (docs/mobile-apps.md, step 2: a failure
/// blocks every ceremony): passed, or the stop screen with the slot's reason. Only an OK reply passes;
/// a refusal or a discard, which the self-test never gives, stops the app as internal (fail closed).
enum StartScreen: Equatable {
    case passed
    case stopped(HaltReason)

    init(selfTest: Reply<Void>) {
        switch selfTest {
        case .done:
            self = .passed
        case .halted(let reason):
            self = .stopped(reason)
        case .refused, .discarded:
            self = .stopped(.internal)
        }
    }

    /// The start-up self-test, run off the main thread (a nonisolated async function), and its screen.
    static func afterSelfTest() async -> StartScreen {
        StartScreen(selfTest: Core.shared.selfTest())
    }
}

/// The stop screen's line for why the slot halted (Android's stopLine, pi-firmware.md's "Finish and
/// halts"): one fixed line per reason, built from no data.
func stopLine(_ reason: HaltReason) -> String {
    switch reason {
    case .knownAnswerTest: return "A known-answer test failed."
    case .entropySource: return "The entropy source failed."
    case .healthTest: return "An entropy health test failed."
    case .exportSelfCheck: return "The watch-only export failed its self-check."
    case .panic: return "The app's core stopped unexpectedly."
    case .internal: return "An internal check failed."
    }
}

/// Stage C's screens (docs/mobile-apps.md, steps 2 and 3; Android's Screen, whose list Stage D's
/// shared table brings in full).
enum Screen: Equatable {
    /// The start-up self-test, running.
    case selfTest
    /// The stop screen: the self-test did not pass, or the slot halted.
    case stopped(HaltReason)
    /// Go offline: the network state, and Start only while no path is usable.
    case goOffline
    /// Home, which Go offline's Start opens; the ceremony starts from here in Stage D.
    case home

    /// Whether the screen holds a session or a file (Android's holds()): none of Stage C's does.
    var holds: Bool { false }

    /// Whether the screen needs the phone offline (Android's needsOffline): every one from Home on.
    var needsOffline: Bool { self == .home }
}

/// Why the session went, said on the screen the app returns to (Android's Notice).
enum Notice: Equatable {
    /// A screenshot was taken (docs/mobile-apps.md, "Screen capture protection: iPhone").
    case screenshot
    /// The phone went online (docs/mobile-apps.md, the offline row).
    case offline
}

/// The notice's line: fixed text, built from no data.
func noticeLine(_ notice: Notice) -> String {
    switch notice {
    case .screenshot:
        return "The session was wiped: a screenshot was taken. A screenshot can keep what the screen showed, so nothing it may have held is used again."
    case .offline:
        return "The session was wiped: the phone went online."
    }
}

/// What a report of the offline check does (Android's offlineChanged, mirrored).
enum PathStep: Equatable {
    /// Only the state changes.
    case nothing
    /// The session is discarded at once and the start screen says why.
    case discard
    /// Go offline comes back, with nothing to say.
    case goOffline
}

/// The model of Stage C's screens. It owns the session's two app-wide rules: a screenshot discards
/// whatever session exists, on every screen (docs/mobile-apps.md: the screenshot response), and going
/// online after the start-up discards a session held or brings Go offline back (the offline row,
/// Android's rule). Core is reached through the two calls the model is given, so its tests can watch
/// them; the app gives Core's own.
@MainActor
final class CeremonyModel: ObservableObject {
    @Published private(set) var screen: Screen = .selfTest
    @Published private(set) var notice: Notice?
    /// No usable network path, as the offline check last reported it; until its first report the
    /// phone counts as online, so Start stays disabled (fail closed).
    @Published private(set) var offline = false
    /// Whether the start-up self-test has passed.
    private(set) var started = false

    private var begun = false
    private let selfTest: () async -> StartScreen
    private let discardCall: () -> Reply<Void>

    init(
        selfTest: @escaping () async -> StartScreen = { await StartScreen.afterSelfTest() },
        discard: @escaping () -> Reply<Void> = { Core.shared.discard() }
    ) {
        self.selfTest = selfTest
        discardCall = discard
    }

    /// The start-up self-test, once (the capture layers' root runs it when the scene appears): then
    /// Go offline, or the stop screen with the slot's reason.
    func startUp() async {
        guard !begun else { return }
        begun = true
        let outcome = await selfTest()
        if case .stopped = screen { return }
        switch outcome {
        case .passed:
            started = true
            if screen == .selfTest { screen = .goOffline }
        case .stopped(let reason):
            screen = .stopped(reason)
        }
    }

    /// Go offline's Start: Home, only while no path is usable (online the button is disabled, and a
    /// press does nothing).
    func startOffline() {
        guard offline, screen == .goOffline else { return }
        notice = nil
        screen = .home
    }

    /// The offline check's report, on every change of the path: offline is no usable path.
    func pathReported(offline now: Bool) {
        if case .stopped = screen { return }
        offline = now
        switch CeremonyModel.afterPathReport(
            offline: now, started: started, holds: screen.holds, needsOffline: screen.needsOffline)
        {
        case .nothing:
            break
        case .goOffline:
            screen = .goOffline
        case .discard:
            discard(.offline)
        }
    }

    /// Android's offlineChanged: offline, or before the start-up self-test has passed, only the state
    /// changes; online after it, a session held is discarded at once and the start screen says why,
    /// and a screen past Go offline that holds nothing goes back to Go offline, with nothing to say.
    /// (A stopped app takes no report.) Stage D's long calls join holds here, as Android's running.
    nonisolated static func afterPathReport(offline: Bool, started: Bool, holds: Bool, needsOffline: Bool) -> PathStep {
        if offline || !started { return .nothing }
        if holds { return .discard }
        if needsOffline { return .goOffline }
        return .nothing
    }

    /// The screenshot response (docs/mobile-apps.md, "Screen capture protection: iPhone"): a screenshot
    /// can keep whatever the screen showed, so on every screen, a secret held or not, Core's discard
    /// drops whatever session exists, and the screen says why. A stopped app has nothing to discard.
    func discardAfterScreenshot() {
        if case .stopped = screen { return }
        discard(.screenshot)
    }

    /// Core's discard, and the screen it leaves: the notice on the start screen (Home while offline,
    /// Go offline online, for a screen past Go offline; the start-up and Go offline stay), or the stop
    /// screen if the slot halted or broke the bridge's contract (a discard is never refused).
    private func discard(_ why: Notice) {
        switch discardCall() {
        case .done:
            notice = why
            if started, screen.needsOffline { screen = offline ? .home : .goOffline }
        case .halted(let reason):
            screen = .stopped(reason)
        case .refused, .discarded:
            screen = .stopped(.internal)
        }
    }
}
