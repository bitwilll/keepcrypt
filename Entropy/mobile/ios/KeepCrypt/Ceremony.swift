// The Swift CeremonyModel's file (tasks/todo.md, M6 items A2 and C3; lead decision M6-6). In Stage C it
// holds the one way the app ends itself, Ceremony.halt, and the start-up self-test's outcome; the
// ceremony's screens and their model come in Stage D.

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
