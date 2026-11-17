// The phone's timers (tasks/todo.md, M6 item D2; :screens' Timers.kt; Q57; docs/pi-firmware.md, "Protected
// screens and idle"; docs/mobile-apps.md, "Session lifetime"), on the injected monotonic clock. They keep
// no thread and schedule nothing: the model asks step on each tick and on every return to the app.

/// What the timers ask of the ceremony model (the Pi's IdleStep, pi/app/src/input.rs, and the phone's
/// background wipe).
enum TimerStep: Equatable {
    /// Cover the Protected screen; the next tap only uncovers it.
    case cover
    /// The idle wipe is a minute away; any tap keeps everything.
    case warn
    /// 10 minutes without input: the session is wiped.
    case idleWipe
    /// 60 s away from the app on a Public screen: the session is wiped.
    case backgroundWipe
}

/// The timers (Android's Timers, ported):
///
/// - Cover: 30 s without input on a Protected screen.
/// - Warning: 9 minutes without input while a session is held.
/// - Idle wipe: 10 minutes without input while a session is held, and on a Protected screen with nothing
///   held (as on the Pi, whose collision-report QR shows the kept seal code).
/// - Background wipe: 60 s after the app was left on a Public screen, while a session is held (leaving a
///   Protected screen discards at once: the model's rule, not a timer's).
/// - The picker rule: a picker the app opened over its own scene, should iOS report it as leaving the
///   app, is no leaving: that time counts as foreground time under the idle rules, and the background
///   time never starts. The exemption ends at the app's next resume, so it never outlasts the picker.
///
/// A boundary belongs to the later step: 59.999 s away keeps the session, 60 s wipes it.
final class Timers {
    /// 30 s without input covers a Protected screen.
    static let coverMillis: Int64 = 30_000
    /// 9 minutes without input warns.
    static let warnMillis: Int64 = 540_000
    /// 10 minutes without input wipes.
    static let wipeMillis: Int64 = 600_000
    /// 60 s away from a Public screen wipes.
    static let backgroundMillis: Int64 = 60_000

    private let clock: MonotonicClock
    private var lastInput: Int64
    /// When the app was left, while it is away; nil in the foreground, a picker the app opened included.
    private var leftAt: Int64?
    /// A picker the app opened is up (or about to be), until the app's next resume.
    private var picker = false

    init(clock: MonotonicClock) {
        self.clock = clock
        lastInput = clock.nowMillis()
    }

    /// A tap, or any input, in the foreground: the idle time starts again.
    func input() {
        lastInput = clock.nowMillis()
    }

    /// The app is about to open a picker over its own scene: a leaving that follows is no leaving.
    func pickerOpened() {
        picker = true
    }

    /// The app went to the background: true when that is leaving the app, and the background time
    /// starts; false while a picker the app opened is up.
    func left() -> Bool {
        if picker { return false }
        leftAt = clock.nowMillis()
        return true
    }

    /// The app is back: the background time ends, and so does a picker.
    func returned() {
        leftAt = nil
        picker = false
    }

    /// The app is active again: a picker it opened is over, or never left the app, so the next
    /// leaving is leaving again.
    func resumed() {
        picker = false
    }

    /// The step due now on a screen that is Protected or not, while a session is held or not; nil for none.
    func step(onProtected: Bool, holdsSecrets: Bool) -> TimerStep? {
        let now = clock.nowMillis()
        let idle = now - lastInput
        if holdsSecrets, let left = leftAt, now - left >= Timers.backgroundMillis { return .backgroundWipe }
        if holdsSecrets || onProtected, idle >= Timers.wipeMillis { return .idleWipe }
        if holdsSecrets, idle >= Timers.warnMillis { return .warn }
        if onProtected, idle >= Timers.coverMillis { return .cover }
        return nil
    }
}
