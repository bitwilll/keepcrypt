// The offline check (docs/mobile-apps.md, "No network, no cloud backup, no clipboard": the monitor must
// report no usable path; tasks/todo.md, M6 item C5): the one file that imports Network, and it names
// the path monitor alone (the gate's Network rule). The app has no networking code; this only watches
// whether the phone could reach a network, so a ceremony runs only with none.
//
// Offline is no usable path: the path's status is anything but satisfied (unsatisfied, or one that
// needs a connection made first). Every update of the monitor is read afresh and reported, on the main
// queue, for the process's life; the model decides what a report does (CeremonyModel.pathReported).
// Until the first update the model counts the phone as online.

import Network

@MainActor
final class OfflineCheck {
    private let monitor = NWPathMonitor()
    private let report: (Bool) -> Void
    #if KC_TEST_HOOKS
    /// The state the UI tests forced (TestHooks): true no usable path, false a usable one; nil the
    /// monitor's own.
    private var forced: Bool?
    #endif

    /// report is called with each update's reading: true when no path is usable.
    init(report: @escaping (Bool) -> Void) {
        self.report = report
    }

    func start() {
        monitor.pathUpdateHandler = { [weak self] path in
            let offline = path.status != .satisfied
            MainActor.assumeIsolated {
                self?.reported(offline)
            }
        }
        monitor.start(queue: .main)
    }

    private func reported(_ offline: Bool) {
        #if KC_TEST_HOOKS
        if let forced {
            report(forced)
            return
        }
        #endif
        report(offline)
    }

    #if KC_TEST_HOOKS
    /// The UI tests' path hook: from now on every report is this state, whatever the monitor says.
    func force(offline: Bool) {
        forced = offline
        report(offline)
    }
    #endif
}
