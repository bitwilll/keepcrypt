// The one offline check (docs/mobile-apps.md): the monitor must report no usable path.
import Network

final class OfflineCheck {
    private let monitor = NWPathMonitor()

    func start(_ changed: @escaping (Bool) -> Void) {
        monitor.pathUpdateHandler = { path in changed(path.status != .satisfied) }
        monitor.start(queue: .main)
    }

    func stop() {
        monitor.cancel()
    }
}
