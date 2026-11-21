// The iPhone's end of the motion-source seam (tasks/todo.md, M6 item D3; Android's SensorMotionSource.kt;
// docs/mobile-apps.md, "Entropy sources on phones": Core Motion's accelerometer and gyroscope, mixed into
// the pool with no credit while Device entropy shows). Each update becomes one sample in Android's layout
// (Seams.swift's motionSample), reported on the main queue; the model hands it to core and wipes it, and
// nothing logs it. Updates come at 50 a second, as Android's SENSOR_DELAY_GAME. Raw accelerometer and
// gyroscope updates need no permission and no NSMotionUsageDescription (that key covers motion activity,
// the pedometer and the altimeter), so Info.plist is unchanged. A phone without one of the two gives the
// other's samples alone: they carry no credit, so nothing rests on them.

import CoreMotion

final class CoreMotionSource: MotionSource {
    /// The update interval: 50 a second.
    private static let interval = 1.0 / 50

    private let manager = CMMotionManager()
    private var report: ((Secret) -> Void)?

    /// Starts both sensors' updates on the main queue, until stop.
    func start(_ report: @escaping (Secret) -> Void) {
        stop()
        self.report = report
        if manager.isAccelerometerAvailable {
            manager.accelerometerUpdateInterval = CoreMotionSource.interval
            manager.startAccelerometerUpdates(to: .main) { [weak self] data, _ in
                guard let data else { return }
                let a = data.acceleration
                self?.sample(.accelerometer, data.timestamp, [Float(a.x), Float(a.y), Float(a.z)])
            }
        }
        if manager.isGyroAvailable {
            manager.gyroUpdateInterval = CoreMotionSource.interval
            manager.startGyroUpdates(to: .main) { [weak self] data, _ in
                guard let data else { return }
                let r = data.rotationRate
                self?.sample(.gyroscope, data.timestamp, [Float(r.x), Float(r.y), Float(r.z)])
            }
        }
    }

    /// Stops both; an update already queued finds no receiver and is dropped.
    func stop() {
        guard report != nil else { return }
        report = nil
        manager.stopAccelerometerUpdates()
        manager.stopGyroUpdates()
    }

    /// One update as a sample, to the model while it listens; its timestamp (seconds since the phone
    /// started) in nanoseconds.
    private func sample(_ sensor: MotionSensor, _ timestamp: TimeInterval, _ values: [Float]) {
        guard let report, timestamp.isFinite, timestamp >= 0 else { return }
        report(motionSample(sensor, timestampNanos: Int64(timestamp * 1_000_000_000), values: values))
    }
}
