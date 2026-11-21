// The go-ahead QR scanner (tasks/todo.md, M6 item D4; Android's camera/GoAheadScanner.kt; docs/mobile-apps.md,
// step 9: the checker's go-ahead QR scanned back with the camera, in airplane mode too): AVFoundation's
// capture session with a metadata output for QR codes and no preview layer, so nothing the camera sees is
// drawn, and the app never receives a frame: AVFoundation decodes the code and hands its text, which goes to
// found once and is not kept here; core parses and judges it (the model's onGoAheadText). The camera is
// asked for as the scan screen starts a scan, and only then (NSCameraUsageDescription). A refused or
// restricted camera, a phone with none, or a session that fails or is interrupted ends the scan with why.
// A camera input that cannot be made once access was granted ends the app: its creation throws, and rule 3
// lets that error end only in Ceremony.halt or a rethrow (D4's plan, (2)).

import AVFoundation

final class GoAheadScanner: NSObject, QrScanner, AVCaptureMetadataOutputObjectsDelegate {
    /// The longest text a QR code holds (version 40, alphanumeric: 4,296 characters); a longer one is no
    /// QR text and is dropped, as Android's scanner drops it (swb:144).
    static let longest = 4_296

    private var session: AVCaptureSession?
    private var found: ((String) -> Void)?
    private var stopped: ((ScanStop) -> Void)?
    private var failure: NSObjectProtocol?
    /// Bumped by each start and stop, so a prompt's late answer for an earlier scan does nothing.
    private var generation = 0

    func start(found: @escaping (String) -> Void, stopped: @escaping (ScanStop) -> Void) {
        stop()
        self.found = found
        self.stopped = stopped
        let current = generation
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            run()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                DispatchQueue.main.async {
                    guard let self, self.generation == current else { return }
                    if granted {
                        self.run()
                    } else {
                        self.end(.refused)
                    }
                }
            }
        default:
            end(.refused)
        }
    }

    func stop() {
        generation += 1
        found = nil
        stopped = nil
        if let failure {
            NotificationCenter.default.removeObserver(failure)
        }
        failure = nil
        session?.stopRunning()
        session = nil
    }

    /// The session, its camera input and its QR output, started.
    private func run() {
        guard let camera = AVCaptureDevice.default(for: .video) else {
            end(.missing)
            return
        }
        let session = AVCaptureSession()
        let input = makeInput(camera)
        let output = AVCaptureMetadataOutput()
        guard session.canAddInput(input), session.canAddOutput(output) else {
            end(.failed)
            return
        }
        session.addInput(input)
        session.addOutput(output)
        guard output.availableMetadataObjectTypes.contains(.qr) else {
            end(.failed)
            return
        }
        output.metadataObjectTypes = [.qr]
        output.setMetadataObjectsDelegate(self, queue: .main)
        failure = NotificationCenter.default.addObserver(
            forName: AVCaptureSession.runtimeErrorNotification, object: session, queue: .main
        ) { [weak self] _ in
            self?.end(.failed)
        }
        self.session = session
        DispatchQueue.global(qos: .userInitiated).async {
            session.startRunning()
        }
    }

    /// The camera's input; one that cannot be made ends the app (rule 3).
    private func makeInput(_ camera: AVCaptureDevice) -> AVCaptureDeviceInput {
        do {
            return try AVCaptureDeviceInput(device: camera)
        } catch {
            Ceremony.halt(.camera)
        }
    }

    /// The first QR code's text, once: to found, and the scan ends.
    func metadataOutput(
        _ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection
    ) {
        guard let found else { return }
        for object in metadataObjects {
            guard let code = object as? AVMetadataMachineReadableCodeObject, code.type == .qr,
                  let text = code.stringValue, text.utf8.count <= GoAheadScanner.longest
            else { continue }
            stop()
            found(text)
            return
        }
    }

    /// The scan ends with why, once.
    private func end(_ why: ScanStop) {
        let stopped = self.stopped
        stop()
        stopped?(why)
    }
}
