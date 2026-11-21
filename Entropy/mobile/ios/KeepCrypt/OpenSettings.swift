import UIKit

// The scan screen's "Open Settings" (tasks/todo.md, M6 item D4; lead decision M6-6): after a refused camera
// iOS never asks again, so the app's own page in Settings, and nothing else. The gate allows this one call
// here alone (SwOpenURL).
enum OpenSettings {
    static func show() {
        UIApplication.shared.open(URL(string: UIApplication.openSettingsURLString)!, options: [:], completionHandler: nil)
    }
}
