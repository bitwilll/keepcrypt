import UIKit

// The camera prompt's "Open Settings": the app's own page in Settings, and nothing else.
enum OpenSettings {
    static func show() {
        UIApplication.shared.open(URL(string: UIApplication.openSettingsURLString)!, options: [:], completionHandler: nil)
    }
}
