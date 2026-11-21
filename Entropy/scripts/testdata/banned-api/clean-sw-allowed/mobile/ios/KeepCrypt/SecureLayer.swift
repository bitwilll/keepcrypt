import UIKit

// Q88's layer: the words drawn inside a secure field's layer, which never takes focus.
final class SecureLayer {
    let field = UITextField()

    init() {
        field.isSecureTextEntry = true
        field.isUserInteractionEnabled = false
    }
}
