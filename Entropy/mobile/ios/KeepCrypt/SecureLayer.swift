// Q88's secure layer (docs/mobile-apps.md, "Secure-layer rendering", the fourth capture layer;
// tasks/todo.md, M6 item C5): the content is drawn inside the drawing layer of a text field whose entry
// is secure, which iOS leaves out of screenshots and recordings. Apple documents no such use and gives
// no guarantee, so it is never the only layer (the capture cover and the screenshot discard carry the
// gate either way), and I1 tests it on the owner's iPhone; if it hides nothing on current iOS, Q88
// drops it by a doc edit. Stage D puts the word views in it.
//
// The field never takes input: it is never made first responder, takes no touch and is not an
// accessibility element (the content inside it is read instead), so no keyboard can open. If the
// field has no drawing layer to hold the content, nothing is shown (fail closed): the content is never
// drawn outside it.

import SwiftUI
import UIKit

/// content, drawn inside a secure text field's layer.
struct SecureLayer<Content: View>: UIViewRepresentable {
    let content: Content

    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }

    func makeUIView(context: Context) -> SecureLayerView {
        SecureLayerView(content: AnyView(content))
    }

    func updateUIView(_ view: SecureLayerView, context: Context) {
        view.show(AnyView(content))
    }
}

/// The field and the content's host inside its drawing layer.
final class SecureLayerView: UIView {
    let field = UITextField()
    let host: UIHostingController<AnyView>
    /// The field's own drawing view (its first subview), which holds the content; nil if it has
    /// none, and then the content is not shown.
    let canvas: UIView?

    init(content: AnyView) {
        host = UIHostingController(rootView: content)
        field.isSecureTextEntry = true
        field.isUserInteractionEnabled = false
        field.isAccessibilityElement = false
        field.borderStyle = .none
        field.backgroundColor = .clear
        canvas = field.subviews.first
        super.init(frame: .zero)
        isAccessibilityElement = false
        field.translatesAutoresizingMaskIntoConstraints = false
        addSubview(field)
        pin(field, to: self)
        guard let canvas else { return }
        host.view.backgroundColor = .clear
        host.view.translatesAutoresizingMaskIntoConstraints = false
        canvas.addSubview(host.view)
        pin(host.view, to: field)
    }

    required init?(coder: NSCoder) {
        nil
    }

    /// The content after a view update.
    func show(_ content: AnyView) {
        host.rootView = content
    }

    private func pin(_ view: UIView, to frame: UIView) {
        NSLayoutConstraint.activate([
            view.leadingAnchor.constraint(equalTo: frame.leadingAnchor),
            view.trailingAnchor.constraint(equalTo: frame.trailingAnchor),
            view.topAnchor.constraint(equalTo: frame.topAnchor),
            view.bottomAnchor.constraint(equalTo: frame.bottomAnchor),
        ])
    }
}
