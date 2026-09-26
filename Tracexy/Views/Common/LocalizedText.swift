import SwiftUI

extension Text {
    /// Fixed interface copy handed through a `String` parameter (a section title, a
    /// row label, a footnote): looked up in the String Catalog like a literal would
    /// be, and shown as written when it has no translation. Never use it for
    /// capture data — the lookup also reads Markdown.
    init(localized copy: String) {
        self.init(LocalizedStringKey(copy))
    }
}
