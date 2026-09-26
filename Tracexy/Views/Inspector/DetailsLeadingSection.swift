import SwiftUI

// MARK: - DetailsLeadingSection

/// A section another part of the app may place at the top of the selected
/// session's Details column. It is given the session's evidence and the route
/// that opens a cited frame in the inspector. `nil` adds nothing.
@MainActor
enum DetailsLeadingSection {
    static var installed: (@MainActor (
        SessionEvidenceSelection,
        @escaping (SessionFrameProvenance) -> Void
    )
        -> AnyView)?
}
