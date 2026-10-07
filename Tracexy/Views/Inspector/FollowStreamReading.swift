import SwiftUI

// MARK: - FollowStreamReading

/// A second reading of a followed TCP stream that the composition root may supply,
/// such as the same bytes transformed by another reader.
///
/// The Stream facet asks it for controls to draw above the transcript and for the
/// result to present in place of the bytes as captured. Without one, the facet
/// presents the captured bytes and nothing else changes. The captured result itself
/// is never replaced in the coordinator: a reading only changes what is drawn,
/// searched, opened and saved from the facet.
@MainActor
protocol FollowStreamReading: AnyObject {
    /// Controls and status for `result`, drawn under the summary row, or `nil` when
    /// this reading has nothing to offer for it.
    func controls(for result: FollowStreamResult) -> AnyView?

    /// The result to present in place of `result`, or `nil` to present it as captured.
    func presentedResult(for result: FollowStreamResult) -> FollowStreamResult?
}

// MARK: - FollowStreamReadings

/// Where the composition root installs its reading, once, before the first window
/// opens. The app has one workspace coordinator, so it has one reading. Held weakly:
/// the composition root owns it. `nil` presents every stream as captured.
@MainActor
enum FollowStreamReadings {
    static weak var installed: (any FollowStreamReading)?
}
