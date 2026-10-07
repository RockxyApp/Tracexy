import SwiftUI

// MARK: - FollowDatagramReading

/// A second reading of a followed UDP conversation that the composition root may
/// supply, such as the same datagrams read by another reader.
///
/// The Stream facet asks it for a section to draw above the datagram list. Without
/// one, the facet lists the datagrams as captured and nothing else changes. The
/// captured result is never replaced in the coordinator.
@MainActor
protocol FollowDatagramReading: AnyObject {
    /// A section for `result`, or `nil` when this reading has nothing to offer for
    /// it. `openFrame` opens a captured frame in Layers.
    func section(
        for result: FollowDatagramResult,
        openFrame: @escaping (SessionFrameProvenance) -> Void
    )
        -> AnyView?
}

// MARK: - FollowDatagramReadings

/// Where the composition root installs its reading, once, before the first window
/// opens. Held weakly: the composition root owns it. `nil` lists every conversation
/// as captured.
@MainActor
enum FollowDatagramReadings {
    static weak var installed: (any FollowDatagramReading)?
}
