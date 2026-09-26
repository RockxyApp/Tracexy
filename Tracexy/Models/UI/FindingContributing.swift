import Foundation

// MARK: - ContributedFindingKind

/// A kind of finding that an installed ``FindingContributing`` source defines
/// rather than Core analysis. It stands where a Core kind's `finding == name`
/// stands: a label for the kind, and the Session Expression that leads back to
/// its sessions.
struct ContributedFindingKind: Hashable, Sendable {
    /// Stable within its source. Occurrences with the same id form one group.
    let id: String
    /// What a findings table shows for the kind, where a Core kind shows its
    /// `finding ==` name.
    let label: String
    /// The Session Expression that selects this kind's sessions, grouped so it can
    /// narrow another expression.
    let expression: String
}

// MARK: - FindingContributing

/// Findings that the composition root may add beside Core analysis findings.
///
/// Every findings surface reads ``MainContentCoordinator/findings``, so an
/// installed source's findings appear wherever Core findings do. Without one, the
/// list holds Core findings only. A source only adds findings: it never changes
/// sessions, Core findings, History, or what the Session Expression grammar
/// matches.
@MainActor
protocol FindingContributing: AnyObject {
    /// Findings for the sessions `coordinator` presents. Findings for any other
    /// session are dropped.
    func contributedFindings(for coordinator: MainContentCoordinator) -> [Finding]
}

// MARK: - FindingContributors

/// Where the composition root installs its source, once, at launch. Held weakly:
/// the composition root owns it. `nil` adds nothing anywhere.
@MainActor
enum FindingContributors {
    static weak var installed: (any FindingContributing)?
}

// MARK: - MainContentCoordinator + contributed findings

extension MainContentCoordinator {
    /// The installed source's findings for the presented sessions `presentedIDs`,
    /// after Core findings in ``findings``. Empty when nothing is installed.
    func contributedFindings(among presentedIDs: Set<UUID>) -> [Finding] {
        guard let contributor = FindingContributors.installed else {
            return []
        }
        return contributor.contributedFindings(for: self).filter { presentedIDs.contains($0.sessionID) }
    }
}
