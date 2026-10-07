import Foundation

// MARK: - FindingsSummaryNode

/// One row of Statistics ▸ Findings. A group row gathers every finding of one kind — its
/// severity, how many there are, in how many sessions and how many frames they cite —
/// and its children are the individual findings, one per session. `term` leads a
/// group back to its sessions; `finding` lets an occurrence open its session and
/// first cited frame.
struct FindingsSummaryNode: Identifiable, Hashable {
    let id: String
    let severity: Finding.Severity
    let title: String
    /// The host of the session for an occurrence; the expression name for a group.
    let detail: String
    let findingCount: Int
    let sessionCount: Int
    let citedFrameCount: Int
    let term: String?
    let finding: Finding?
    var children: [FindingsSummaryNode]?

    var isGroup: Bool {
        finding == nil
    }
}

// MARK: - FindingsSummary

/// Folds the findings of the sessions in view into Wireshark's Expert Information
/// shape: grouped by summary, worst severity first, with a severity floor and a text
/// search over titles and hosts. It adds no policy: every row is a projected Core
/// finding, and counts are plain tallies of those rows.
enum FindingsSummary {
    // MARK: Internal

    enum SeverityFloor: String, CaseIterable, Identifiable {
        case all
        case warnings

        // MARK: Internal

        var id: String {
            rawValue
        }

        var title: String {
            switch self {
            case .all: String(localized: "Warnings and Notes")
            case .warnings: String(localized: "Warnings Only")
            }
        }

        func admits(_ severity: Finding.Severity) -> Bool {
            switch self {
            case .all: true
            case .warnings: severity != .note
            }
        }
    }

    /// - Parameters:
    ///   - findings: findings already limited to the sessions in view.
    ///   - hosts: the host shown for each session id.
    ///   - grouped: `true` for one row per kind (children = occurrences), `false`
    ///     for a flat list of occurrences in the same order.
    static func nodes(
        of findings: [Finding],
        hosts: [UUID: String],
        floor: SeverityFloor = .all,
        search: String = "",
        grouped: Bool = true
    )
        -> [FindingsSummaryNode]
    {
        let needle = search.trimmingCharacters(in: .whitespacesAndNewlines)
        let admitted = findings.filter { finding in
            guard floor.admits(finding.severity) else {
                return false
            }
            guard !needle.isEmpty else {
                return true
            }
            let host = hosts[finding.sessionID] ?? ""
            return finding.title.localizedCaseInsensitiveContains(needle)
                || host.localizedCaseInsensitiveContains(needle)
                || finding.kindName.localizedCaseInsensitiveContains(needle)
        }
        let occurrences = admitted.map { occurrence($0, host: hosts[$0.sessionID] ?? "") }
        guard grouped else {
            return occurrences.worstFirstStable()
        }

        var order: [Finding.Kind] = []
        var byKind: [Finding.Kind: [FindingsSummaryNode]] = [:]
        for (finding, node) in zip(admitted, occurrences) {
            if byKind[finding.kind] == nil {
                order.append(finding.kind)
            }
            byKind[finding.kind, default: []].append(node)
        }
        return order.compactMap { kind -> FindingsSummaryNode? in
            guard let children = byKind[kind], let first = children.first, let finding = first.finding else {
                return nil
            }
            let id = switch kind {
            case .analysis: "kind.\(finding.kindName)"
            case let .contributed(contributed): "contributed.\(contributed.id)"
            }
            return FindingsSummaryNode(
                id: id,
                severity: children.map(\.severity).min(by: { $0.rawValue < $1.rawValue }) ?? finding.severity,
                title: finding.title,
                detail: finding.kindName,
                findingCount: children.count,
                sessionCount: Set(children.compactMap(\.finding?.sessionID)).count,
                citedFrameCount: children.reduce(0) { $0 + $1.citedFrameCount },
                term: finding.kindExpression,
                finding: nil,
                children: children
            )
        }
        .worstFirstStable()
    }

    /// Counts per severity over the same admitted rows, for the footer.
    static func severityCounts(of findings: [Finding]) -> [Finding.Severity: Int] {
        Dictionary(grouping: findings, by: \.severity).mapValues(\.count)
    }

    /// Tab-separated lines for Copy: severity, summary, detail and the counts.
    static func copyText(_ nodes: [FindingsSummaryNode]) -> String {
        nodes.map { node in
            [
                severityTitle(node.severity), node.title, node.detail,
                String(node.findingCount), String(node.sessionCount), String(node.citedFrameCount),
            ].joined(separator: "\t")
        }
        .joined(separator: "\n")
    }

    static func severityTitle(_ severity: Finding.Severity) -> String {
        switch severity {
        case .error: String(localized: "Error")
        case .warning: String(localized: "Warning")
        case .note: String(localized: "Note")
        }
    }

    // MARK: Private

    private static func occurrence(_ finding: Finding, host: String) -> FindingsSummaryNode {
        FindingsSummaryNode(
            id: "finding.\(finding.id.uuidString)",
            severity: finding.severity,
            title: finding.title,
            detail: host,
            findingCount: 1,
            sessionCount: 1,
            citedFrameCount: finding.citedFrames.count,
            term: nil,
            finding: finding,
            children: nil
        )
    }
}

private extension [FindingsSummaryNode] {
    /// Worst severity first, keeping the incoming (capture) order within a severity.
    func worstFirstStable() -> [FindingsSummaryNode] {
        enumerated()
            .sorted { lhs, rhs in
                lhs.element.severity.rawValue == rhs.element.severity.rawValue
                    ? lhs.offset < rhs.offset
                    : lhs.element.severity.rawValue < rhs.element.severity.rawValue
            }
            .map(\.element)
    }
}
