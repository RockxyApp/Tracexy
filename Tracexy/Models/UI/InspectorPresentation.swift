import Foundation

// MARK: - InspectorTab

enum InspectorTab: String, CaseIterable, Identifiable, Hashable {
    // Evidence only. What the selection *means* — verdicts, baselines, findings,
    // related sessions — belongs to the Context Dock, and used to be duplicated
    // here as Summary and Security tabs.
    //
    // Timeline opens first: for a correlated action it is the one view a packet
    // analyser cannot draw, since its engine has no shared axis across
    // conversations of different protocols.
    case timeline
    case layers
    case requests
    case payload
    case hex

    // MARK: Internal

    nonisolated var id: String {
        rawValue
    }

    nonisolated var title: String {
        switch self {
        case .timeline: "Timeline"
        case .layers: "Layers"
        case .requests: "Requests"
        case .payload: "Payload"
        case .hex: "Hex"
        }
    }

    nonisolated var systemImage: String {
        switch self {
        case .timeline: "chart.bar.xaxis"
        case .layers: "square.stack.3d.up"
        case .requests: "arrow.left.arrow.right"
        case .payload: "doc.plaintext"
        case .hex: "number"
        }
    }

    /// Tabs to show for a session, in display order. Never render an empty
    /// facet: each one appears only once there is something for it to show.
    ///
    /// Unlike the right inspector — whose two modes are fixed places the user
    /// learns once — the evidence tabs describe what this session literally
    /// contains, so a facet with no bytes behind it would be a promise the
    /// decode cannot keep.
    static func visibleTabs(for session: SessionSummary) -> [InspectorTab] {
        var tabs: [InspectorTab] = [.timeline]
        if !session.decodedLayers.isEmpty {
            tabs.append(.layers)
        }
        if session.hasApplicationExchange {
            tabs.append(.requests)
        }
        if !session.representativeBytes.isEmpty {
            tabs.append(contentsOf: [.payload, .hex])
        }
        return tabs
    }
}

// MARK: - InspectorLayout

/// Where the **evidence** inspector docks. There is deliberately no `.right`
/// case: the right-hand column is a separate inspector, with its
/// own state, tabs and toggle (`WorkspaceState.isContextDockVisible`).
///
/// Two orientations of one inspector produced panels that duplicated each other's
/// purpose — a wide pane spent its width on key/value pairs the narrow column
/// rendered better. Splitting them by *job*
/// instead of by *orientation* is what removed the duplication:
///
/// - the bottom inspector owns **evidence** — what the selection literally
///   contains: decoded layers, hex, payload, the action timeline. Wide,
///   chronological, read-only.
/// - the right inspector owns **details and assistance** — facts, interpretation,
///   relationships, and the honest placeholder for future AI help.
///
/// They live on different axes (the bottom pane is nested inside the centre
/// column, the dock is a sibling of it), so both can be open at once without
/// competing for space or purpose.
enum InspectorLayout: String, CaseIterable, Identifiable, Hashable {
    case hidden
    case bottom

    // MARK: Internal

    nonisolated var id: String {
        rawValue
    }

    nonisolated var systemImage: String {
        switch self {
        case .hidden: "rectangle.bottomthird.inset.filled"
        case .bottom: "rectangle.bottomhalf.inset.filled"
        }
    }
}

// MARK: - ContextDockTab

/// The two primary modes of the right-hand inspector column. Both are fixed
/// places the user learns once, scoped to the current selection.
///
/// - **Details** gathers everything the app can *say* about the selection:
///   identity, verdict, layer facts, host baseline, related actions, grouping
///   evidence and security findings, in one vertically scrollable read.
/// - **AI Assistant** is a production-shaped conversation shell for a future
///   assistant. It carries the current selection as compact attached context and
///   pins a disabled composer below an empty transcript; it is not connected to
///   any backend and neither sends nor stores anything.
enum ContextDockTab: String, CaseIterable, Identifiable, Hashable {
    case details
    case aiAssistant

    // MARK: Internal

    nonisolated var id: String {
        rawValue
    }

    nonisolated var title: String {
        switch self {
        case .details: "Details"
        case .aiAssistant: "AI Assistant"
        }
    }

    nonisolated var systemImage: String {
        switch self {
        case .details: "list.bullet.rectangle"
        case .aiAssistant: "sparkles"
        }
    }
}
