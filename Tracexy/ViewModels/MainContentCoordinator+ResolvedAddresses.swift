import Foundation

@MainActor
extension MainContentCoordinator {
    /// Resolved Addresses: every name the capture's DNS and mDNS answers gave an
    /// address, beside the names given in this Project.
    var resolvedAddressRows: [ResolvedAddressRow] {
        ResolvedAddresses.rows(
            sessions: presentedSessions, namedAddresses: addressNames.names, namedSubnets: addressNames.subnetNames,
            captureFileRecords: isViewingSavedCapture ? savedCaptureNameResolutionRecords : []
        )
    }

    var resolvedFrameAddressName: (String) -> String {
        FrameAddressNames.resolver(
            sessions: presentedSessions, book: addressNames,
            captureFileRecords: isViewingSavedCapture ? savedCaptureNameResolutionRecords : []
        )
    }

    /// Selects the DNS or mDNS session whose answer taught a name. A session hidden
    /// by the current scope is revealed by narrowing to its host — a recorded
    /// drill-in, so Back to Previous Scope returns — never by clearing the scope.
    func showSessionThatResolved(_ sessionID: UUID) {
        guard let session = presentedSessions.first(where: { $0.id == sessionID }) else {
            return
        }
        if !visibleSessions.contains(where: { $0.id == sessionID }) {
            selectHost(session.host)
        }
        openSessionsPreservingScope()
        if visibleSessions.contains(where: { $0.id == sessionID }) {
            select(session)
        }
    }
}
