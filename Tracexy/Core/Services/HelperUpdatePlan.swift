// MARK: - HelperUpdateBlockReason

nonisolated enum HelperUpdateBlockReason: Equatable {
    case notInstalled
    case requiresApproval
    case unreachable
    case signingMismatch
    case incompatibleProtocol
    case embeddedPackageInvalid
    case downgradeRefused
}

// MARK: - HelperUpdatePlan

nonisolated enum HelperUpdatePlan: Equatable {
    case upToDate
    case approvalPreservingRefresh
    case legacyManualMigration
    case blocked(HelperUpdateBlockReason)
}

// MARK: - HelperRefreshCandidate

nonisolated struct HelperRefreshCandidate: Equatable, Sendable {
    let executableDigest: String
    let expectedProtocolVersion: Int
    let bundledBuildNumber: Int
}
