import Foundation

// MARK: - HistoryRecordProjection

/// A pure, `nonisolated`/`Sendable` conversion from the app's transitional
/// ``SessionSummary`` values into the storage-owned neutral history records.
///
/// It is deliberately isolated from `@MainActor`: the coordinator snapshots the
/// immutable session array and resolves only the privacy flag plus the durable
/// lifetime metadata, then hands both to this projection off the main actor. The
/// store never learns about `AppSettings`, `SessionSummary`, or any UI value — it
/// only ever receives the frozen ``HistoryCaptureRecord``/``HistorySessionRecord``
/// values produced here.
///
/// The projection maps status explicitly, bounds every integer/string/protocol
/// conversion so a produced record can never exceed a storage invariant, preserves
/// protocol order, and applies the *same* IP/endpoint masking semantics as
/// protected session export (``PrivacyMask``). Payload/credential redaction is a
/// no-op here because those values are simply absent from the neutral schema; only
/// address masking has any surface to act on, and it transforms the rendered host
/// and both endpoints before the actor is called.
nonisolated enum HistoryRecordProjection {
    // MARK: Internal

    /// The complete, immutable input to one projection. `sessions` is the exact
    /// session array the coordinator adopted; `startedAt`/`endedAt` are the durable
    /// lifetime instants (seconds since 1970) resolved on the main actor.
    struct Input: Sendable {
        // MARK: Lifecycle

        init(
            captureID: UUID,
            startedAt: Double,
            endedAt: Double,
            sourceKind: HistorySourceKind,
            completeness: HistoryCompleteness,
            sessions: [SessionSummary],
            maskIPAddresses: Bool
        ) {
            self.captureID = captureID
            self.startedAt = startedAt
            self.endedAt = endedAt
            self.sourceKind = sourceKind
            self.completeness = completeness
            self.sessions = sessions
            self.maskIPAddresses = maskIPAddresses
        }

        // MARK: Internal

        let captureID: UUID
        let startedAt: Double
        let endedAt: Double
        let sourceKind: HistorySourceKind
        let completeness: HistoryCompleteness
        let sessions: [SessionSummary]
        let maskIPAddresses: Bool
    }

    /// The immutable projection result: one capture record plus its ordered
    /// session records, ready for ``SessionStore/replaceCapture(_:sessions:)``.
    struct Output: Sendable {
        let capture: HistoryCaptureRecord
        let sessions: [HistorySessionRecord]
    }

    /// Project one capture's neutral history records. Pure and total: it never
    /// throws, never reads settings, and always produces records that satisfy the
    /// store's bounds (invalid inputs are clamped/dropped rather than rejected
    /// here, so the store's own re-validation is a defence-in-depth check, not the
    /// primary gate).
    static func project(_ input: Input) -> Output {
        let capture = HistoryCaptureRecord(
            captureID: input.captureID,
            startedAt: sanitizedInstant(input.startedAt),
            // Guarantee `endedAt >= startedAt` even if the derived instants invert
            // (an empty capture, or clock skew): a persisted record must satisfy
            // the store's ordering invariant.
            endedAt: max(sanitizedInstant(input.startedAt), sanitizedInstant(input.endedAt)),
            sourceKind: input.sourceKind,
            completeness: input.completeness
        )
        let sessions = input.sessions.map { session in
            projectSession(session, maskIPAddresses: input.maskIPAddresses)
        }
        return Output(capture: capture, sessions: sessions)
    }

    // MARK: Private

    private static func projectSession(
        _ session: SessionSummary,
        maskIPAddresses mask: Bool
    )
        -> HistorySessionRecord
    {
        HistorySessionRecord(
            sessionID: session.id,
            startTime: sanitizedInstant(session.startTime.timeIntervalSince1970),
            duration: sanitizedNonNegative(session.duration),
            processName: session.processName.map { bounded($0) },
            host: bounded(masked(session.host, mask: mask)),
            sourceEndpoint: bounded(maskedEndpoint(session.sourceEndpoint, mask: mask)),
            destinationEndpoint: bounded(maskedEndpoint(session.destinationEndpoint, mask: mask)),
            protocols: projectProtocols(session.protocolStack),
            status: mapStatus(session.status),
            latencyMilliseconds: projectLatency(session.latencyMilliseconds),
            bytesUp: nonNegativeInt64(session.bytesUp),
            bytesDown: nonNegativeInt64(session.bytesDown)
        )
    }

    /// Explicit status mapping between the transitional UI vocabulary and the
    /// storage-owned one. Deliberately exhaustive so a new `SessionStatus` case
    /// forces a decision here rather than silently defaulting.
    private static func mapStatus(_ status: SessionStatus) -> HistorySessionStatus {
        switch status {
        case .ok: .ok
        case .warning: .warning
        case .error: .error
        }
    }

    /// Preserve protocol order, map to stable raw values, and bound to the store's
    /// per-session protocol cap so an unusually deep stack cannot be rejected.
    private static func projectProtocols(_ stack: [ProtocolKind]) -> [String] {
        stack.prefix(HistoryLimits.maxProtocolsPerSession).map(\.rawValue)
    }

    /// A latency is kept only when finite and non-negative; anything else becomes
    /// "not measured" rather than a poisoned numeric field.
    private static func projectLatency(_ latency: Double?) -> Double? {
        guard let latency, latency.isFinite, latency >= 0 else {
            return nil
        }
        return latency
    }

    private static func masked(_ value: String, mask: Bool) -> String {
        mask ? PrivacyMask.maskingAddresses(in: value) : value
    }

    private static func maskedEndpoint(_ value: String, mask: Bool) -> String {
        mask ? PrivacyMask.maskingEndpoint(value) : value
    }

    /// A finite instant, defaulting a non-finite value to `0` so the record can
    /// still be persisted deterministically.
    private static func sanitizedInstant(_ value: Double) -> Double {
        value.isFinite ? value : 0
    }

    private static func sanitizedNonNegative(_ value: Double) -> Double {
        guard value.isFinite, value >= 0 else {
            return 0
        }
        return value
    }

    private static func nonNegativeInt64(_ value: Int) -> Int64 {
        Int64(max(0, value))
    }

    /// Clamp a string to the store's UTF-8 byte bound on a character boundary, so
    /// an unexpectedly long rendered value is truncated safely rather than
    /// rejected. Ordinary hosts/endpoints are far under the bound and untouched.
    private static func bounded(_ value: String) -> String {
        guard value.utf8.count > HistoryLimits.maxStringUTF8Bytes else {
            return value
        }
        var result = value
        while result.utf8.count > HistoryLimits.maxStringUTF8Bytes, !result.isEmpty {
            result.removeLast()
        }
        return result
    }
}
