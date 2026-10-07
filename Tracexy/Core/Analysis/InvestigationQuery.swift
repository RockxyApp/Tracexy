import Foundation

// This file declares the frozen, pure value types for the Community-only
// bounded typed investigation query engine. It is a new representation over the
// already-produced, immutable ``InvestigationSnapshot`` (its sessions plus the two
// passive analyses); it decodes nothing, retains no bytes, touches no `@MainActor`,
// scans no packets and persists nothing. There is deliberately no text grammar,
// regular expression, rendered-endpoint parser, TLS operand, finding *policy* or UI
// copy here: the AST is preconstructed by a caller, validated once, then evaluated.
//
// The engine has two stages:
//   1. `compile` validates a preconstructed ``InvestigationQuery`` against injectable
//      (downward-only) bounds and normalizes every text operand exactly once, yielding
//      a ``CompiledInvestigationQuery`` or throwing a typed ``QueryValidationError``.
//   2. `evaluate` runs the compiled query over one immutable ``InvestigationSnapshot``
//      with three-valued (Kleene) logic, preserving session order and returning matched
//      sessions plus indeterminate session ids, and — whenever a finding predicate
//      appears — a typed coverage summary that never claims whole-capture completeness.

// MARK: - EndpointScope

/// Which canonical endpoint(s) an address/port predicate reads. `either` matches if
/// the source *or* the destination satisfies the predicate. Scope reads only the
/// typed ``IPEndpoint`` projections on a summary — never the rendered display copy.
nonisolated enum EndpointScope: Hashable, Sendable {
    case source
    case destination
    case either
}

// MARK: - QueryFindingKind

/// The neutral projection a query matches against: the five TCP lifecycle findings
/// (refused, unanswered, aborted after data, half-close, tuple reuse), the four
/// accepted TCP sequence observations, the four TCP flow-control observations (zero
/// window, window full, duplicate ACK, keep-alive), the four UDP-DNS outcome
/// indications (truncation, name error, server failure, unanswered retried query),
/// the three ICMP messages on the flow that carried them, the same three reported
/// against the TCP/UDP flow the message quoted, and the five TLS observations
/// (fatal alert, warning alert, deprecated selected version, repeated retry request,
/// unanswered ClientHello). It is deliberately its own
/// vocabulary, disjoint from the analysis layers' internal finding-kind enums, so a
/// query never depends on their identity or ordering.
nonisolated enum QueryFindingKind: Hashable, Sendable, CaseIterable {
    /// The responder answered the observed SYN with a reset
    /// (`ConnectionAnalysisFindingKind.connectionRefusedObserved`).
    case connectionRefused
    /// A retried SYN never observed a SYN+ACK
    /// (`ConnectionAnalysisFindingKind.handshakeUnansweredObserved`).
    case handshakeUnanswered
    /// Payload was observed and a reset followed it (`.abortAfterDataObserved`).
    case abortAfterData
    /// A FIN in one direction was followed by payload from the peer
    /// (`.halfCloseObserved`).
    case halfClose
    /// A conflicting SYN arrived before any terminal (`.tupleReuseObserved`).
    case tupleReuse
    /// A reset was observed (`ConnectionAnalysisFindingKind.resetObserved`).
    case reset
    /// One or more retransmissions were observed (`.retransmissionObserved`).
    case retransmission
    /// One or more overlapping segments were observed (`.overlapObserved`).
    case overlap
    /// One or more out-of-order segments were observed (`.outOfOrderObserved`).
    case outOfOrder
    /// A zero receive window was advertised or probed (`.zeroWindowObserved`).
    case zeroWindow
    /// A data segment filled the peer's receive window (`.windowFullObserved`).
    case windowFull
    /// One or more duplicate acknowledgements were observed
    /// (`.duplicateAcknowledgementObserved`).
    case duplicateAck
    /// One or more keep-alive probes were observed (`.keepAliveObserved`).
    case keepAlive
    /// A segment was re-sent after repeated duplicate acknowledgements
    /// (`.fastRetransmissionObserved`).
    case fastRetransmission
    /// Already-acknowledged bytes were re-sent (`.spuriousRetransmissionObserved`).
    case spuriousRetransmission
    /// A side acknowledged bytes the capture never saw (`.ackedUnseenSegmentObserved`).
    case ackedUnseen
    /// A login secret was sent unencrypted (`.cleartextCredentialsObserved`).
    case cleartextCredentials
    /// The DNS TC (truncation) bit was observed set on a UDP-DNS message
    /// (`DatagramAnalysisFindingKind.dnsTruncationIndicated`).
    case dnsTruncation
    /// A DNS response carried RCODE 3 (`.dnsNameErrorObserved`).
    case dnsNameError
    /// A DNS response carried RCODE 2 or 5 (`.dnsServerFailureObserved`).
    case dnsServerFailure
    /// A retried DNS query id observed no response (`.dnsQueryUnansweredObserved`).
    case dnsUnanswered
    /// An ICMP destination-unreachable message (`.icmpDestinationUnreachableObserved`).
    case icmpUnreachable
    /// An ICMP fragmentation-needed / packet-too-big message (`.icmpPacketTooBigObserved`).
    case icmpPacketTooBig
    /// An ICMP time-exceeded message (`.icmpTimeExceededObserved`).
    case icmpTimeExceeded
    /// A destination-unreachable message quoted this session's flow
    /// (`.icmpUnreachableReportedForFlow`).
    case icmpReportedUnreachable
    /// A packet-too-big message quoted this session's flow
    /// (`.icmpPacketTooBigReportedForFlow`).
    case icmpReportedPacketTooBig
    /// A time-exceeded message quoted this session's flow
    /// (`.icmpTimeExceededReportedForFlow`).
    case icmpReportedTimeExceeded
    /// A plaintext TLS alert carried the fatal level (`.tlsFatalAlertObserved`).
    case tlsFatalAlert
    /// A plaintext TLS alert carried the warning level and was not an orderly
    /// shutdown (`.tlsWarningAlertObserved`).
    case tlsWarningAlert
    /// A complete ServerHello selected a version below TLS 1.2
    /// (`.tlsDeprecatedVersionSelectedObserved`).
    case tlsDeprecatedVersion
    /// More than one HelloRetryRequest was observed in one direction
    /// (`.tlsRepeatedHelloRetryRequestObserved`).
    case tlsRepeatedRetryRequest
    /// A ClientHello was observed with no reply of any kind
    /// (`.tlsHandshakeUnansweredObserved`).
    case tlsHandshakeUnanswered
}

// MARK: - QueryEvidenceField

/// The already-typed optional session/finding presence a `hasEvidence` predicate can
/// test. The first seven are ordinary two-valued session facts; `anyFinding` is the
/// only three-valued member, because a finding's *absence* is never proof under
/// incomplete coverage.
nonisolated enum QueryEvidenceField: Hashable, Sendable, CaseIterable {
    case processAttribution
    case latency
    case dnsQuery
    case dnsAnswer
    case serverNameIndication
    case sourceEndpoint
    case destinationEndpoint
    /// Whether *any* accepted finding is retained for the session. Three-valued:
    /// present is a match, absent is indeterminate (never a safe negative).
    case anyFinding
}

// MARK: - QueryPredicate

/// One leaf test in a preconstructed query. Text operands hold their raw, un-normalized
/// strings (normalized once at compile); range operands hold explicit lower/upper
/// bounds (validated at compile, so a reversed range is a typed error rather than a
/// `ClosedRange` trap). All typed IP/CIDR/port/status/protocol/finding values are
/// already validated by construction.
nonisolated enum QueryPredicate: Hashable, Sendable {
    /// Case-insensitive substring over the originating process name.
    case processContains(String)
    /// Case-insensitive substring over the resolved display host.
    case hostContains(String)
    /// Case-insensitive whole-value wildcard (`*`, `?`) over the process name.
    case processMatches(String)
    /// Case-insensitive whole-value wildcard (`*`, `?`) over the display host.
    case hostMatches(String)
    /// Exact binary IP equality within a scope, parsed from `IPEndpoint.ip`.
    case ipEquals(IPAddressValue, scope: EndpointScope)
    /// Binary CIDR containment within a scope, parsed from `IPEndpoint.ip`.
    case cidrContains(CIDRValue, scope: EndpointScope)
    /// Closed `UInt16` port range membership within a scope.
    case portInRange(lower: UInt16, upper: UInt16, scope: EndpointScope)
    /// Membership of a protocol in the session's decoded stack.
    case protocolStackContains(ProtocolKind)
    /// Exact session status equality.
    case statusEquals(SessionStatus)
    /// Three-valued finding-kind presence (see ``QueryFindingKind``).
    case findingKind(QueryFindingKind)
    /// Closed start-`Date` range membership.
    case startDateInRange(lower: Date, upper: Date)
    /// Closed non-negative total-byte range membership.
    case totalBytesInRange(lower: Int, upper: Int)
    /// Typed optional session/finding presence (see ``QueryEvidenceField``).
    case hasEvidence(QueryEvidenceField)
    /// An HTTP/1 request with this method was counted in the session (exact token).
    case httpMethodEquals(String)
    /// An HTTP/1 response with a status code in this closed range was counted.
    case httpStatusInRange(lower: Int, upper: Int)
    /// A DHCP message of this type (case-insensitive, e.g. `Discover`) was counted.
    case dhcpMessageEquals(String)
    /// Closed session-duration range in seconds; an unknown duration is undecidable.
    case durationInRange(lower: TimeInterval, upper: TimeInterval)
    /// Closed measured-latency range in milliseconds; an unmeasured latency is
    /// undecidable.
    case latencyInRange(lower: Double, upper: Double)
    /// The investigator put this color tag on the session (see ``SessionTag``).
    case tagEquals(String)
    /// The session's client and/or server Ethernet address (from its representative
    /// frame), as `aa:bb:cc:dd:ee:ff`.
    case macEquals(String, scope: EndpointScope)
    /// TCP completeness (Wireshark's `tcp.completeness`): an exact bit value, or
    /// the complete / incomplete verdict. A session that is not TCP never matches.
    case tcpCompleteness(TCPCompletenessMatch)
    /// A session measure against a whole-number expression that may read other
    /// measures (`bytes.received >= {10 * bytes.sent}`).
    case numericCompare(QueryNumericComparison)
}

// MARK: - InvestigationQuery

/// A preconstructed, indirect query expression. `all` is a conjunction, `any` a
/// disjunction, `not` a single-child negation and `leaf` a single predicate. It is a
/// pure value: no grammar parses it, and it is validated before evaluation.
nonisolated indirect enum InvestigationQuery: Hashable, Sendable {
    case all([InvestigationQuery])
    case any([InvestigationQuery])
    case not(InvestigationQuery)
    case leaf(QueryPredicate)
}

// MARK: - TCPCompletenessMatch

/// What a `tcp.completeness` term asks for.
nonisolated enum TCPCompletenessMatch: Hashable, Sendable {
    /// Exactly these stages, as Wireshark's number (0...63).
    case value(UInt8)
    /// The handshake and a FIN or RST were seen (Wireshark's "Complete").
    case complete
    case incomplete

    // MARK: Internal

    func matches(_ completeness: TCPCompleteness) -> Bool {
        switch self {
        case let .value(raw): completeness.rawValue == raw
        case .complete: completeness.isComplete
        case .incomplete: !completeness.isComplete
        }
    }
}

// MARK: - CompiledPredicate

/// A validated leaf: text operands are normalized once, range operands are closed and
/// ordered. Produced only by ``InvestigationQueryEngine/compile(_:)``; never built by a
/// caller directly.
nonisolated enum CompiledPredicate: Hashable, Sendable {
    case processContains(String)
    case hostContains(String)
    case processMatches(WildcardPattern)
    case hostMatches(WildcardPattern)
    case ipEquals(IPAddressValue, scope: EndpointScope)
    case cidrContains(CIDRValue, scope: EndpointScope)
    case portInRange(ClosedRange<UInt16>, scope: EndpointScope)
    case protocolStackContains(ProtocolKind)
    case statusEquals(SessionStatus)
    case findingKind(QueryFindingKind)
    case startDateInRange(ClosedRange<Date>)
    case totalBytesInRange(ClosedRange<Int>)
    case httpMethodEquals(String)
    case httpStatusInRange(ClosedRange<Int>)
    case dhcpMessageEquals(String)
    case durationInRange(ClosedRange<TimeInterval>)
    case latencyInRange(ClosedRange<Double>)
    case tagEquals(String)
    case macEquals(String, scope: EndpointScope)
    case tcpCompleteness(TCPCompletenessMatch)
    case numericCompare(QueryNumericComparison)
    case hasEvidence(QueryEvidenceField)

    // MARK: Internal

    /// Whether this predicate reads the finding index (and therefore requires a
    /// coverage summary). Only `findingKind` and `hasEvidence(.anyFinding)` do.
    var readsFindings: Bool {
        switch self {
        case .findingKind: true
        case let .hasEvidence(field): field == .anyFinding
        default: false
        }
    }

    /// Whether this predicate reads a session's capture time, so an evaluation must
    /// disclose unknown-timing coverage. Only the start-date range does.
    var readsCaptureTime: Bool {
        switch self {
        case .startDateInRange,
             .durationInRange: true
        default: false
        }
    }
}

// MARK: - CompiledQueryNode

/// A validated query node mirroring ``InvestigationQuery`` after compilation.
nonisolated indirect enum CompiledQueryNode: Hashable, Sendable {
    case all([CompiledQueryNode])
    case any([CompiledQueryNode])
    case not(CompiledQueryNode)
    case leaf(CompiledPredicate)
}

// MARK: - CompiledInvestigationQuery

/// The immutable output of validation: the compiled root plus a precomputed flag
/// recording whether any finding predicate appears (so evaluation only builds a
/// coverage summary when one does).
nonisolated struct CompiledInvestigationQuery: Hashable, Sendable {
    let root: CompiledQueryNode
    /// `true` iff at least one leaf reads the finding index (see
    /// ``CompiledPredicate/readsFindings``).
    let referencesFindings: Bool
    /// `true` iff at least one leaf reads a session's capture time, so unknown
    /// timing must be disclosed as typed coverage rather than silently excluded.
    let referencesCaptureTime: Bool

    /// Whether an evaluation of this query must produce a coverage summary.
    var requiresCoverage: Bool {
        referencesFindings || referencesCaptureTime
    }
}

// MARK: - QueryValidationError

/// A typed, `Equatable` reason validation rejected a query. Every case fails closed:
/// an invalid query is never partially evaluated. Bound-carrying cases echo the exact
/// enforced ceiling for a caller's diagnostics.
nonisolated enum QueryValidationError: Error, Hashable, Sendable {
    /// An `all`/`any` group had no children.
    case emptyGroup
    /// The total node count exceeded the enforced ceiling.
    case nodeCountExceeded(limit: Int)
    /// A path exceeded the enforced depth ceiling (root is depth 1).
    case depthExceeded(limit: Int)
    /// One group exceeded the enforced children-per-group ceiling.
    case childCountExceeded(limit: Int)
    /// A text operand normalized to the empty string.
    case emptyText
    /// A normalized text operand contained a control character.
    case controlCharacterInText
    /// A normalized text operand exceeded the enforced UTF-8 byte ceiling.
    case textTooLong(limit: Int)
    /// A range operand's lower bound exceeded its upper bound.
    case reversedRange
    /// A byte-range operand carried a negative bound.
    case negativeByteBound
    /// A date-range operand carried a non-finite endpoint.
    case nonFiniteDate
    /// A numeric comparison's arithmetic held more than its node ceiling.
    case arithmeticTooLarge(limit: Int)
}

// MARK: - QueryTruth

/// Three-valued (Kleene) truth. `indeterminate` means the evidence cannot decide the
/// predicate — it is never collapsed into `match` or `noMatch`.
nonisolated enum QueryTruth: Hashable, Sendable {
    case match
    case noMatch
    case indeterminate
}

// MARK: - QueryCoverageReason

/// One typed reason the query result may under-report a finding predicate. Each is
/// derived from a current snapshot fact; a reason's *absence* is a bounded-local
/// statement about this snapshot only, never a whole-capture completeness guarantee.
nonisolated enum QueryCoverageReason: Hashable, Sendable, CaseIterable {
    /// Connection summaries were dropped to honor a bound.
    case connectionSummaryOmission
    /// Connection findings or their citations were dropped to honor a bound.
    case connectionFindingOmission
    /// A connection's event history or sequence state was truncated to a bound.
    case connectionEventOrStateLimitation
    /// Datagram observations were omitted to a bound or a contributing frame was
    /// captured shorter than its original on-wire length.
    case datagramObservationOmission
    /// Datagram findings or their citations were dropped to honor a bound.
    case datagramFindingOmission
    /// TLS records were omitted to a bound, a reassembled record was excluded from
    /// retention, a frame's decode hit the record cap, or a TLS-bearing frame was
    /// captured shorter than its original on-wire length.
    case tlsObservationOmission
    /// TLS findings or their citations were dropped to honor a bound.
    case tlsFindingOmission
    /// TCP-DNS facts were deliberately excluded from datagram retention.
    case excludedTCPDNSInput
    /// A datagram evidence bound rejected at least one fact.
    case capacityReached
    /// The capture layer reported loss for at least one flow.
    case captureLossReported
    /// Capture completeness is unknown for at least one flow.
    case captureLossUnknown
    /// A source-table or analysis saturating counter reached its maximum.
    case counterOverflow
    /// At least one session in the snapshot has no known start time, so a date
    /// predicate could not be decided for it in either direction.
    case unknownSessionStartTime
}

// MARK: - QueryCoverageSummary

/// The bounded set of coverage reasons that apply to one evaluation. Returned only
/// when the query references a finding or capture-time predicate. An empty set is the clean
/// bounded-local context: nothing was dropped *for this snapshot within its bounds* —
/// never a claim the whole capture or network was seen completely.
nonisolated struct QueryCoverageSummary: Hashable, Sendable {
    let reasons: Set<QueryCoverageReason>

    /// Whether no known coverage issue applies to this snapshot. This is a
    /// bounded-local statement only; it is *not* a whole-capture guarantee.
    var isCleanBoundedLocalContext: Bool {
        reasons.isEmpty
    }
}

// MARK: - InvestigationQueryResult

/// The immutable result of one evaluation: matched sessions and indeterminate session
/// ids, both in snapshot input order without duplication, plus the optional coverage
/// summary (present iff the query references findings or capture time).
nonisolated struct InvestigationQueryResult: Hashable, Sendable {
    /// Sessions whose top-level truth was `match`, in snapshot order.
    let matched: [SessionSummary]
    /// Ids of sessions whose top-level truth was `indeterminate`, in snapshot order.
    let indeterminate: [UUID]
    /// The coverage caveat for a finding/time-referencing query, else `nil`.
    let coverage: QueryCoverageSummary?
}

// MARK: - InvestigationQueryEngine

/// A pure, stateless engine that validates and evaluates typed investigation queries.
/// It holds only an injectable ``Configuration`` (downward-clamped bounds), so
/// compiling/evaluating the same inputs always yields the same result. Nothing here
/// mutates the snapshot, decodes packets, retains bytes or touches the `@MainActor`.
nonisolated struct InvestigationQueryEngine: Hashable, Sendable {
    // MARK: Lifecycle

    init(configuration: Configuration = Configuration()) {
        self.configuration = configuration
    }

    // MARK: Internal

    // MARK: Configuration

    /// Injectable validation bounds. Each is clamped into `1 ... productionCeiling`,
    /// so a configuration can only *lower* a ceiling, never raise it — the production
    /// ceilings (128 nodes, depth 8, 16 children, 256 UTF-8 bytes) are the hard caps.
    nonisolated struct Configuration: Hashable, Sendable {
        // MARK: Lifecycle

        init(
            maxNodes: Int = Configuration.productionMaxNodes,
            maxDepth: Int = Configuration.productionMaxDepth,
            maxChildrenPerGroup: Int = Configuration.productionMaxChildrenPerGroup,
            maxTextUTF8Bytes: Int = Configuration.productionMaxTextUTF8Bytes
        ) {
            self.maxNodes = min(Self.productionMaxNodes, max(1, maxNodes))
            self.maxDepth = min(Self.productionMaxDepth, max(1, maxDepth))
            self.maxChildrenPerGroup = min(Self.productionMaxChildrenPerGroup, max(1, maxChildrenPerGroup))
            self.maxTextUTF8Bytes = min(Self.productionMaxTextUTF8Bytes, max(1, maxTextUTF8Bytes))
        }

        // MARK: Internal

        /// The frozen production ceilings. A `Configuration` can never exceed these.
        static let productionMaxNodes = 128
        static let productionMaxDepth = 8
        static let productionMaxChildrenPerGroup = 16
        static let productionMaxTextUTF8Bytes = 256

        let maxNodes: Int
        let maxDepth: Int
        let maxChildrenPerGroup: Int
        let maxTextUTF8Bytes: Int
    }

    /// The investigator's session tags for the evaluation in progress, by session.
    /// Bound by the caller around ``evaluate(_:over:isCancelled:)``.
    @TaskLocal static var sessionTags: [UUID: Set<String>] = [:]

    /// The fixed locale used for case-insensitive folding. `en_US_POSIX` makes folding
    /// deterministic and locale-independent. Folding performs no IDN/Punycode
    /// normalization: a host operand is compared as its raw scalars, case-folded only.
    static let foldingLocale = Locale(identifier: "en_US_POSIX")

    let configuration: Configuration

    /// Normalize one text operand exactly once: trim surrounding whitespace/newlines,
    /// then apply fixed-locale case-insensitive folding. There is deliberately no IDN
    /// normalization — an internationalized host is folded, not Punycode-encoded.
    static func normalizeText(_ text: String) -> String {
        text
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .folding(options: .caseInsensitive, locale: foldingLocale)
    }

    static func projected(_ kind: ConnectionAnalysisFindingKind) -> QueryFindingKind {
        switch kind {
        case .connectionRefusedObserved: .connectionRefused
        case .handshakeUnansweredObserved: .handshakeUnanswered
        case .abortAfterDataObserved: .abortAfterData
        case .halfCloseObserved: .halfClose
        case .tupleReuseObserved: .tupleReuse
        case .resetObserved: .reset
        case .retransmissionObserved: .retransmission
        case .overlapObserved: .overlap
        case .outOfOrderObserved: .outOfOrder
        case .zeroWindowObserved: .zeroWindow
        case .windowFullObserved: .windowFull
        case .duplicateAcknowledgementObserved: .duplicateAck
        case .keepAliveObserved: .keepAlive
        case .fastRetransmissionObserved: .fastRetransmission
        case .spuriousRetransmissionObserved: .spuriousRetransmission
        case .ackedUnseenSegmentObserved: .ackedUnseen
        case .cleartextCredentialsObserved: .cleartextCredentials
        }
    }

    static func projected(_ kind: DatagramAnalysisFindingKind) -> QueryFindingKind {
        switch kind {
        case .dnsTruncationIndicated: .dnsTruncation
        case .dnsNameErrorObserved: .dnsNameError
        case .dnsServerFailureObserved: .dnsServerFailure
        case .dnsQueryUnansweredObserved: .dnsUnanswered
        case .icmpDestinationUnreachableObserved: .icmpUnreachable
        case .icmpPacketTooBigObserved: .icmpPacketTooBig
        case .icmpTimeExceededObserved: .icmpTimeExceeded
        case .icmpUnreachableReportedForFlow: .icmpReportedUnreachable
        case .icmpPacketTooBigReportedForFlow: .icmpReportedPacketTooBig
        case .icmpTimeExceededReportedForFlow: .icmpReportedTimeExceeded
        }
    }

    static func projected(_ kind: TLSAnalysisFindingKind) -> QueryFindingKind {
        switch kind {
        case .tlsFatalAlertObserved: .tlsFatalAlert
        case .tlsWarningAlertObserved: .tlsWarningAlert
        case .tlsDeprecatedVersionSelectedObserved: .tlsDeprecatedVersion
        case .tlsRepeatedHelloRetryRequestObserved: .tlsRepeatedRetryRequest
        case .tlsHandshakeUnansweredObserved: .tlsHandshakeUnanswered
        }
    }

    /// Validate and normalize a preconstructed query. Throws the first
    /// ``QueryValidationError`` encountered; on success the query is guaranteed to fit
    /// every bound and to carry only normalized, non-empty, control-free text.
    func compile(_ query: InvestigationQuery) throws -> CompiledInvestigationQuery {
        var context = CompileContext()
        let root = try compileNode(query, depth: 1, context: &context)
        return CompiledInvestigationQuery(
            root: root,
            referencesFindings: context.referencesFindings,
            referencesCaptureTime: context.referencesCaptureTime
        )
    }

    /// Evaluate a compiled query over one immutable snapshot. Synchronous and pure.
    /// `isCancelled` is checked before every session (including the first); a `true`
    /// answer throws `CancellationError`. Matched sessions and indeterminate ids are
    /// returned in snapshot order without duplication; coverage is present iff the
    /// query references a finding predicate.
    func evaluate(
        _ query: CompiledInvestigationQuery,
        over snapshot: InvestigationSnapshot,
        isCancelled: () -> Bool = { false }
    )
        throws -> InvestigationQueryResult
    {
        // Honor cancellation before building even the bounded transient finding map.
        // Subsequent checks occur before each later session, so the probe is called
        // exactly once per session while no work precedes the first check.
        if isCancelled() {
            throw CancellationError()
        }
        // Built once from the already-bounded analysis arrays; discarded at return, so
        // no permanent/duplicate finding index is created. Scalar-only queries do not
        // pay this allocation cost at all.
        let membership = query.referencesFindings ? Self.buildFindingMembership(snapshot) : [:]
        // A date predicate has its own coverage story (unknown capture time), so the
        // summary is produced for finding *and* time predicates alike.

        var matched: [SessionSummary] = []
        var indeterminate: [UUID] = []
        for (index, session) in snapshot.sessions.enumerated() {
            if index > 0, isCancelled() {
                throw CancellationError()
            }
            switch Self.evaluateNode(query.root, session: session, membership: membership) {
            case .match: matched.append(session)
            case .indeterminate: indeterminate.append(session.id)
            case .noMatch: break
            }
        }

        let coverage: QueryCoverageSummary?
        if query.requiresCoverage {
            var reasons = query.referencesFindings ? Self.coverage(for: snapshot).reasons : []
            if query.referencesCaptureTime, snapshot.sessions.contains(where: { $0.startTime == nil }) {
                reasons.insert(.unknownSessionStartTime)
            }
            coverage = QueryCoverageSummary(reasons: reasons)
        } else {
            coverage = nil
        }
        return InvestigationQueryResult(matched: matched, indeterminate: indeterminate, coverage: coverage)
    }

    // MARK: Private

    // MARK: Compilation

    /// The mutable bookkeeping threaded through one compilation: the running node
    /// budget plus which coverage-relevant inputs the query reads.
    private struct CompileContext {
        var nodeCount = 0
        var referencesFindings = false
        var referencesCaptureTime = false
    }

    // MARK: Evaluation — Kleene combinators

    private static func evaluateNode(
        _ node: CompiledQueryNode,
        session: SessionSummary,
        membership: [UUID: Set<QueryFindingKind>]
    )
        -> QueryTruth
    {
        switch node {
        case let .leaf(predicate):
            return evaluatePredicate(predicate, session: session, membership: membership)
        case let .not(child):
            switch evaluateNode(child, session: session, membership: membership) {
            case .match: return .noMatch
            case .noMatch: return .match
            case .indeterminate: return .indeterminate
            }
        case let .all(children):
            // Kleene AND: any no-match wins; else any indeterminate; else match.
            var sawIndeterminate = false
            for child in children {
                switch evaluateNode(child, session: session, membership: membership) {
                case .noMatch: return .noMatch
                case .indeterminate: sawIndeterminate = true
                case .match: break
                }
            }
            return sawIndeterminate ? .indeterminate : .match
        case let .any(children):
            // Kleene OR: any match wins; else any indeterminate; else no-match.
            var sawIndeterminate = false
            for child in children {
                switch evaluateNode(child, session: session, membership: membership) {
                case .match: return .match
                case .indeterminate: sawIndeterminate = true
                case .noMatch: break
                }
            }
            return sawIndeterminate ? .indeterminate : .noMatch
        }
    }

    // MARK: Evaluation — leaf predicates

    private static func evaluatePredicate(
        _ predicate: CompiledPredicate,
        session: SessionSummary,
        membership: [UUID: Set<QueryFindingKind>]
    )
        -> QueryTruth
    {
        switch predicate {
        case let .processContains(needle):
            boolean(substringMatch(needle, in: session.processName))
        case let .hostContains(needle):
            boolean(substringMatch(needle, in: session.host))
        case let .processMatches(pattern):
            boolean(wildcardMatch(pattern, in: session.processName))
        case let .hostMatches(pattern):
            boolean(wildcardMatch(pattern, in: session.host))
        case let .ipEquals(value, scope):
            boolean(endpoints(scope, of: session).contains {
                IPAddressValue(parsing: $0.ip) == value
            })
        case let .cidrContains(value, scope):
            boolean(endpoints(scope, of: session).contains {
                guard let parsed = IPAddressValue(parsing: $0.ip) else {
                    return false
                }
                return value.contains(parsed)
            })
        case let .portInRange(range, scope):
            boolean(endpoints(scope, of: session).contains { range.contains($0.port) })
        case let .protocolStackContains(kind):
            boolean(session.protocolStack.contains(kind))
        case let .statusEquals(status):
            boolean(session.status == status)
        case let .findingKind(kind):
            evaluateFindingKind(kind, session: session, membership: membership)
        case let .startDateInRange(range):
            // A session with no known start time is genuinely undecidable against a
            // date range — including under negation, which propagates
            // `indeterminate` rather than turning absence into a match.
            evaluateStartDate(range, session: session)
        case let .totalBytesInRange(range):
            evaluateTotalBytes(range, session: session)
        case let .hasEvidence(field):
            evaluateEvidence(field, session: session, membership: membership)
        case let .httpMethodEquals(method):
            tallyTruth(session.messageTally.httpRequests[method] != nil, tally: session.messageTally)
        case let .httpStatusInRange(range):
            tallyTruth(
                session.messageTally.httpResponses.keys.contains { range.contains($0) },
                tally: session.messageTally
            )
        case let .durationInRange(range):
            session.duration.map { boolean(range.contains($0)) } ?? .indeterminate
        case let .latencyInRange(range):
            session.latencyMilliseconds.map { boolean(range.contains($0)) } ?? .indeterminate
        case let .tagEquals(tag):
            // Tags are the investigator's own labels: known exactly, never undecidable.
            boolean(Self.sessionTags[session.id]?.contains(tag) == true)
        case let .tcpCompleteness(match):
            // The stages are what the fold saw; a stage the capture missed is absent,
            // which is exactly what the value says, so the answer is never undecided.
            boolean(session.protocolStack.contains(.tcp) && match.matches(session.tcpCompleteness))
        case let .macEquals(mac, scope):
            // A session without an Ethernet header has no MAC to match.
            boolean(session.macAddresses.map { pair in
                switch scope {
                case .source: pair.client == mac
                case .destination: pair.server == mac
                case .either: pair.client == mac || pair.server == mac
                }
            } ?? false)
        case let .numericCompare(comparison):
            comparison.truth(for: session)
        case let .dhcpMessageEquals(kind):
            tallyTruth(
                session.messageTally.dhcpMessages.keys.contains { $0.caseInsensitiveCompare(kind) == .orderedSame },
                tally: session.messageTally
            )
        }
    }

    /// A counted message is a match. A missing one is a known no-match unless the
    /// session's bounded tally dropped messages, when it may have been among them.
    private static func tallyTruth(_ found: Bool, tally: SessionMessageTally) -> QueryTruth {
        if found {
            return .match
        }
        return tally.omitted > 0 ? .indeterminate : .noMatch
    }

    /// Three-valued finding-kind test: a retained finding is a match; an absent but
    /// *applicable* kind is indeterminate; a kind that cannot apply to this session's
    /// protocol stack is a known no-match.
    private static func evaluateFindingKind(
        _ kind: QueryFindingKind,
        session: SessionSummary,
        membership: [UUID: Set<QueryFindingKind>]
    )
        -> QueryTruth
    {
        if membership[session.id]?.contains(kind) == true {
            return .match
        }
        return applies(kind, to: session) ? .indeterminate : .noMatch
    }

    /// Whether a finding kind could apply to this session at all. TCP observations
    /// apply only to a TCP stack; DNS truncation applies only to a UDP-DNS stack.
    private static func applies(_ kind: QueryFindingKind, to session: SessionSummary) -> Bool {
        switch kind {
        case .connectionRefused,
             .handshakeUnanswered,
             .abortAfterData,
             .halfClose,
             .tupleReuse,
             .reset,
             .retransmission,
             .overlap,
             .outOfOrder,
             .zeroWindow,
             .windowFull,
             .duplicateAck,
             .keepAlive,
             .fastRetransmission,
             .spuriousRetransmission,
             .ackedUnseen,
             .cleartextCredentials:
            session.protocolStack.contains(.tcp)
        case .dnsTruncation,
             .dnsNameError,
             .dnsServerFailure,
             .dnsUnanswered:
            session.protocolStack.contains(.udp) && session.protocolStack.contains(.dns)
        case .icmpUnreachable,
             .icmpPacketTooBig,
             .icmpTimeExceeded:
            session.protocolStack.contains(.icmp) || session.protocolStack.contains(.icmpv6)
        case .icmpReportedUnreachable,
             .icmpReportedPacketTooBig,
             .icmpReportedTimeExceeded:
            // The quoted flow is always TCP or UDP — the decoder retains no other
            // quotation — so an ICMP or ARP session can never carry these.
            session.protocolStack.contains(.tcp) || session.protocolStack.contains(.udp)
        case .tlsFatalAlert,
             .tlsWarningAlert,
             .tlsDeprecatedVersion,
             .tlsRepeatedRetryRequest,
             .tlsHandshakeUnanswered:
            // TLS records are only retained for a flow whose stack the fold already
            // recognized as carrying them.
            session.protocolStack.contains(.tls)
        }
    }

    /// `hasEvidence`: the seven typed session facts are ordinary two-valued presence
    /// tests; `anyFinding` is three-valued (present is a match, absent indeterminate).
    private static func evaluateEvidence(
        _ field: QueryEvidenceField,
        session: SessionSummary,
        membership: [UUID: Set<QueryFindingKind>]
    )
        -> QueryTruth
    {
        switch field {
        case .processAttribution: boolean(isPresent(session.processName))
        case .latency: boolean(session.latencyMilliseconds != nil)
        case .dnsQuery: boolean(isPresent(session.dnsQuery))
        case .dnsAnswer: boolean(!session.dnsAnswers.isEmpty)
        case .serverNameIndication: boolean(isPresent(session.sni))
        case .sourceEndpoint: boolean(session.sourceEndpointValue != nil)
        case .destinationEndpoint: boolean(session.destinationEndpointValue != nil)
        case .anyFinding:
            // Absence is never a safe negative: a session with no retained finding is
            // indeterminate because coverage may be incomplete.
            (membership[session.id]?.isEmpty == false) ? .match : .indeterminate
        }
    }

    /// Three-valued start-date test: a known start compares against the closed range;
    /// an unknown start is indeterminate, never a silent no-match.
    private static func evaluateStartDate(
        _ range: ClosedRange<Date>,
        session: SessionSummary
    )
        -> QueryTruth
    {
        guard let startTime = session.startTime else {
            return .indeterminate
        }
        return boolean(range.contains(startTime))
    }

    /// Total-byte range test with fail-closed overflow handling. A hand-built summary
    /// with a negative component or an overflowing `bytesUp + bytesDown` is a no-match,
    /// never a trap.
    private static func evaluateTotalBytes(
        _ range: ClosedRange<Int>,
        session: SessionSummary
    )
        -> QueryTruth
    {
        guard session.bytesUp >= 0, session.bytesDown >= 0 else {
            return .noMatch
        }
        let (total, overflow) = session.bytesUp.addingReportingOverflow(session.bytesDown)
        guard !overflow else {
            return .noMatch
        }
        return boolean(range.contains(total))
    }

    // MARK: Evaluation — helpers

    private static func boolean(_ value: Bool) -> QueryTruth {
        value ? .match : .noMatch
    }

    /// Whether an optional string operand is present: non-nil and non-empty after
    /// trimming. Empty/whitespace-only fields count as absent.
    private static func isPresent(_ value: String?) -> Bool {
        guard let value else {
            return false
        }
        return !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    /// Case-insensitive substring match: the operand is already normalized; the
    /// haystack is normalized the same way before the containment check.
    private static func substringMatch(_ needle: String, in haystack: String?) -> Bool {
        guard let haystack, !haystack.isEmpty else {
            return false
        }
        return normalizeText(haystack).contains(needle)
    }

    /// An absent or empty value never matches, exactly as for a substring test.
    private static func wildcardMatch(_ pattern: WildcardPattern, in value: String?) -> Bool {
        guard let value, !value.isEmpty else {
            return false
        }
        return pattern.matches(normalizeText(value))
    }

    /// The typed endpoints a scope reads, dropping any absent projection. A missing or
    /// unexpectedly invalid typed endpoint contributes nothing (no rendered fallback).
    private static func endpoints(_ scope: EndpointScope, of session: SessionSummary) -> [IPEndpoint] {
        switch scope {
        case .source: session.sourceEndpointValue.map { [$0] } ?? []
        case .destination: session.destinationEndpointValue.map { [$0] } ?? []
        case .either: [session.sourceEndpointValue, session.destinationEndpointValue].compactMap { $0 }
        }
    }

    // MARK: Finding membership + coverage

    /// Build the per-session finding-kind membership once from the already-bounded
    /// connection/datagram analysis arrays. Connection findings join through
    /// `SessionBuilder.sessionID(for: finding.tuple)`; datagram findings carry their
    /// tuple-derived `sessionID` directly. It synthesizes no session and mutates
    /// nothing; a finding for a session absent from `snapshot.sessions` simply never
    /// gets read, so it yields no orphan result.
    private static func buildFindingMembership(
        _ snapshot: InvestigationSnapshot
    )
        -> [UUID: Set<QueryFindingKind>]
    {
        var membership: [UUID: Set<QueryFindingKind>] = [:]
        for finding in snapshot.connectionAnalysis.findings {
            let sessionID = SessionBuilder.sessionID(for: finding.tuple)
            membership[sessionID, default: []].insert(projected(finding.kind))
        }
        for finding in snapshot.datagramAnalysis.findings {
            membership[finding.sessionID, default: []].insert(projected(finding.kind))
        }
        for finding in snapshot.tlsAnalysis.findings {
            membership[finding.sessionID, default: []].insert(projected(finding.kind))
        }
        return membership
    }

    /// Derive the coverage summary from current snapshot facts. Each reason is a real
    /// omission/limitation/loss/overflow signal already recorded by the fold or the
    /// assessors; the empty set is a bounded-local no-known-issue statement only.
    private static func coverage(for snapshot: InvestigationSnapshot) -> QueryCoverageSummary {
        let connections = snapshot.connections
        let connectionAnalysis = snapshot.connectionAnalysis
        let datagramEvidence = snapshot.datagramEvidence
        let datagramAnalysis = snapshot.datagramAnalysis
        let tlsEvidence = snapshot.tlsEvidence
        let tlsAnalysis = snapshot.tlsAnalysis
        var reasons: Set<QueryCoverageReason> = []

        if connections.omittedSummaryCount > 0 {
            reasons.insert(.connectionSummaryOmission)
        }
        if connectionAnalysis.omittedFindingCount > 0
            || connectionAnalysis.findings.contains(where: { $0.omittedCitationCount > 0 })
        {
            reasons.insert(.connectionFindingOmission)
        }
        if connections.summaries.contains(where: {
            $0.omittedEventCount > 0
                || $0.limitations.contains(.eventHistoryTruncated)
                || $0.limitations.contains(.sequenceStateTruncated)
        }) {
            reasons.insert(.connectionEventOrStateLimitation)
        }
        if datagramAnalysis.inputOmittedObservationCount > 0
            || datagramEvidence.summaries.contains(where: {
                $0.omittedObservationCount > 0 || $0.snapLengthTruncationObserved
            })
        {
            reasons.insert(.datagramObservationOmission)
        }
        if datagramAnalysis.omittedFindingCount > 0
            || datagramAnalysis.findings.contains(where: { $0.omittedCitationCount > 0 })
        {
            reasons.insert(.datagramFindingOmission)
        }
        if datagramAnalysis.excludedTCPDNSFactCount > 0 {
            reasons.insert(.excludedTCPDNSInput)
        }
        if tlsAnalysis.inputOmittedObservationCount > 0
            || tlsAnalysis.excludedReassembledRecordCount > 0
            || tlsAnalysis.decoderTruncatedFrameCount > 0
            || tlsEvidence.summaries.contains(where: \.snapLengthTruncationObserved)
        {
            reasons.insert(.tlsObservationOmission)
        }
        if tlsAnalysis.omittedFindingCount > 0
            || tlsAnalysis.findings.contains(where: { $0.omittedCitationCount > 0 })
        {
            reasons.insert(.tlsFindingOmission)
        }
        if datagramAnalysis.inputCapacityReached
            || datagramEvidence.capacityReached
            || tlsEvidence.capacityReached
        {
            reasons.insert(.capacityReached)
        }
        if anyLoss(connections, datagramEvidence, tlsEvidence, is: .lossReported) {
            reasons.insert(.captureLossReported)
        }
        if anyLoss(connections, datagramEvidence, tlsEvidence, is: .unknown) {
            reasons.insert(.captureLossUnknown)
        }
        if connections.countersOverflowed
            || connectionAnalysis.countersOverflowed
            || connections.summaries.contains(where: { $0.limitations.contains(.counterOverflow) })
            || datagramEvidence.countersOverflowed
            || datagramAnalysis.countersOverflowed
            || tlsEvidence.countersOverflowed
            || tlsAnalysis.countersOverflowed
        {
            reasons.insert(.counterOverflow)
        }
        return QueryCoverageSummary(reasons: reasons)
    }

    /// Whether any connection, datagram or TLS summary carries a given loss knowledge.
    private static func anyLoss(
        _ connections: ConnectionTable.Snapshot,
        _ datagramEvidence: DatagramEvidenceTable.Snapshot,
        _ tlsEvidence: TLSEvidenceTable.Snapshot,
        is knowledge: CaptureLossKnowledge
    )
        -> Bool
    {
        connections.summaries.contains { $0.lossKnowledge == knowledge }
            || datagramEvidence.summaries.contains { $0.lossKnowledge == knowledge }
            || tlsEvidence.summaries.contains { $0.lossKnowledge == knowledge }
    }

    private func compileNode(
        _ node: InvestigationQuery,
        depth: Int,
        context: inout CompileContext
    )
        throws -> CompiledQueryNode
    {
        context.nodeCount += 1
        guard context.nodeCount <= configuration.maxNodes else {
            throw QueryValidationError.nodeCountExceeded(limit: configuration.maxNodes)
        }
        guard depth <= configuration.maxDepth else {
            throw QueryValidationError.depthExceeded(limit: configuration.maxDepth)
        }
        switch node {
        case let .all(children):
            return try .all(compileGroup(children, depth: depth, context: &context))
        case let .any(children):
            return try .any(compileGroup(children, depth: depth, context: &context))
        case let .not(child):
            return try .not(compileNode(child, depth: depth + 1, context: &context))
        case let .leaf(predicate):
            let compiled = try compilePredicate(predicate)
            context.referencesFindings = context.referencesFindings || compiled.readsFindings
            context.referencesCaptureTime = context.referencesCaptureTime || compiled.readsCaptureTime
            return .leaf(compiled)
        }
    }

    private func compileGroup(
        _ children: [InvestigationQuery],
        depth: Int,
        context: inout CompileContext
    )
        throws -> [CompiledQueryNode]
    {
        guard !children.isEmpty else {
            throw QueryValidationError.emptyGroup
        }
        guard children.count <= configuration.maxChildrenPerGroup else {
            throw QueryValidationError.childCountExceeded(limit: configuration.maxChildrenPerGroup)
        }
        return try children.map {
            try compileNode($0, depth: depth + 1, context: &context)
        }
    }

    private func compilePredicate(_ predicate: QueryPredicate) throws -> CompiledPredicate {
        switch predicate {
        case let .processContains(raw):
            return try .processContains(normalizedOperand(raw))
        case let .hostContains(raw):
            return try .hostContains(normalizedOperand(raw))
        case let .processMatches(raw):
            return try .processMatches(WildcardPattern(normalized: normalizedOperand(raw)))
        case let .hostMatches(raw):
            return try .hostMatches(WildcardPattern(normalized: normalizedOperand(raw)))
        case let .ipEquals(value, scope):
            return .ipEquals(value, scope: scope)
        case let .cidrContains(value, scope):
            return .cidrContains(value, scope: scope)
        case let .portInRange(lower, upper, scope):
            guard lower <= upper else {
                throw QueryValidationError.reversedRange
            }
            return .portInRange(lower ... upper, scope: scope)
        case let .protocolStackContains(kind):
            return .protocolStackContains(kind)
        case let .statusEquals(status):
            return .statusEquals(status)
        case let .findingKind(kind):
            return .findingKind(kind)
        case let .startDateInRange(lower, upper):
            guard lower.timeIntervalSinceReferenceDate.isFinite,
                  upper.timeIntervalSinceReferenceDate.isFinite else
            {
                throw QueryValidationError.nonFiniteDate
            }
            guard lower <= upper else {
                throw QueryValidationError.reversedRange
            }
            return .startDateInRange(lower ... upper)
        case let .totalBytesInRange(lower, upper):
            guard lower >= 0, upper >= 0 else {
                throw QueryValidationError.negativeByteBound
            }
            guard lower <= upper else {
                throw QueryValidationError.reversedRange
            }
            return .totalBytesInRange(lower ... upper)
        case let .hasEvidence(field):
            return .hasEvidence(field)
        case let .httpMethodEquals(raw):
            let method = try normalizedOperand(raw).uppercased()
            guard SessionMessageTally.httpMethod(fromRequestLine: method + " ") != nil else {
                throw QueryValidationError.emptyText
            }
            return .httpMethodEquals(method)
        case let .httpStatusInRange(lower, upper):
            guard lower <= upper else {
                throw QueryValidationError.reversedRange
            }
            return .httpStatusInRange(max(100, lower) ... min(599, max(upper, 100)))
        case let .dhcpMessageEquals(raw):
            return try .dhcpMessageEquals(normalizedOperand(raw))
        case let .tcpCompleteness(match):
            return .tcpCompleteness(match)
        case let .durationInRange(lower, upper):
            guard lower.isFinite, upper.isFinite, lower >= 0 else {
                throw QueryValidationError.nonFiniteDate
            }
            guard lower <= upper else {
                throw QueryValidationError.reversedRange
            }
            return .durationInRange(lower ... upper)
        case let .latencyInRange(lower, upper):
            guard lower.isFinite, upper.isFinite, lower >= 0 else {
                throw QueryValidationError.nonFiniteDate
            }
            guard lower <= upper else {
                throw QueryValidationError.reversedRange
            }
            return .latencyInRange(lower ... upper)
        case let .macEquals(raw, scope):
            guard let mac = try SessionSummary.normalizedMAC(normalizedOperand(raw)) else {
                throw QueryValidationError.emptyText
            }
            return .macEquals(mac, scope: scope)
        case let .numericCompare(comparison):
            guard comparison.value.nodeCount <= QueryNumericComparison.maximumNodes else {
                throw QueryValidationError.arithmeticTooLarge(limit: QueryNumericComparison.maximumNodes)
            }
            return .numericCompare(comparison)
        case let .tagEquals(raw):
            let tag = try normalizedOperand(raw).lowercased()
            guard SessionTag(rawValue: tag) != nil else {
                throw QueryValidationError.emptyText
            }
            return .tagEquals(tag)
        }
    }

    /// Normalize one text operand once and enforce the empty/control/overlength rules.
    private func normalizedOperand(_ raw: String) throws -> String {
        let normalized = Self.normalizeText(raw)
        guard !normalized.isEmpty else {
            throw QueryValidationError.emptyText
        }
        guard !normalized.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw QueryValidationError.controlCharacterInText
        }
        guard normalized.utf8.count <= configuration.maxTextUTF8Bytes else {
            throw QueryValidationError.textTooLong(limit: configuration.maxTextUTF8Bytes)
        }
        return normalized
    }
}
