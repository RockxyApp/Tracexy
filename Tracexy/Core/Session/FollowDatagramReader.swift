import Foundation

// MARK: - FollowDNSMessage

/// The DNS reading of one followed datagram: the neutral header facts, the first
/// question and the answer records the decoder produced, plus the index of the
/// message it pairs with. Read on demand from the local capture only; nothing here
/// enters the always-on fold.
nonisolated struct FollowDNSMessage: Sendable, Equatable {
    let transactionID: UInt16
    let isResponse: Bool
    let opcode: UInt8
    let responseCode: UInt8
    let isTruncated: Bool
    /// The first question's name, or empty when the question section was absent.
    let questionName: String
    /// The first question's QTYPE, when it was intact.
    let questionType: UInt16?
    /// Human-readable answer records under the decoder's retention cap.
    let answerRecords: [String]
    /// Valid answer records decoded beyond that cap.
    let omittedAnswerCount: Int
    /// Index into ``FollowDatagramResult/messages`` of the query this response
    /// answers (or the response this query received). `nil` when unpaired or when
    /// the partner fell outside the retained prefix.
    var pairedMessageIndex: Int?
}

// MARK: - FollowDatagramMessage

/// One datagram of the followed conversation, in capture order.
nonisolated struct FollowDatagramMessage: Sendable, Equatable {
    let direction: ConnectionDirection
    /// Where the frame sits in the source, with a locator when the caller supplied
    /// the source token, so the transcript can open the exact frame.
    let provenance: SessionFrameProvenance
    /// The retained payload prefix. Never longer than the reader's per-message bound.
    let payload: [UInt8]
    /// The payload length the frame carried as captured (before the message bound).
    let capturedPayloadLength: Int
    /// The UDP-declared payload length, when the header declared a usable one.
    let declaredPayloadLength: Int?
    /// The DNS reading, for a datagram the decoder recognised as DNS.
    var dns: FollowDNSMessage?

    /// The capture kept fewer payload bytes than the datagram declared.
    var isCaptureTruncated: Bool {
        guard let declaredPayloadLength else {
            return false
        }
        return capturedPayloadLength < declaredPayloadLength
    }

    /// Captured payload bytes the reader did not keep because of the per-message bound.
    var boundOmittedByteCount: Int {
        max(0, capturedPayloadLength - payload.count)
    }
}

// MARK: - FollowDatagramLimitations

/// Independently-set, neutral qualifications of a datagram follow. The absence of a
/// flag never proves the capture was complete.
nonisolated struct FollowDatagramLimitations: OptionSet, Sendable, Equatable {
    /// At least one datagram was captured shorter than its declared length.
    static let capturedPayloadTruncated = FollowDatagramLimitations(rawValue: 1 << 0)
    /// At least one retained datagram's payload exceeded the per-message bound.
    static let messageBytesBounded = FollowDatagramLimitations(rawValue: 1 << 1)
    /// The message or total-byte bound was reached; later datagrams were counted only.
    static let messageRetentionTruncated = FollowDatagramLimitations(rawValue: 1 << 2)
    /// The source file's tail was cut mid-record/-block.
    static let sourceTailTruncated = FollowDatagramLimitations(rawValue: 1 << 3)

    let rawValue: UInt8
}

// MARK: - FollowDatagramResult

/// The immutable result of one on-demand datagram follow: a **complete capture-order
/// prefix** of the conversation's datagrams (never a sample), the exact count of
/// datagrams beyond it, and the neutral limitations.
nonisolated struct FollowDatagramResult: Sendable, Equatable {
    let identity: PcapFileIdentity
    let format: CaptureStreamFormat
    let tuple: FiveTuple
    let messages: [FollowDatagramMessage]
    /// Matched datagrams after the retained prefix ended.
    let omittedMessageCount: Int
    /// Captured payload bytes of those omitted datagrams, saturating.
    let omittedPayloadByteCount: UInt64
    let matchedFrameCount: Int
    let scannedFrameCount: Int
    let limitations: FollowDatagramLimitations
    let completeness: FollowStreamCompleteness
    let finalProgress: PcapStreamProgress

    /// `true` when any retained message carries a DNS reading.
    var containsDNS: Bool {
        messages.contains { $0.dns != nil }
    }
}

// MARK: - FollowDatagramReader

/// A pure, synchronous, on-demand reader that lists one UDP conversation's
/// datagrams from a *stable* saved / stopped-live capture. It mirrors
/// ``FollowStreamReader``: one ``CaptureStreamReader``, identity checked before and
/// after the scan, every frame decoded once through `SessionBuilder.decodePacket`,
/// and only frames whose decoded canonical tuple *exactly* equals the requested one
/// are folded — direction comes from the tuple's `a`/`b`, never a role guess.
///
/// Retention contract: the result holds a complete capture-order prefix of the
/// matched datagrams. When a bound is reached the reader stops retaining and counts
/// every later datagram exactly; it never thins or evicts what it holds. Each
/// retained payload is itself a prefix under a per-message bound, with the
/// remainder counted on the message.
/// ``readEach(contentsOf:expectedIdentity:tuples:sourceToken:configuration:tuplesPerPass:_:)``
/// lists many conversations with one file pass per group, each exactly as a single
/// read would.
nonisolated final class FollowDatagramReader {
    // MARK: Lifecycle

    convenience init(
        contentsOf url: URL,
        expectedIdentity: PcapFileIdentity,
        tuple: FiveTuple,
        sourceToken: UUID? = nil,
        configuration: Configuration = Configuration()
    )
        throws
    {
        try self.init(
            contentsOf: url, expectedIdentity: expectedIdentity, tuples: [tuple],
            sourceToken: sourceToken, configuration: configuration
        )
    }

    /// One pass over `url` for every tuple in `tuples` (duplicates read once).
    /// Callers go through ``readEach``, which bounds the group size.
    private init(
        contentsOf url: URL,
        expectedIdentity: PcapFileIdentity,
        tuples: [FiveTuple],
        sourceToken: UUID?,
        configuration: Configuration
    )
        throws
    {
        guard tuples.allSatisfy({ $0.proto == .udp }) else {
            throw FollowStreamError.tupleNotUDP
        }
        var order: [FiveTuple] = []
        var conversations: [FiveTuple: Conversation] = [:]
        for tuple in tuples where conversations[tuple] == nil {
            order.append(tuple)
            conversations[tuple] = Conversation()
        }
        sourceURL = url
        self.order = order
        self.conversations = conversations
        self.sourceToken = sourceToken
        self.configuration = configuration
        let reader = try CaptureStreamReader(
            contentsOf: url,
            configuration: .init(
                maxCapturedLength: configuration.maxCapturedLength,
                isCancelled: configuration.isCancelled
            )
        )
        guard reader.identity.matches(expectedIdentity) else {
            throw FollowStreamError.identityMismatch
        }
        self.reader = reader
    }

    // MARK: Internal

    nonisolated struct Configuration: Sendable {
        // MARK: Lifecycle

        init(
            maxCapturedLength: Int = CapturedFrame.maxReasonableLength,
            maxMessages: Int = Configuration.defaultMaxMessages,
            maxPayloadBytesPerMessage: Int = Configuration.defaultMaxPayloadBytesPerMessage,
            maxRetainedPayloadBytes: Int = Configuration.defaultMaxRetainedPayloadBytes,
            progressStride: Int = 256,
            isCancelled: @escaping @Sendable () -> Bool = { Task.isCancelled }
        ) {
            self.maxCapturedLength = min(max(0, maxCapturedLength), CapturedFrame.maxReasonableLength)
            self.maxMessages = min(max(1, maxMessages), Self.ceilingMaxMessages)
            self.maxPayloadBytesPerMessage = min(
                max(0, maxPayloadBytesPerMessage), Self.ceilingMaxPayloadBytesPerMessage
            )
            self.maxRetainedPayloadBytes = min(
                max(0, maxRetainedPayloadBytes), Self.ceilingMaxRetainedPayloadBytes
            )
            self.progressStride = max(1, progressStride)
            self.isCancelled = isCancelled
        }

        // MARK: Internal

        /// The largest message count, per-message payload and total payload any
        /// caller may request. Passing a larger value is clamped, not honoured.
        static let defaultMaxMessages = 4_096
        static let defaultMaxPayloadBytesPerMessage = 16 << 10
        static let defaultMaxRetainedPayloadBytes = 2 << 20
        /// What a caller may raise the bounds to — Export Objects reads whole TFTP
        /// transfers — never past a UDP payload or the object export's byte bound.
        static let ceilingMaxMessages = 1 << 20
        static let ceilingMaxPayloadBytesPerMessage = 65_535
        static let ceilingMaxRetainedPayloadBytes = 256 << 20

        let maxCapturedLength: Int
        let maxMessages: Int
        let maxPayloadBytesPerMessage: Int
        let maxRetainedPayloadBytes: Int
        let progressStride: Int
        let isCancelled: @Sendable () -> Bool
    }

    /// The most conversations one pass lists together. Memory for a pass is at most
    /// this many times the retained-payload bound.
    static let maximumTuplesPerPass = 64

    /// Pair each DNS response with the earliest still-unanswered query that carried
    /// the same transaction id in the opposite direction, and link the query back.
    /// A retransmitted query stays unpaired once its twin has taken the response,
    /// so a retry reads as a retry rather than as two answered questions.
    static func pairDNS(_ messages: [FollowDatagramMessage]) -> [FollowDatagramMessage] {
        var paired = messages
        var open: [UInt16: [Int]] = [:]
        for index in paired.indices {
            guard let dns = paired[index].dns else {
                continue
            }
            if !dns.isResponse {
                open[dns.transactionID, default: []].append(index)
                continue
            }
            let direction = paired[index].direction
            guard var candidates = open[dns.transactionID],
                  let position = candidates.firstIndex(where: { paired[$0].direction != direction }) else
            {
                continue
            }
            let queryIndex = candidates.remove(at: position)
            open[dns.transactionID] = candidates
            paired[index].dns?.pairedMessageIndex = queryIndex
            paired[queryIndex].dns?.pairedMessageIndex = index
        }
        return paired
    }

    /// List every tuple in `tuples` with one scan of `url` per group of
    /// `tuplesPerPass`, handing each result to `body` in the order given (a repeated
    /// tuple is read once) as soon as its group's pass ends. Each result is the one
    /// a single read of that tuple would return.
    ///
    /// - Parameter tuplesPerPass: clamped to `1...maximumTuplesPerPass`.
    /// - Throws: ``FollowStreamError/tupleNotUDP`` before any scan when a tuple is
    ///   not UDP; otherwise whatever a single read throws, or what `body` throws.
    static func readEach(
        contentsOf url: URL,
        expectedIdentity: PcapFileIdentity,
        tuples: [FiveTuple],
        sourceToken: UUID? = nil,
        configuration: Configuration = Configuration(),
        tuplesPerPass: Int = 16,
        _ body: (FollowDatagramResult) throws -> Void
    )
        throws
    {
        guard tuples.allSatisfy({ $0.proto == .udp }) else {
            throw FollowStreamError.tupleNotUDP
        }
        var seen = Set<FiveTuple>()
        let unique = tuples.filter { seen.insert($0).inserted }
        let group = min(max(1, tuplesPerPass), maximumTuplesPerPass)
        var start = 0
        while start < unique.count {
            if configuration.isCancelled() {
                throw CancellationError()
            }
            let end = min(start + group, unique.count)
            let results = try FollowDatagramReader(
                contentsOf: url, expectedIdentity: expectedIdentity, tuples: Array(unique[start ..< end]),
                sourceToken: sourceToken, configuration: configuration
            ).readAll()
            for result in results {
                try body(result)
            }
            start = end
        }
    }

    /// Scan to the terminal and return the bounded conversation.
    ///
    /// - Throws: `CancellationError`, `PacketError.malformed`, or
    ///   ``FollowStreamError/identityMismatch`` when the file changed during the scan.
    func read(onProgress: (PcapStreamProgress) -> Void = { _ in }) throws -> FollowDatagramResult {
        guard let result = try readAll(onProgress: onProgress).first else {
            // The public initializer always asks for exactly one tuple.
            preconditionFailure("A follow read has one requested conversation.")
        }
        return result
    }

    // MARK: Private

    private let sourceURL: URL
    /// Requested tuples, first-asked order, each once.
    private let order: [FiveTuple]
    private let sourceToken: UUID?
    private let configuration: Configuration
    private let reader: CaptureStreamReader

    private var conversations: [FiveTuple: Conversation]
    /// Rebuilds fragmented IP datagrams across this one pass over the capture.
    private var sequential = SequentialFrameDecoder()

    private static func dnsReading(of packet: DecodedPacket) -> FollowDNSMessage? {
        guard packet.appProtocol == .dns, let facts = packet.dnsFacts else {
            return nil
        }
        return FollowDNSMessage(
            transactionID: facts.transactionID,
            isResponse: facts.isResponse,
            opcode: facts.opcode,
            responseCode: facts.responseCode,
            isTruncated: facts.isTruncated,
            questionName: packet.dnsQuery ?? "",
            questionType: packet.dnsQueryType,
            answerRecords: packet.dnsAnswerRecords,
            omittedAnswerCount: packet.dnsAnswersOmittedCount,
            pairedMessageIndex: nil
        )
    }

    /// Scan once and return every requested conversation in `order`.
    private func readAll(onProgress: (PcapStreamProgress) -> Void = { _ in }) throws -> [FollowDatagramResult] {
        var scanned = 0
        let completion: CaptureStreamCompletion
        walk: while true {
            switch try reader.next() {
            case let .frame(event):
                scanned += 1
                fold(event, ordinal: scanned)
                if scanned % configuration.progressStride == 0 {
                    onProgress(event.progress)
                }
            case let .end(end):
                completion = end
                break walk
            }
        }
        try revalidateSourceIdentity()
        onProgress(completion.progress)

        let completeness: FollowStreamCompleteness = switch completion.reason {
        case .cleanEndOfFile: .complete
        case .partialHeader,
             .partialBody: .incompleteTruncatedTail(completion.reason)
        }

        return order.compactMap { tuple in
            guard var conversation = conversations.removeValue(forKey: tuple) else {
                return nil
            }
            if case .incompleteTruncatedTail = completeness {
                conversation.limitations.insert(.sourceTailTruncated)
            }
            return FollowDatagramResult(
                identity: reader.identity,
                format: reader.format,
                tuple: tuple,
                messages: Self.pairDNS(conversation.messages),
                omittedMessageCount: conversation.omittedMessages,
                omittedPayloadByteCount: conversation.omittedBytes,
                matchedFrameCount: conversation.matched,
                scannedFrameCount: scanned,
                limitations: conversation.limitations,
                completeness: completeness,
                finalProgress: completion.progress
            )
        }
    }

    private func fold(_ event: CaptureFrameEvent, ordinal: Int) {
        let frame = CapturedFrame(
            bytes: event.bytes,
            timestamp: event.reference.timestamp,
            originalLength: event.reference.originalLength,
            capturedLength: event.reference.capturedLength,
            linkType: event.reference.linkType
        )
        let locator = sourceToken.map {
            SessionEvidenceLocator(sourceToken: $0, offset: event.reference.payloadOffset)
        }
        let packet = sequential.decode(
            frame,
            linkType: reader.defaultLinkType ?? event.reference.linkType,
            ordinal: UInt64(ordinal),
            locator: locator
        )
        guard packet.transport == .udp,
              let tuple = packet.fiveTuple, conversations[tuple] != nil,
              let source = packet.sourceEndpoint,
              let destination = packet.destinationEndpoint else
        {
            return
        }
        let direction: ConnectionDirection
        if source == tuple.a, destination == tuple.b {
            direction = .aToB
        } else if source == tuple.b, destination == tuple.a {
            direction = .bToA
        } else {
            return
        }
        // A reassembled datagram's payload is not in this frame's bytes; it comes
        // with the decode instead.
        let payload: ArraySlice<UInt8>
        if let reassembled = packet.reassembledUDPPayload {
            payload = reassembled[...]
        } else {
            let range = packet.udpPayloadRange.map { range in
                range.clamped(to: 0 ..< event.bytes.count)
            } ?? 0 ..< 0
            payload = event.bytes[range]
        }
        let provenance = SessionFrameProvenance(
            ordinal: FrameOrdinal(UInt64(ordinal)),
            timestamp: event.reference.timestamp,
            capturedLength: event.reference.capturedLength,
            originalLength: event.reference.originalLength,
            linkType: event.reference.linkType,
            locator: locator,
            reassembledFrom: sequential.lastReassembledFrom
        )
        // Mutated in place through the dictionary: retained messages are never
        // copied per frame.
        conversations[tuple]?.fold(
            direction: direction,
            payload: payload,
            declaredPayloadLength: packet.udpDeclaredPayloadLength,
            dns: Self.dnsReading(of: packet),
            provenance: provenance,
            configuration: configuration
        )
    }

    private func revalidateSourceIdentity() throws {
        guard let handle = try? FileHandle(forReadingFrom: sourceURL) else {
            throw FollowStreamError.identityMismatch
        }
        defer { try? handle.close() }
        guard PcapFileIdentity.snapshot(of: handle).matches(reader.identity) else {
            throw FollowStreamError.identityMismatch
        }
    }
}

// MARK: FollowDatagramReader.Conversation

private extension FollowDatagramReader {
    /// One requested conversation's retained prefix and exact counts.
    nonisolated struct Conversation {
        var messages: [FollowDatagramMessage] = []
        var retainedBytes = 0
        var matched = 0
        var omittedMessages = 0
        var omittedBytes: UInt64 = 0
        var limitations: FollowDatagramLimitations = []
        var retentionEnded = false

        mutating func fold(
            direction: ConnectionDirection,
            payload captured: ArraySlice<UInt8>,
            declaredPayloadLength: Int?,
            dns: @autoclosure () -> FollowDNSMessage?,
            provenance: SessionFrameProvenance,
            configuration: Configuration
        ) {
            matched += 1
            let capturedPayload = captured.count
            if let declaredPayloadLength, capturedPayload < declaredPayloadLength {
                limitations.insert(.capturedPayloadTruncated)
            }

            let keep = min(capturedPayload, configuration.maxPayloadBytesPerMessage)
            // Once one datagram is refused every later one is too, even a smaller one,
            // so the retained set stays a prefix: counted exactly, never out of order.
            if retentionEnded
                || messages.count >= configuration.maxMessages
                || retainedBytes + keep > configuration.maxRetainedPayloadBytes
            {
                retentionEnded = true
                limitations.insert(.messageRetentionTruncated)
                omittedMessages += 1
                omittedBytes = omittedBytes > UInt64.max - UInt64(capturedPayload)
                    ? .max
                    : omittedBytes + UInt64(capturedPayload)
                return
            }
            if keep < capturedPayload {
                limitations.insert(.messageBytesBounded)
            }
            retainedBytes += keep
            messages.append(FollowDatagramMessage(
                direction: direction,
                provenance: provenance,
                payload: Array(captured.prefix(keep)),
                capturedPayloadLength: capturedPayload,
                declaredPayloadLength: declaredPayloadLength,
                dns: dns()
            ))
        }
    }
}
