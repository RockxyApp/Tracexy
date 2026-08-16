import Foundation

// MARK: - CapturedFrameMessage

/// One captured frame, ferried across the app↔helper XPC boundary as a typed,
/// `NSSecureCoding` object rather than a bare `Data`.
///
/// The legacy surface drained a `[Data]` plus a single link type: every frame in
/// a batch then shared one wall-clock timestamp assigned app-side, the captured
/// length was inferred from `bytes.count`, and the true on-wire length was lost.
/// That is exactly the kind of quiet fidelity loss the capture path must not
/// have. This type carries each frame's own libpcap timestamp (seconds +
/// microseconds, as `struct timeval` reports it), the captured length, the
/// original on-wire length (which exceeds the captured length when a snaplen
/// truncated the packet), and the per-frame link type — nothing is inferred or
/// shared across a batch.
///
/// Decoding is deliberately total: `init(coder:)` never traps and never rejects,
/// it reads whatever is present. Validation and truthful rejection happen at the
/// app-side conversion to `CapturedFrame`, so a malformed message degrades to a
/// dropped frame instead of a decode failure that could wedge the connection.
@objc(TracexyCapturedFrameMessage)
nonisolated final class CapturedFrameMessage: NSObject, NSSecureCoding, @unchecked Sendable {
    // MARK: Lifecycle

    init(
        bytes: Data,
        timestampSeconds: Int64,
        timestampMicroseconds: Int64,
        capturedLength: Int64,
        originalLength: Int64,
        linkType: UInt32
    ) {
        self.bytes = bytes
        self.timestampSeconds = timestampSeconds
        self.timestampMicroseconds = timestampMicroseconds
        self.capturedLength = capturedLength
        self.originalLength = originalLength
        self.linkType = linkType
    }

    required init?(coder: NSCoder) {
        bytes = (coder.decodeObject(of: NSData.self, forKey: Key.bytes)).map { $0 as Data } ?? Data()
        timestampSeconds = coder.decodeInt64(forKey: Key.timestampSeconds)
        timestampMicroseconds = coder.decodeInt64(forKey: Key.timestampMicroseconds)
        capturedLength = coder.decodeInt64(forKey: Key.capturedLength)
        originalLength = coder.decodeInt64(forKey: Key.originalLength)
        linkType = UInt32(bitPattern: coder.decodeInt32(forKey: Key.linkType))
    }

    // MARK: Internal

    static var supportsSecureCoding: Bool {
        true
    }

    let bytes: Data
    /// `struct timeval` seconds, straight from the libpcap per-packet header.
    let timestampSeconds: Int64
    /// `struct timeval` microseconds. Kept separate from seconds so the precise
    /// capture instant survives — never collapsed to a shared batch `Date`.
    let timestampMicroseconds: Int64
    /// Bytes actually captured (`pcap_pkthdr.caplen`). The app requires this to
    /// agree with `bytes.count`; malformed metadata is rejected, not normalized.
    let capturedLength: Int64
    /// Original on-wire length (`pcap_pkthdr.len`), which may exceed the captured
    /// length. Carried explicitly so it is never inferred from `bytes.count`.
    let originalLength: Int64
    /// The DLT for *this* frame. Homogeneous for a normal capture, but carried
    /// per frame so a link type is always authoritative rather than assumed.
    let linkType: UInt32

    func encode(with coder: NSCoder) {
        coder.encode(bytes as NSData, forKey: Key.bytes)
        coder.encode(timestampSeconds, forKey: Key.timestampSeconds)
        coder.encode(timestampMicroseconds, forKey: Key.timestampMicroseconds)
        coder.encode(capturedLength, forKey: Key.capturedLength)
        coder.encode(originalLength, forKey: Key.originalLength)
        coder.encode(Int32(bitPattern: linkType), forKey: Key.linkType)
    }

    // MARK: Private

    private enum Key {
        static let bytes = "b"
        static let timestampSeconds = "ts"
        static let timestampMicroseconds = "tu"
        static let capturedLength = "cl"
        static let originalLength = "ol"
        static let linkType = "lt"
    }
}

// MARK: - FrameBatchMessage

/// A drained batch of captured frames plus the capture accounting that qualifies
/// it. Everything the UI needs to state honestly *how much it might have missed*
/// travels with the frames, so no number is presented without its caveat.
@objc(TracexyFrameBatchMessage)
nonisolated final class FrameBatchMessage: NSObject, NSSecureCoding, @unchecked Sendable {
    // MARK: Lifecycle

    init(
        frames: [CapturedFrameMessage],
        bufferDroppedCount: UInt64,
        captureLinkType: UInt32,
        stats: HelperCaptureStats?
    ) {
        self.frames = frames
        self.bufferDroppedCount = bufferDroppedCount
        self.captureLinkType = captureLinkType
        statsAvailable = stats != nil
        statsReceived = stats?.received ?? 0
        statsDroppedByKernel = stats?.droppedByKernel ?? 0
        statsDroppedByInterface = stats?.droppedByInterface ?? 0
    }

    required init?(coder: NSCoder) {
        let decodedFrames = coder.decodeObject(
            of: [NSArray.self, CapturedFrameMessage.self], forKey: Key.frames
        ) as? [CapturedFrameMessage]
        frames = decodedFrames ?? []
        bufferDroppedCount = UInt64(bitPattern: coder.decodeInt64(forKey: Key.bufferDropped))
        captureLinkType = UInt32(bitPattern: coder.decodeInt32(forKey: Key.captureLinkType))
        statsAvailable = coder.decodeBool(forKey: Key.statsAvailable)
        statsReceived = UInt32(bitPattern: coder.decodeInt32(forKey: Key.statsReceived))
        statsDroppedByKernel = UInt32(bitPattern: coder.decodeInt32(forKey: Key.statsDroppedByKernel))
        statsDroppedByInterface = UInt32(bitPattern: coder.decodeInt32(forKey: Key.statsDroppedByInterface))
    }

    // MARK: Internal

    static var supportsSecureCoding: Bool {
        true
    }

    let frames: [CapturedFrameMessage]
    /// Cumulative count of frames the helper's *own* bounded buffer evicted
    /// because the app did not drain fast enough. Distinct from kernel/interface
    /// loss and from the app's UI-retention eviction — a different stage of the
    /// pipeline, never conflated with them.
    let bufferDroppedCount: UInt64
    /// Representative outer DLT for the capture, used to write a faithful savefile.
    let captureLinkType: UInt32
    /// Whether `pcap_stats` was available for this capture. When false the app
    /// must show accounting as *unknown* rather than imply a perfect capture.
    let statsAvailable: Bool
    let statsReceived: UInt32
    let statsDroppedByKernel: UInt32
    let statsDroppedByInterface: UInt32

    /// The kernel/interface accounting, or `nil` when `pcap_stats` was unavailable.
    var stats: HelperCaptureStats? {
        guard statsAvailable else {
            return nil
        }
        return HelperCaptureStats(
            received: statsReceived,
            droppedByKernel: statsDroppedByKernel,
            droppedByInterface: statsDroppedByInterface
        )
    }

    func encode(with coder: NSCoder) {
        coder.encode(frames as NSArray, forKey: Key.frames)
        coder.encode(Int64(bitPattern: bufferDroppedCount), forKey: Key.bufferDropped)
        coder.encode(Int32(bitPattern: captureLinkType), forKey: Key.captureLinkType)
        coder.encode(statsAvailable, forKey: Key.statsAvailable)
        coder.encode(Int32(bitPattern: statsReceived), forKey: Key.statsReceived)
        coder.encode(Int32(bitPattern: statsDroppedByKernel), forKey: Key.statsDroppedByKernel)
        coder.encode(Int32(bitPattern: statsDroppedByInterface), forKey: Key.statsDroppedByInterface)
    }

    // MARK: Private

    private enum Key {
        static let frames = "f"
        static let bufferDropped = "d"
        static let captureLinkType = "lt"
        static let statsAvailable = "sa"
        static let statsReceived = "sr"
        static let statsDroppedByKernel = "sk"
        static let statsDroppedByInterface = "si"
    }
}

// MARK: - HelperCaptureStats

/// Raw kernel/interface capture accounting sampled from `pcap_stats`, shared
/// verbatim from the helper to the app. The app maps it onto its richer
/// `CaptureStatistics` (which adds fidelity/threshold logic); the helper only
/// reports the three counters libpcap gives it.
nonisolated struct HelperCaptureStats: Sendable, Equatable {
    var received: UInt32
    var droppedByKernel: UInt32
    var droppedByInterface: UInt32
}

// MARK: - CaptureConfigurationError

/// Why an immutable capture configuration was rejected. Carries a user-facing
/// `message` so the app can surface *why* a capture never started, and the helper
/// can fail the start reply with the same explanation.
nonisolated enum CaptureConfigurationError: Error, Equatable {
    case emptyInterface
    case interfaceTooLong
    case bpfTooLong

    // MARK: Internal

    var message: String {
        switch self {
        case .emptyInterface:
            "no capture interface was specified."
        case .interfaceTooLong:
            "the capture interface name is too long."
        case .bpfTooLong:
            "the BPF filter expression is too long."
        }
    }
}

// MARK: - CaptureConfiguration

/// The immutable capture parameters ferried across the app↔helper XPC boundary as
/// a typed, `NSSecureCoding` object: the interface to open, the snap length, the
/// promiscuous flag, and an optional BPF filter expression.
///
/// This is the *only* privileged command surface — a fixed, validated description
/// of a capture, never an arbitrary command. Both the app (before it asks the
/// helper to start) and the helper (before it opens libpcap) run the same
/// ``validated()`` so bounds are enforced on both sides: the snap length is
/// clamped into a supported range, the interface must be present and reasonable,
/// and an over-long BPF expression is rejected with a clear message. Syntactic BPF
/// validation happens against libpcap at open time — a bad expression fails the
/// start *before* any capture is reported running.
///
/// Decoding is deliberately total: `init(coder:)` never traps. Whatever crosses
/// the wire is validated by ``validated()`` on receipt, so a malformed message is
/// rejected truthfully rather than trusted.
@objc(TracexyCaptureConfiguration)
nonisolated final class CaptureConfiguration: NSObject, NSSecureCoding, @unchecked Sendable {
    // MARK: Lifecycle

    init(interface: String, snapLength: Int, promiscuous: Bool, bpf: String?) {
        self.interface = interface
        self.snapLength = snapLength
        self.promiscuous = promiscuous
        self.bpf = bpf
    }

    required init?(coder: NSCoder) {
        interface = (coder.decodeObject(of: NSString.self, forKey: Key.interface) as String?) ?? ""
        // A snap length written as Int64; a nonsensical value is caught by `validated()`.
        snapLength = Int(coder.decodeInt64(forKey: Key.snapLength))
        promiscuous = coder.decodeBool(forKey: Key.promiscuous)
        // A missing/empty BPF string decodes to `nil` — no filter.
        let decodedBPF = coder.decodeObject(of: NSString.self, forKey: Key.bpf) as String?
        bpf = (decodedBPF?.isEmpty ?? true) ? nil : decodedBPF
    }

    // MARK: Internal

    /// Supported snap-length range. The floor keeps enough of a frame for L2–L4
    /// headers; the ceiling matches the largest preset the UI offers and is well
    /// above any real frame, so a larger persisted value is clamped rather than
    /// trusted into an oversized buffer.
    static let snapLengthRange: ClosedRange<Int> = 64 ... 262_144
    /// Full-frame default used when a persisted snap length is missing or unusable.
    static let defaultSnapLength = 65_536
    /// Upper bound on a BPF expression's length. A real filter is short; anything
    /// longer is rejected rather than handed to `pcap_compile`.
    static let maxBPFLength = 1_024
    /// Upper bound on an interface name's length (BSD names are a handful of chars).
    static let maxInterfaceLength = 128

    static var supportsSecureCoding: Bool {
        true
    }

    let interface: String
    let snapLength: Int
    let promiscuous: Bool
    /// Trimmed BPF expression, or `nil` for "capture everything". Never an empty
    /// string — an empty filter is normalized to `nil` so it is unambiguous.
    let bpf: String?

    /// Clamp a raw snap length into the supported range. A non-positive value is
    /// treated as unset and becomes the full-frame default; anything else is
    /// clamped to the nearest supported bound.
    static func clampedSnapLength(_ raw: Int) -> Int {
        guard raw > 0 else {
            return defaultSnapLength
        }
        return min(max(raw, snapLengthRange.lowerBound), snapLengthRange.upperBound)
    }

    /// Validate and normalize. Returns a copy with a clamped snap length and a
    /// trimmed/normalized BPF, or the reason it was rejected. Never traps.
    func validated() -> Result<CaptureConfiguration, CaptureConfigurationError> {
        let trimmedInterface = interface.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedInterface.isEmpty else {
            return .failure(.emptyInterface)
        }
        guard trimmedInterface.count <= Self.maxInterfaceLength else {
            return .failure(.interfaceTooLong)
        }
        var normalizedBPF: String?
        if let bpf {
            let trimmed = bpf.trimmingCharacters(in: .whitespacesAndNewlines)
            if trimmed.isEmpty {
                normalizedBPF = nil
            } else if trimmed.count > Self.maxBPFLength {
                return .failure(.bpfTooLong)
            } else {
                normalizedBPF = trimmed
            }
        }
        return .success(CaptureConfiguration(
            interface: trimmedInterface,
            snapLength: Self.clampedSnapLength(snapLength),
            promiscuous: promiscuous,
            bpf: normalizedBPF
        ))
    }

    func encode(with coder: NSCoder) {
        coder.encode(interface as NSString, forKey: Key.interface)
        coder.encode(Int64(snapLength), forKey: Key.snapLength)
        coder.encode(promiscuous, forKey: Key.promiscuous)
        if let bpf {
            coder.encode(bpf as NSString, forKey: Key.bpf)
        }
    }

    // MARK: Private

    private enum Key {
        static let interface = "if"
        static let snapLength = "sl"
        static let promiscuous = "pr"
        static let bpf = "bpf"
    }
}

// MARK: - TracexyHelperInterface

/// Builds the `NSXPCInterface` for `TracexyHelperProtocol` with the secure-coding
/// allow-list configured for the typed `fetchFrames` reply. Shared so the app's
/// `remoteObjectInterface` and the helper's `exportedInterface` are configured
/// identically — a mismatch would silently fail decoding at runtime.
nonisolated enum TracexyHelperInterface {
    static func make() -> NSXPCInterface {
        let interface = NSXPCInterface(with: TracexyHelperProtocol.self)
        // Class metatypes aren't `Hashable` in Swift, so the allow-list is built
        // as an `NSSet` and bridged — the standard shape for this ObjC API.
        let classes: [Any] = [
            FrameBatchMessage.self,
            CapturedFrameMessage.self,
            NSArray.self,
            NSData.self,
        ]
        if let allowed = NSSet(array: classes) as? Set<AnyHashable> {
            interface.setClasses(
                allowed,
                for: #selector(TracexyHelperProtocol.fetchFrames(withReply:)),
                argumentIndex: 0,
                ofReply: true
            )
            interface.setClasses(
                allowed,
                for: #selector(TracexyHelperProtocol.stopCapture(withReply:)),
                argumentIndex: 0,
                ofReply: true
            )
        }
        // The immutable capture configuration is the one typed object the app
        // *sends* to the helper, so its allow-list is set on the request argument
        // (`ofReply: false`) rather than a reply.
        if let allowedConfig = NSSet(array: [CaptureConfiguration.self, NSString.self]) as? Set<AnyHashable> {
            interface.setClasses(
                allowedConfig,
                for: #selector(TracexyHelperProtocol.startCapture(configuration:withReply:)),
                argumentIndex: 0,
                ofReply: false
            )
        }
        return interface
    }
}
