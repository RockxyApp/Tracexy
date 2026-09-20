import Foundation

// The provider-neutral assistant seam.
//
// It is neutral so a future packaging decision has somewhere to plug in — and
// deliberately empty of anything a remote provider would need. There is no API
// key, no credential, no account, no organization, no header dictionary and no
// entitlement anywhere in this file, and the Community checkout ships exactly one
// conformance: a credential-free adapter that only talks to loopback.

// MARK: - AssistantLimits

/// Every bound one exchange is held to. They are constants, not settings, so a
/// misconfigured endpoint cannot make the app read forever.
nonisolated enum AssistantLimits {
    /// The largest request body the app will send, in bytes.
    static let maxRequestBytes = 524_288
    /// The largest cumulative response body the app will read, in bytes.
    static let maxResponseBytes = 2_097_152
    /// The largest single streamed line, in bytes.
    static let maxLineBytes = 262_144
    /// The largest answer the app will accumulate, in characters.
    static let maxOutputCharacters = 32_000
    /// The output token budget requested from the model.
    static let maxOutputTokens = 1_024
    /// The largest model list the app will adopt.
    static let maxModels = 64
    /// The largest discovery response the app will read, in bytes.
    static let maxDiscoveryBytes = 262_144
    /// Seconds allowed before the first byte of a response arrives.
    static let firstByteTimeout: TimeInterval = 30
    /// Seconds allowed for the whole exchange.
    static let totalTimeout: TimeInterval = 180
    /// Seconds allowed for one discovery request.
    static let discoveryTimeout: TimeInterval = 10
    /// The largest prompt the user may type, in characters.
    static let maxPromptCharacters = 4_000
}

// MARK: - AssistantProviderKind

/// What the app can honestly claim about an endpoint.
nonisolated enum AssistantProviderKind: String, Sendable, Equatable, Codable {
    /// Discovery answered on the Ollama-native path, so the app knows the shape.
    case ollama
    /// Discovery answered on the OpenAI-compatible path. The app does **not**
    /// claim to know which server this is; it says only that the endpoint speaks
    /// a local OpenAI-compatible API.
    case localOpenAICompatible

    // MARK: Internal

    var label: String {
        switch self {
        case .ollama: "Ollama (local)"
        case .localOpenAICompatible: "Local OpenAI-compatible"
        }
    }
}

// MARK: - AssistantModel

/// One model the local endpoint advertises.
nonisolated struct AssistantModel: Sendable, Hashable, Identifiable, Codable {
    let id: String
    /// The label to show. Identical to `id` for endpoints that publish no
    /// separate display name — the app never invents one.
    let name: String
}

// MARK: - AssistantDiscovery

/// The result of one discovery round.
nonisolated struct AssistantDiscovery: Sendable, Equatable {
    let kind: AssistantProviderKind
    let models: [AssistantModel]
    /// Models the endpoint advertised beyond ``AssistantLimits/maxModels``.
    let omittedModelCount: Int
}

// MARK: - AssistantChatRequest

/// One bounded exchange. It carries the reviewed brief text verbatim — the same
/// bytes the Review Data sheet showed — and nothing else about the capture.
nonisolated struct AssistantChatRequest: Sendable, Equatable {
    let model: String
    let systemPrompt: String
    let userPrompt: String
    /// The canonical brief JSON the user reviewed.
    let briefJSON: String
}

// MARK: - AssistantStreamEvent

/// One incremental event from a streamed answer.
nonisolated enum AssistantStreamEvent: Sendable, Equatable {
    /// A fragment of the answer, in arrival order.
    case token(String)
    /// The model finished on its own terms.
    case completed(reason: String?)
    /// The app stopped reading because a bound was reached. The text collected so
    /// far is real, but the answer is incomplete and must be shown as such.
    case truncated(AssistantTruncationReason)
}

// MARK: - AssistantFinishOutcome

/// How the app reads a provider's own finish reason. The string is untrusted
/// input from a local process, so it is classified into a closed set here and
/// never shown to the user or treated as a conclusion on its own.
nonisolated enum AssistantFinishOutcome: Sendable, Equatable {
    /// The model stopped on its own terms.
    case complete
    /// The model hit its output-token budget. The text is real but the answer
    /// is incomplete, exactly like the app's own answer-length bound.
    case outputLimit
    /// A reason this app does not recognize. Treated conservatively as a
    /// failure rather than as a finished answer.
    case unrecognized

    // MARK: Internal

    /// Finish reasons that mean a complete answer, across the two shapes read.
    static let completeReasons: Set<String> = ["stop", "end", "end_turn", "stop_sequence", "eos"]
    /// Finish reasons that mean the output budget cut the answer short.
    static let outputLimitReasons: Set<String> = ["length", "max_tokens", "max_output_tokens"]

    /// Classify one finish reason. A `nil` reason is the provider's bare done
    /// marker (for example an SSE `[DONE]`), which is completion.
    static func classify(_ reason: String?) -> AssistantFinishOutcome {
        guard let reason else {
            return .complete
        }
        let normalized = reason.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if completeReasons.contains(normalized) {
            return .complete
        }
        if outputLimitReasons.contains(normalized) {
            return .outputLimit
        }
        return .unrecognized
    }
}

// MARK: - AssistantTruncationReason

nonisolated enum AssistantTruncationReason: String, Sendable, Equatable {
    case outputLimit
    case responseSizeLimit
    case timeLimit
    /// The connection closed without the provider's explicit done marker. Any
    /// text received is real, but it is not a complete answer.
    case unexpectedEnd
}

// MARK: - AssistantError

/// Every controlled failure of the local assistant path. None carries a URL, a
/// path, a header or a response body.
nonisolated enum AssistantError: Error, Sendable, Equatable {
    /// The endpoint could not be reached at all.
    case unreachable
    /// Discovery found no usable API on the endpoint.
    case notALocalModelEndpoint
    /// The endpoint answered, but advertised no models.
    case noModelsAvailable
    /// The endpoint answered with a non-success status.
    case httpStatus(Int)
    /// A redirect pointed somewhere that is not on this Mac. Nothing was followed.
    case redirectRejected
    /// A streamed line was not valid JSON of the expected shape.
    case malformedStream
    /// A streamed line exceeded ``AssistantLimits/maxLineBytes``.
    case streamLineTooLong
    /// The prompt or the brief exceeded the request bound.
    case requestTooLarge
    /// Nothing arrived before ``AssistantLimits/firstByteTimeout``.
    case timedOut
    /// The selected model is not one the endpoint advertised.
    case modelUnavailable

    // MARK: Internal

    /// Actionable copy for the transcript's error row.
    var message: String {
        switch self {
        case .unreachable:
            "Couldn’t reach the local model. Make sure it’s running, then try again."
        case .notALocalModelEndpoint:
            "That address answered, but it isn’t a local model API."
        case .noModelsAvailable:
            "The local endpoint has no models installed."
        case let .httpStatus(code):
            "The local model returned HTTP \(code)."
        case .redirectRejected:
            "The local endpoint redirected off this Mac. Nothing was sent there."
        case .malformedStream:
            "The local model sent a response Tracexy couldn’t read."
        case .streamLineTooLong:
            "The local model sent an oversized response line."
        case .requestTooLarge:
            "This request is larger than Tracexy will send. Shorten the prompt."
        case .timedOut:
            "The local model didn’t respond in time."
        case .modelUnavailable:
            "That model isn’t available at this endpoint. Choose another."
        }
    }
}

// MARK: - AssistantProviding

/// The provider-neutral seam. Two operations, both bounded and cancellable.
nonisolated protocol AssistantProviding: Sendable {
    /// What the app may honestly say about this endpoint, once discovered.
    var endpoint: AssistantLocalEndpoint { get }

    /// Discover which local API the endpoint speaks and which models it has.
    func discover() async throws -> AssistantDiscovery

    /// Stream one bounded answer. Cancelling the consuming task stops the read
    /// and the underlying request promptly.
    func stream(_ request: AssistantChatRequest, kind: AssistantProviderKind)
        -> AsyncThrowingStream<AssistantStreamEvent, Error>
}
