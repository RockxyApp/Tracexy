import Foundation

// The single place that decides whether a URL is a *local* model endpoint.
//
// The rule is deliberately narrow and literal: the host must already be a
// loopback literal, or the one name (`localhost`) this app maps explicitly to
// one. Nothing here performs DNS. A name that is not `localhost` is refused
// rather than resolved, because a resolver's answer can change between the check
// and the request, and a "local" assistant that silently followed a rebound name
// would not be local at all.

// MARK: - AssistantEndpointError

/// Why a candidate endpoint is not a local model endpoint. Each case is user-
/// actionable copy in the Settings pane, never a silent downgrade.
nonisolated enum AssistantEndpointError: Error, Sendable, Equatable {
    case empty
    case notAURL
    case unsupportedScheme(String)
    case missingHost
    /// The host is neither a loopback literal nor `localhost`.
    case notLoopback(String)
    /// The URL carried a user or password component.
    case embeddedCredentials
    case invalidPort(Int)
    /// The URL carried a query or fragment; a base endpoint is a base, not a call.
    case unsupportedComponents
    case pathTooLong

    // MARK: Internal

    var message: String {
        switch self {
        case .empty: "Enter a local model endpoint."
        case .notAURL: "That is not a valid URL."
        case let .unsupportedScheme(scheme):
            "“\(scheme)” endpoints aren’t supported. Use http:// or https:// on this Mac."
        case .missingHost: "The endpoint has no host."
        case let .notLoopback(host):
            "“\(host)” isn’t on this Mac. Tracexy only sends to 127.0.0.1, ::1 or localhost."
        case .embeddedCredentials: "Remove the user name and password from the URL."
        case let .invalidPort(port): "Port \(port) is outside the valid range."
        case .unsupportedComponents: "Remove the query and fragment — this is a base address."
        case .pathTooLong: "The endpoint path is too long."
        }
    }
}

// MARK: - AssistantLocalEndpoint

/// A validated loopback base address.
nonisolated struct AssistantLocalEndpoint: Sendable, Hashable {
    // MARK: Lifecycle

    private init(baseURL: URL, displayText: String) {
        self.baseURL = baseURL
        self.displayText = displayText
    }

    // MARK: Internal

    /// The default endpoint: a local Ollama daemon.
    static let defaultText = "http://127.0.0.1:11434"

    /// Every host literal this app will send to, plus the one name it maps.
    /// `localhost` is mapped to the IPv4 loopback *explicitly* rather than
    /// resolved, so the request cannot follow a rebound name.
    static let loopbackLiterals: Set<String> = ["127.0.0.1", "::1", "localhost"]

    /// The one host name accepted, and the numeric literal it is rewritten to
    /// before any URL is built. No request ever carries the name itself.
    static let mappedHostName = "localhost"
    static let mappedHostLiteral = "127.0.0.1"

    /// The longest base path accepted, in characters.
    static let maxPathLength = 128

    let baseURL: URL
    /// The canonical validated base address used by Settings, review approval and
    /// run pinning. Cosmetic whitespace or a trailing slash cannot create two
    /// identities for the same endpoint.
    let displayText: String

    /// The production default.
    static func standard() throws -> AssistantLocalEndpoint {
        try validate(defaultText)
    }

    /// Validate one candidate endpoint. Pure: no DNS, no connection, no I/O.
    static func validate(_ text: String) throws -> AssistantLocalEndpoint {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw AssistantEndpointError.empty
        }
        guard var components = URLComponents(string: trimmed) else {
            throw AssistantEndpointError.notAURL
        }
        let scheme = (components.scheme ?? "").lowercased()
        guard ["http", "https"].contains(scheme) else {
            throw AssistantEndpointError.unsupportedScheme(scheme.isEmpty ? trimmed : scheme)
        }
        guard components.user == nil, components.password == nil else {
            throw AssistantEndpointError.embeddedCredentials
        }
        guard components.query == nil, components.fragment == nil else {
            throw AssistantEndpointError.unsupportedComponents
        }
        guard let rawHost = components.host, !rawHost.isEmpty else {
            throw AssistantEndpointError.missingHost
        }
        let host = normalizedHost(rawHost)
        guard loopbackLiterals.contains(host) else {
            throw AssistantEndpointError.notLoopback(rawHost)
        }
        // `localhost` is canonicalized to the numeric loopback literal here, so
        // the validated base — and therefore every request, the saved setting,
        // the review fingerprint and the run pin — names an address, not a name.
        if host == mappedHostName {
            components.host = mappedHostLiteral
        }
        if let port = components.port, !(1 ... 65_535).contains(port) {
            throw AssistantEndpointError.invalidPort(port)
        }
        // Normalize the base path: no trailing slash, bounded length.
        var path = components.path
        while path.hasSuffix("/") {
            path.removeLast()
        }
        guard path.count <= maxPathLength else {
            throw AssistantEndpointError.pathTooLong
        }
        components.path = path
        components.scheme = scheme

        guard let url = components.url else {
            throw AssistantEndpointError.notAURL
        }
        return AssistantLocalEndpoint(baseURL: url, displayText: url.absoluteString)
    }

    /// Whether an *arbitrary* URL — a redirect target, for example — is still on
    /// this Mac. Used by the redirect guard, where the candidate never came from
    /// the user.
    static func isLoopback(_ url: URL) -> Bool {
        canonicalLoopbackURL(url) != nil
    }

    /// The same URL with `localhost` rewritten to the numeric loopback literal,
    /// or `nil` when the URL is not on this Mac. A redirect that names
    /// `localhost` is followed only through the rewritten address, so no request
    /// ever depends on what a resolver says that name means.
    static func canonicalLoopbackURL(_ url: URL) -> URL? {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let scheme = components.scheme?.lowercased(),
              ["http", "https"].contains(scheme),
              components.user == nil,
              components.password == nil,
              let rawHost = components.host else
        {
            return nil
        }
        let host = normalizedHost(rawHost)
        guard loopbackLiterals.contains(host) else {
            return nil
        }
        if host == mappedHostName {
            components.host = mappedHostLiteral
        }
        return components.url
    }

    /// Append one API path to the validated base.
    func url(path: String) -> URL {
        baseURL.appendingPathComponent(path)
    }

    // MARK: Private

    /// Lowercase, and strip the brackets `URLComponents` keeps around an IPv6
    /// literal, so `[::1]` and `::1` are the same host.
    ///
    /// A zone identifier (`::1%lo0`) is deliberately *not* stripped. Stripping it
    /// would silently accept a host string the user did not write, and the
    /// allowed set is meant to be matched literally — so a zoned literal simply
    /// fails to match and is refused.
    private static func normalizedHost(_ host: String) -> String {
        var value = host.lowercased()
        if value.hasPrefix("["), value.hasSuffix("]") {
            value.removeFirst()
            value.removeLast()
        }
        return value
    }
}
