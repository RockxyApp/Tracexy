import Foundation
import Testing
@testable import Tracexy

// MARK: - Fixtures

private func makeSession(
    host: String = "api.example.com",
    process: String? = "Chrome",
    source: String = "192.168.1.10:52344",
    destination: String = "93.184.216.34:443",
    protocols: [ProtocolKind] = [.tcp, .tls],
    status: SessionStatus = .ok,
    dnsQuery: String? = nil,
    dnsAnswers: [String] = [],
    latencyMilliseconds: Double? = nil
)
    -> SessionSummary
{
    SessionSummary(
        id: UUID(),
        startTime: Date(timeIntervalSince1970: 0),
        duration: 0.1,
        processName: process,
        host: host,
        sourceEndpoint: source,
        destinationEndpoint: destination,
        protocolStack: protocols,
        status: status,
        latencyMilliseconds: latencyMilliseconds,
        bytesUp: 1,
        bytesDown: 1,
        sni: nil,
        dnsQuery: dnsQuery,
        dnsAnswers: dnsAnswers
    )
}

// MARK: - SessionSearchFieldTests

@Suite("Session search-field scoping")
struct SessionSearchFieldTests {
    @Test("The default scope is All Fields")
    func defaultScope() {
        #expect(WorkspaceState(title: "t").searchField == .allFields)
    }

    @Test("All Fields spans host, client, protocol, endpoints, summary and DNS answers")
    func allFieldsBreadth() {
        let session = makeSession(
            host: "cdn.example.net",
            process: "Chrome",
            source: "10.0.0.5:1000",
            destination: "1.1.1.1:443",
            protocols: [.udp, .quic],
            dnsQuery: "cdn.example.net",
            dnsAnswers: ["9.9.9.9"]
        )
        let hay = SessionSearchField.allFields.haystack(in: session)
        #expect(hay.contains("cdn.example.net")) // host
        #expect(hay.contains("chrome")) // client / process
        #expect(hay.contains("quic")) // protocol label
        #expect(hay.contains("10.0.0.5")) // source endpoint
        #expect(hay.contains("1.1.1.1")) // destination endpoint
        #expect(hay.contains("9.9.9.9")) // DNS answer
    }

    @Test("A scoped field matches only its own attribute")
    func scopedField() {
        let session = makeSession(host: "api.example.com", process: "Chrome")
        // "chrome" is the process, not the host.
        #expect(SessionSearchField.client.haystack(in: session).contains("chrome"))
        #expect(!SessionSearchField.host.haystack(in: session).contains("chrome"))
        #expect(SessionSearchField.host.haystack(in: session).contains("api.example.com"))
    }
}

// MARK: - WorkspaceSearchStateTests

@Suite("Search enable/disable state")
struct WorkspaceSearchStateTests {
    @Test("A disabled search retains its text but does not count as active")
    func disabledSearchIsInactive() {
        let ws = WorkspaceState(title: "t")
        ws.filterText = "example"
        ws.isSearchEnabled = true
        #expect(ws.isSearchActive)
        #expect(ws.hasActiveFilters)

        ws.isSearchEnabled = false
        #expect(ws.filterText == "example") // text is retained
        #expect(!ws.isSearchActive)
        #expect(!ws.hasActiveFilters)
    }

    @Test("An enabled but empty search is not active")
    func emptySearchIsInactive() {
        let ws = WorkspaceState(title: "t")
        ws.isSearchEnabled = true
        ws.filterText = "   "
        #expect(!ws.isSearchActive)
    }
}

// MARK: - SessionCategoryFilterTests

@Suite("Quick-category group semantics")
struct SessionCategoryFilterTests {
    @Test("Empty category set imposes no constraint")
    func emptyIsUnconstrained() {
        let session = makeSession(protocols: [.udp])
        #expect(MainContentCoordinator.categoryFilterMatches(session, categories: []))
    }

    @Test("Protocol chips are OR-ed within their group")
    func protocolOr() {
        let tcp = makeSession(protocols: [.tcp])
        let dns = makeSession(protocols: [.udp, .dns])
        let icmp = makeSession(protocols: [.icmp])
        let categories: Set<SessionFilterCategory> = [.tcp, .dns]
        #expect(MainContentCoordinator.categoryFilterMatches(tcp, categories: categories))
        #expect(MainContentCoordinator.categoryFilterMatches(dns, categories: categories))
        #expect(!MainContentCoordinator.categoryFilterMatches(icmp, categories: categories))
    }

    @Test("A protocol chip and Errors combine with AND")
    func protocolAndErrors() {
        let categories: Set<SessionFilterCategory> = [.tcp, .errors]
        let tcpError = makeSession(protocols: [.tcp], status: .error)
        let tcpOk = makeSession(protocols: [.tcp], status: .ok)
        let udpError = makeSession(protocols: [.udp], status: .error)
        #expect(MainContentCoordinator.categoryFilterMatches(tcpError, categories: categories))
        #expect(!MainContentCoordinator.categoryFilterMatches(
            tcpOk,
            categories: categories
        )) // investigation group fails
        #expect(!MainContentCoordinator.categoryFilterMatches(udpError, categories: categories)) // protocol group fails
    }

    @Test("Errors means exactly an error — a warning is excluded")
    func errorsExcludesWarning() {
        let categories: Set<SessionFilterCategory> = [.errors]
        #expect(MainContentCoordinator.categoryFilterMatches(makeSession(status: .error), categories: categories))
        #expect(!MainContentCoordinator.categoryFilterMatches(makeSession(status: .warning), categories: categories))
        #expect(!MainContentCoordinator.categoryFilterMatches(makeSession(status: .ok), categories: categories))
    }

    @Test("Findings matches only exact typed-finding session membership")
    func findingsUsesExactMembership() {
        let categories: Set<SessionFilterCategory> = [.security]
        let member = makeSession(status: .ok)
        let heuristicOnly = makeSession(
            protocols: [.tcp, .http],
            status: .error,
            dnsQuery: "missing.example",
            latencyMilliseconds: 401
        )
        let ids: Set<UUID> = [member.id]

        #expect(MainContentCoordinator.categoryFilterMatches(
            member,
            categories: categories,
            findingSessionIDs: ids
        ))
        #expect(!MainContentCoordinator.categoryFilterMatches(
            heuristicOnly,
            categories: categories,
            findingSessionIDs: ids
        ))
    }

    @MainActor
    @Test("Findings quick-filter routing preserves complementary filters")
    func findingsFilterUsesSessionWorkflow() {
        let coordinator = MainContentCoordinator()
        let workspace = coordinator.activeWorkspace
        workspace.sidebarSelection = .overview
        workspace.categoryFilters = [.tcp]
        workspace.hostFilter = "api.example.com"
        workspace.isFilterBarVisible = false

        coordinator.showFindingSessions()

        #expect(workspace.sidebarSelection == .sessions)
        #expect(workspace.categoryFilters == [.tcp, .security])
        #expect(workspace.hostFilter == nil)
        #expect(workspace.isFilterBarVisible)
    }
}
