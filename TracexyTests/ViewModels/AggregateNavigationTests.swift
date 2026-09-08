import Foundation
import Testing
@testable import Tracexy

/// The contract behind clicking a number on a summary surface: the sessions you
/// land on are exactly the sessions that number counted.
///
/// Every assertion here compares the aggregate the surface displayed with the
/// resulting session set — by id, not by count alone, because two sets of the
/// same size can still be the wrong ones. The fixtures deliberately include the
/// two ways a wider predicate would cheat: a session that merely *sent from* the
/// clicked address, and one that only resolved it in a DNS answer.
@MainActor
@Suite("Aggregate drill-in")
struct AggregateNavigationTests {
    // MARK: Internal

    // MARK: Overview host rollups

    @Test("A top-talker click narrows to that host and keeps every other constraint")
    func hostDrillInNarrowsWithinTheCurrentScope() throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let fixture = environment.fixture
        workspace.processFilter = "Safari"

        // The rollup the user is reading is computed over the Safari-only scope.
        let talker = try #require(coordinator.topHosts().first { $0.host == "api.example.com" })
        #expect(talker.bytes == fixture.apiTLSSafari.totalBytes + fixture.errorUDP.totalBytes)

        coordinator.showSessionsForAggregateHost("api.example.com")

        // Exactly the sessions the row counted — the Mail session under the same
        // host is still excluded, because the client filter was never cleared.
        #expect(visibleIDs(coordinator) == Set([fixture.apiTLSSafari.id, fixture.errorUDP.id]))
        #expect(bytes(coordinator) == talker.bytes)
        #expect(workspace.processFilter == "Safari")
        #expect(workspace.sidebarSelection == .sessions)
        #expect(workspace.sessionScopeReturnStack.count == 1)
    }

    @Test("One host with several clients keeps every one of them")
    func multipleProcessesUnderOneHostAllSurvive() throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let fixture = environment.fixture

        let talker = try #require(coordinator.topHosts().first { $0.host == "api.example.com" })
        coordinator.showSessionsForAggregateHost("api.example.com")

        #expect(visibleIDs(coordinator) == Set([
            fixture.apiTLSSafari.id, fixture.apiHTTP2Mail.id, fixture.errorUDP.id,
        ]))
        #expect(bytes(coordinator) == talker.bytes)
        // Two clients, not one collapsed row.
        #expect(Set(coordinator.visibleSessions.compactMap(\.processName)) == ["Safari", "Mail"])
    }

    @Test("Top-talker ties order deterministically instead of by dictionary order")
    func topHostTiesAreDeterministic() throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        coordinator.sessions = [
            session(host: "zulu.example", process: "Safari", ip: "198.51.100.1", port: 443, stack: [.tcp], bytes: 10),
            session(host: "alpha.example", process: "Safari", ip: "198.51.100.2", port: 443, stack: [.tcp], bytes: 10),
            session(host: "mike.example", process: "Safari", ip: "198.51.100.3", port: 443, stack: [.tcp], bytes: 10),
        ]

        let order = coordinator.topHosts().map(\.host)
        #expect(order == ["alpha.example", "mike.example", "zulu.example"])
        // Same input, same order — a rollup that reshuffles under the cursor is
        // a rollup no one can click.
        #expect(coordinator.topHosts().map(\.host) == order)
    }

    // MARK: Overview protocol rollups

    @Test("Protocol rows with no sidebar lens of their own drill in: UDP and HTTP/2")
    func protocolRowsWithoutASidebarLensDrillIn() throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let fixture = environment.fixture

        let udpCount = coordinator.count(for: .udp)
        coordinator.showSessionsForAggregateProtocol(.udp)
        #expect(workspace.aggregateProtocolFilters == [.udp])
        #expect(visibleIDs(coordinator) == Set([
            fixture.dnsUDP.id, fixture.answerDecoy.id, fixture.errorUDP.id,
        ]))
        #expect(coordinator.visibleSessions.count == udpCount)

        coordinator.resetSessionFilters()
        let http2Count = coordinator.count(for: .http2)
        coordinator.showSessionsForAggregateProtocol(.http2)
        #expect(visibleIDs(coordinator) == Set([fixture.apiHTTP2Mail.id]))
        #expect(coordinator.visibleSessions.count == http2Count)
    }

    @Test("A second protocol intersects with the first rather than replacing it")
    func protocolAggregatesIntersect() throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let fixture = environment.fixture

        coordinator.showSessionsForAggregateProtocol(.tcp)
        coordinator.showSessionsForAggregateProtocol(.tls)

        #expect(workspace.aggregateProtocolFilters == [.tcp, .tls])
        // Conjunctive: the plain-TCP decoy is gone, and nothing was widened back
        // in by the second click.
        #expect(visibleIDs(coordinator) == Set([
            fixture.apiTLSSafari.id, fixture.apiHTTP2Mail.id, fixture.cdnTLSSafari.id,
        ]))
        #expect(workspace.sessionScopeReturnStack.count == 2)
    }

    @Test("An aggregate protocol never rewrites the OR-ed category group")
    func protocolAggregateKeepsCategoryChips() throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let fixture = environment.fixture
        // DNS *or* HTTP/2 — writing an aggregate into this group would have
        // added every UDP session to the list instead of removing rows from it.
        workspace.categoryFilters = [.dns, .http2]
        #expect(visibleIDs(coordinator) == Set([
            fixture.dnsUDP.id, fixture.answerDecoy.id, fixture.apiHTTP2Mail.id,
        ]))

        coordinator.showSessionsForAggregateProtocol(.udp)

        #expect(workspace.categoryFilters == [.dns, .http2])
        #expect(visibleIDs(coordinator) == Set([fixture.dnsUDP.id, fixture.answerDecoy.id]))
    }

    // MARK: Flow destination rows

    @Test("A Flow address row opens exactly its own sessions, not the sidebar IP scope")
    func destinationDrillInIsDestinationOnly() throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let fixture = environment.fixture
        let expected = Set([fixture.apiTLSSafari.id, fixture.apiHTTP2Mail.id, fixture.errorUDP.id])

        let row = try #require(coordinator.flowEndpoints.first { $0.address == "93.184.16.34" })
        #expect(row.sessionCount == expected.count)

        coordinator.showSessionsForAggregateDestination("93.184.16.34")

        // The source-only and DNS-answer-only decoys are not in the row, so they
        // are not in the list the row opened.
        #expect(visibleIDs(coordinator) == expected)
        #expect(bytes(coordinator) == row.bytes)
        #expect(!visibleIDs(coordinator).contains(fixture.sourceDecoy.id))
        #expect(!visibleIDs(coordinator).contains(fixture.answerDecoy.id))

        // The sidebar's IP route is deliberately wider, and still is.
        coordinator.resetSessionFilters()
        coordinator.selectIP("93.184.16.34")
        #expect(visibleIDs(coordinator) == expected
            .union([fixture.sourceDecoy.id, fixture.answerDecoy.id]))
    }

    @Test("Equivalent IPv6 spellings are one row and one drill-in")
    func equivalentIPv6SpellingsAreOneAggregate() throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let short = session(
            host: "v6.example.com", process: "Safari",
            ip: "2001:db8::1", port: 443, stack: [.tcp, .tls], bytes: 11
        )
        let long = session(
            host: "v6.example.com", process: "Mail",
            ip: "2001:0db8:0000:0000:0000:0000:0000:0001", port: 443, stack: [.tcp], bytes: 13
        )
        coordinator.sessions = [short, long]

        let row = try #require(coordinator.flowEndpoints.first)
        #expect(row.sessionCount == 2)

        coordinator.showSessionsForAggregateDestination(row.address)

        #expect(visibleIDs(coordinator) == Set([short.id, long.id]))
        #expect(bytes(coordinator) == row.bytes)
        let depth = coordinator.activeWorkspace.sessionScopeReturnStack.count
        coordinator.showSessionsForAggregateDestination("2001:db8::1")
        #expect(coordinator.activeWorkspace.sessionScopeReturnStack.count == depth)
        #expect(visibleIDs(coordinator) == Set([short.id, long.id]))
    }

    @Test("A session with no typed destination is omitted from the rows and never matched")
    func sessionsWithoutATypedDestinationAreOmitted() throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        var untyped = session(
            host: "api.example.com", process: "Safari",
            ip: "93.184.16.34", port: 443, stack: [.tcp], bytes: 9
        )
        // The rendered endpoint still reads "93.184.16.34:443"; it is not parsed
        // back into a row, so the row cannot claim a session it cannot match.
        untyped.destinationEndpointValue = nil
        let typed = session(
            host: "api.example.com", process: "Safari",
            ip: "93.184.16.34", port: 443, stack: [.tcp], bytes: 4
        )
        coordinator.sessions = [untyped, typed]

        let row = try #require(coordinator.flowEndpoints.first { $0.address == "93.184.16.34" })
        #expect(row.sessionCount == 1)
        #expect(FlowEndpoint.omittedSessionCount(in: coordinator.visibleSessions) == 1)
        #expect(coordinator.regionTraffic.reduce(0) { $0 + $1.sessions } == 1)
        #expect(coordinator.regionTraffic.reduce(0) { $0 + $1.bytes } == typed.totalBytes)

        coordinator.showSessionsForAggregateDestination("93.184.16.34")
        #expect(visibleIDs(coordinator) == Set([typed.id]))
    }

    // MARK: No-ops

    @Test("A repeated or stale drill-in narrows nothing and records nothing")
    func repeatedAndStaleDrillInsAreNoOps() throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace

        coordinator.showSessionsForAggregateHost("api.example.com")
        let afterFirst = visibleIDs(coordinator)
        #expect(workspace.sessionScopeReturnStack.count == 1)

        // Same scope again: nothing changed, so nothing is recorded.
        coordinator.showSessionsForAggregateHost("api.example.com")
        #expect(workspace.sessionScopeReturnStack.count == 1)
        #expect(visibleIDs(coordinator) == afterFirst)

        // A stale row under an existing host scope must not swap the scope out.
        coordinator.showSessionsForAggregateHost("cdn.fastly.net")
        #expect(workspace.hostFilter == "api.example.com")
        #expect(workspace.sessionScopeReturnStack.count == 1)
        #expect(visibleIDs(coordinator) == afterFirst)

        coordinator.showSessionsForAggregateDestination("93.184.16.34")
        let afterDestination = visibleIDs(coordinator)
        #expect(workspace.sessionScopeReturnStack.count == 2)
        coordinator.showSessionsForAggregateDestination("93.184.16.34")
        coordinator.showSessionsForAggregateDestination("104.18.32.7")
        #expect(workspace.aggregateDestinationFilter == "93.184.16.34")
        #expect(workspace.sessionScopeReturnStack.count == 2)
        #expect(visibleIDs(coordinator) == afterDestination)
    }

    // MARK: Complementary layers

    @Test("A sidebar protocol lens is carried into the intersection, never dropped")
    func sidebarLensIsCarriedIntoTheAggregate() throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let fixture = environment.fixture
        workspace.sidebarSelection = .tls
        let underLens = visibleIDs(coordinator)

        coordinator.showSessionsForAggregateHost("api.example.com")

        // Moving to Sessions would otherwise have dropped the lens and shown the
        // host's UDP session too — more rows than the aggregate counted.
        #expect(workspace.sidebarSelection == .sessions)
        #expect(workspace.aggregateProtocolFilters == [.tls])
        #expect(visibleIDs(coordinator) == underLens.intersection([
            fixture.apiTLSSafari.id, fixture.apiHTTP2Mail.id, fixture.errorUDP.id,
        ]))
        #expect(!visibleIDs(coordinator).contains(fixture.errorUDP.id))

        #expect(coordinator.returnToPreviousSessionScope())
        #expect(workspace.sidebarSelection == .tls)
        #expect(workspace.aggregateProtocolFilters.isEmpty)
        #expect(visibleIDs(coordinator) == underLens)
    }

    @Test("An Investigation query and an investigation category both survive a drill-in")
    func queryAndCategoryIntersectionsSurvive() throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let fixture = environment.fixture
        let draft = InvestigationQueryDraft()
        workspace.acceptedInvestigationDraft = draft
        workspace.investigationMatchedSessionIDs = [
            fixture.apiTLSSafari.id, fixture.apiHTTP2Mail.id, fixture.cdnTLSSafari.id,
        ]
        workspace.categoryFilters = [.tls]

        coordinator.showSessionsForAggregateProtocol(.http2)

        #expect(visibleIDs(coordinator) == Set([fixture.apiHTTP2Mail.id]))
        #expect(workspace.acceptedInvestigationDraft == draft)
        #expect(workspace.investigationMatchedSessionIDs.count == 3)
        #expect(workspace.categoryFilters == [.tls])

        // The errors chip is an independent AND-ed group and stays one.
        coordinator.resetSessionFilters()
        workspace.categoryFilters = [.errors]
        coordinator.showSessionsForAggregateHost("api.example.com")
        #expect(visibleIDs(coordinator) == Set([fixture.errorUDP.id]))
        #expect(workspace.categoryFilters == [.errors])
    }

    @Test("Noise Control and rows removed from view keep constraining a drill-in")
    func noiseAndRemovalDecisionsAreNotBypassed() throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let fixture = environment.fixture
        coordinator.removeSessionsFromView([fixture.apiHTTP2Mail.id])
        coordinator.toggleMuteProtocol(.udp)

        coordinator.showSessionsForAggregateHost("api.example.com")

        #expect(visibleIDs(coordinator) == Set([fixture.apiTLSSafari.id]))
        #expect(coordinator.removedSessionIDs == [fixture.apiHTTP2Mail.id])
        #expect(coordinator.mutedProtocols == [.udp])
    }

    // MARK: Return, reset, replacement, isolation

    @Test("Back unwinds the aggregate scope and Reset clears both fields")
    func backAndResetBothCoverTheAggregateScope() throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        let everything = visibleIDs(coordinator)

        coordinator.showSessionsForAggregateProtocol(.tls)
        coordinator.showSessionsForAggregateDestination("93.184.16.34")
        #expect(workspace.sessionScopeReturnStack.count == 2)

        #expect(coordinator.returnToPreviousSessionScope())
        #expect(workspace.aggregateDestinationFilter == nil)
        #expect(workspace.aggregateProtocolFilters == [.tls])

        #expect(coordinator.returnToPreviousSessionScope())
        #expect(workspace.aggregateProtocolFilters.isEmpty)
        #expect(visibleIDs(coordinator) == everything)

        coordinator.showSessionsForAggregateProtocol(.tls)
        coordinator.showSessionsForAggregateDestination("93.184.16.34")
        #expect(workspace.hasActiveFilters)
        coordinator.resetSessionFilters()
        #expect(workspace.aggregateProtocolFilters.isEmpty)
        #expect(workspace.aggregateDestinationFilter == nil)
        #expect(!workspace.hasActiveFilters)
        #expect(visibleIDs(coordinator) == everything)
    }

    @Test("Ordinary global navigation keeps replacement semantics and clears the aggregate scope")
    func globalNavigationClearsTheAggregateScope() throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace

        let routes: [() -> Void] = [
            { coordinator.selectHost("cdn.fastly.net") },
            { coordinator.selectProcess("Safari") },
            { coordinator.selectIP("104.18.32.7") },
            { coordinator.selectSidebarItem(.overview) },
            { coordinator.applyFocusSet(FocusSet(name: "Review", rules: [])) },
        ]
        for navigate in routes {
            workspace.aggregateProtocolFilters = [.tls]
            workspace.aggregateDestinationFilter = "93.184.16.34"
            workspace.aggregateRequiresFindings = true
            navigate()
            #expect(!workspace.aggregateRequiresFindings)
            #expect(workspace.aggregateProtocolFilters.isEmpty)
            #expect(workspace.aggregateDestinationFilter == nil)
        }
    }

    @Test("Open Sessions moves surfaces without widening or recording anything")
    func openSessionsPreservesTheDescribedScope() throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        workspace.sidebarSelection = .overview
        workspace.hostFilter = "api.example.com"
        workspace.aggregateProtocolFilters = [.tls]
        let described = visibleIDs(coordinator)

        coordinator.openFlowPreservingScope()
        #expect(workspace.sidebarSelection == .flow)
        #expect(visibleIDs(coordinator) == described)
        coordinator.openSessionsPreservingScope()

        #expect(workspace.sidebarSelection == .sessions)
        #expect(workspace.hostFilter == "api.example.com")
        #expect(workspace.aggregateProtocolFilters == [.tls])
        #expect(visibleIDs(coordinator) == described)
        // Opening a list narrows nothing, so there is nothing to go back from.
        #expect(workspace.sessionScopeReturnStack.isEmpty)

        // From a protocol lens it keeps the same sessions by carrying the lens.
        coordinator.resetSessionFilters()
        workspace.sidebarSelection = .tls
        let underLens = visibleIDs(coordinator)
        coordinator.openSessionsPreservingScope()
        #expect(workspace.aggregateProtocolFilters == [.tls])
        #expect(visibleIDs(coordinator) == underLens)
    }

    @Test("The aggregate scope is workspace-local and its return dies with the source")
    func scopeIsWorkspaceLocalAndGenerationGuarded() throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let first = coordinator.activeWorkspace
        let second = try coordinator.workspaces.addWorkspace(title: "Second")

        coordinator.showSessionsForAggregateDestination("93.184.16.34")
        #expect(second.aggregateDestinationFilter == "93.184.16.34")
        #expect(first.aggregateDestinationFilter == nil)
        #expect(first.sessionScopeReturnStack.isEmpty)

        // A new capture, source or Project retires the way back without
        // resurrecting the scope it described.
        coordinator.startGeneration &+= 1
        #expect(!coordinator.canReturnToPreviousSessionScope)
        #expect(!coordinator.returnToPreviousSessionScope())
        #expect(second.aggregateDestinationFilter == "93.184.16.34")
        #expect(second.sessionScopeReturnStack.isEmpty)
    }

    @Test("Both aggregate layers are named in the shared scope notice")
    func scopeSummaryNamesBothAggregateLayers() throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        let workspace = coordinator.activeWorkspace
        workspace.aggregateProtocolFilters = [.tls, .http2]
        workspace.aggregateDestinationFilter = "93.184.16.34"

        let summary = coordinator.sessionScope()

        #expect(summary.descriptors.map(\.kind) == [.protocolIntersection, .destination])
        #expect(summary.hasClearableFilters)
        // Fixed enum order, never set-iteration order.
        #expect(summary.descriptors.first { $0.kind == .protocolIntersection }?.fullLabel
            == "Sessions that also carry TLS + HTTP/2")
        #expect(summary.descriptors.first { $0.kind == .destination }?.fullLabel
            == "Destination: 93.184.16.34")
    }

    @Test("Hiding a binary-equivalent destination releases its aggregate scope")
    func hidingScopedDestinationClearsIt() throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        coordinator.showSessionsForAggregateDestination("2001:db8::1")
        coordinator.hideSourceIP("2001:0db8:0:0:0:0:0:1")
        #expect(coordinator.activeWorkspace.aggregateDestinationFilter == nil)
        #expect(coordinator.hiddenSourceIPs.contains("2001:0db8:0:0:0:0:0:1"))
    }

    @Test("Overview source counts use visible facts and deduplicate binary addresses")
    func sourceCountsRespectScopeAndAddressIdentity() throws {
        let environment = try makeEnvironment()
        defer { environment.teardown() }
        let coordinator = environment.coordinator
        coordinator.sessions = [
            session(host: "one.test", process: "Safari", ip: "2001:db8::1", port: 80, stack: [.tcp], bytes: 10),
            session(host: "one.test", process: "Mail", ip: "2001:0db8:0:0:0:0:0:1", port: 81, stack: [.tcp], bytes: 10),
            session(host: "two.test", process: "Other", ip: "198.51.100.2", port: 80, stack: [.tcp], bytes: 10),
        ]
        coordinator.activeWorkspace.hostFilter = "one.test"
        let counts = coordinator.visibleSourceSummary
        #expect(counts.apps == 2)
        #expect(counts.domains == 1)
        #expect(counts.addresses == 2) // One shared source and one binary IPv6 destination.
    }

    // MARK: Private

    /// The fixture session set, held by name so an assertion can say which
    /// session it expects rather than only how many.
    private struct Fixture {
        let apiTLSSafari: SessionSummary
        let apiHTTP2Mail: SessionSummary
        let cdnTLSSafari: SessionSummary
        let dnsUDP: SessionSummary
        let sourceDecoy: SessionSummary
        let answerDecoy: SessionSummary
        let errorUDP: SessionSummary

        var all: [SessionSummary] {
            [apiTLSSafari, apiHTTP2Mail, cdnTLSSafari, dnsUDP, sourceDecoy, answerDecoy, errorUDP]
        }
    }

    private struct Environment {
        let coordinator: MainContentCoordinator
        let fixture: Fixture
        let teardown: () -> Void
    }

    private func visibleIDs(_ coordinator: MainContentCoordinator) -> Set<UUID> {
        Set(coordinator.visibleSessions.map(\.id))
    }

    private func bytes(_ coordinator: MainContentCoordinator) -> Int {
        coordinator.visibleSessions.reduce(0) { $0 + $1.totalBytes }
    }

    private func makeEnvironment(function: String = #function) throws -> Environment {
        let isolation = ProjectIsolationEnvironment(name: "aggregate-\(function)")
        let coordinator = isolation.makeCoordinator()
        let fixture = makeFixture()
        coordinator.sessions = fixture.all
        return Environment(coordinator: coordinator, fixture: fixture) {
            isolation.tearDown()
        }
    }

    private func makeFixture() -> Fixture {
        Fixture(
            apiTLSSafari: session(
                host: "api.example.com", process: "Safari",
                ip: "93.184.16.34", port: 443, stack: [.tcp, .tls], bytes: 100
            ),
            apiHTTP2Mail: session(
                host: "api.example.com", process: "Mail",
                ip: "93.184.16.34", port: 443, stack: [.tcp, .tls, .http2], bytes: 40
            ),
            cdnTLSSafari: session(
                host: "cdn.fastly.net", process: "Safari",
                ip: "104.18.32.7", port: 443, stack: [.tcp, .tls], bytes: 30
            ),
            dnsUDP: session(
                host: "resolver.example", process: "mDNSResponder",
                ip: "1.1.1.1", port: 53, stack: [.udp, .dns], bytes: 10
            ),
            // Talks *from* the clicked address: only a source-or-destination
            // predicate would pull this into a destination aggregate.
            sourceDecoy: session(
                host: "decoy-source.example", process: "Safari",
                ip: "198.51.100.7", port: 443, stack: [.tcp], bytes: 5,
                sourceIP: "93.184.16.34", sourcePort: 5_000
            ),
            // Only *resolved* the clicked address.
            answerDecoy: session(
                host: "decoy-answer.example", process: "Safari",
                ip: "203.0.113.5", port: 53, stack: [.udp, .dns], bytes: 5,
                dnsAnswers: ["93.184.16.34"]
            ),
            errorUDP: session(
                host: "api.example.com", process: "Safari",
                ip: "93.184.16.34", port: 8_443, stack: [.udp], bytes: 7, status: .error
            )
        )
    }

    private func session(
        host: String,
        process: String,
        ip: String,
        port: UInt16,
        stack: [ProtocolKind],
        bytes: Int,
        status: SessionStatus = .ok,
        sourceIP: String = "192.168.1.2",
        sourcePort: UInt16 = 52_000,
        dnsAnswers: [String] = []
    )
        -> SessionSummary
    {
        SessionSummary(
            id: UUID(),
            startTime: Date(timeIntervalSince1970: 0),
            duration: 0.1,
            processName: process,
            host: host,
            sourceEndpoint: "\(sourceIP):\(sourcePort)",
            destinationEndpoint: "\(ip):\(port)",
            sourceEndpointValue: IPEndpoint(ip: sourceIP, port: sourcePort),
            destinationEndpointValue: IPEndpoint(ip: ip, port: port),
            protocolStack: stack,
            status: status,
            latencyMilliseconds: 10,
            bytesUp: bytes,
            bytesDown: 0,
            dnsAnswers: dnsAnswers
        )
    }
}
