//
//  SessionBuilderTests.swift
//  TracexyTests
//
//  End-to-end: real sample bytes → decode → real sessions. Asserts the UI is
//  fed genuinely-decoded data (host resolution, status, latency), not mocks.
//

import Foundation
import Testing
@testable import Tracexy

@Suite("SessionBuilder end-to-end")
struct SessionBuilderTests {
    // MARK: Internal

    @Test
    func producesRealSessions() {
        let result = sessions()
        #expect(result.count >= 6)
        #expect(result.allSatisfy { $0.totalBytes > 0 })
    }

    @Test
    func tlsSessionResolvesHostFromSNI() {
        guard let api = sessions().first(where: { $0.host == "api.example.com" && $0.protocolStack.contains(.tls) }) else {
            Issue.record("no TLS session for api.example.com")
            return
        }
        #expect(api.sni == "api.example.com")
        #expect(api.protocolStack.contains(.tls))
        #expect(!api.decodedLayers.isEmpty)
        // Layer tree carries the real Ethernet→IP→TCP→TLS decode.
        #expect(api.decodedLayers.contains { $0.title == "Transport Layer Security" })
    }

    @Test
    func resetConnectionIsError() {
        let auth = sessions().first { $0.host == "auth.example.com" }
        #expect(auth?.status == .error)
    }

    @Test
    func incompleteHandshakeIsWarning() {
        let syn = sessions().first { $0.host == "203.0.113.9" }
        #expect(syn?.status == .warning)
    }

    @Test
    func dnsSessionHasMeasuredLatency() {
        let dns = sessions().first { $0.protocolStack.contains(.dns) && $0.latencyMilliseconds != nil }
        #expect(dns != nil)
        #expect((dns?.latencyMilliseconds ?? 0) > 0)
    }

    @Test
    func quicSessionIsDecoded() {
        #expect(sessions().contains { $0.protocolStack.contains(.quic) })
    }

    @Test
    func httpSessionResolvesHostFromHeader() {
        #expect(sessions().contains { $0.host == "registry.npmjs.org" && $0.protocolStack.contains(.http) })
    }

    @Test
    func sessionIDsAreStableAcrossRebuilds() {
        // The same 5-tuple must keep the same id across rebuilds, so the table
        // selection survives when new packets arrive.
        let frames = SampleCapture.frames(now: Date())
        let first = SessionBuilder.build(from: frames, linkType: LinkType.ethernet)
        let second = SessionBuilder.build(from: frames, linkType: LinkType.ethernet)
        #expect(!first.isEmpty)
        #expect(first.map(\.id) == second.map(\.id))
    }

    // MARK: Private

    private func sessions() -> [SessionSummary] {
        SessionBuilder.build(from: SampleCapture.frames(now: Date()), linkType: LinkType.ethernet)
    }
}
