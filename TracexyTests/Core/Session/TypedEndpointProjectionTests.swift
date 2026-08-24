import Foundation
import Testing
@testable import Tracexy

// MARK: - TypedEndpointProjectionTests

/// The common accumulator publishes the exact earliest-packet client/server
/// ``IPEndpoint`` values it uses to render the display strings and decide direction —
/// never by re-parsing the rendered copy. These tests fold ``DecodedPacket`` values
/// directly through ``SessionAccumulator`` and pin the projection against the strings.
struct TypedEndpointProjectionTests {
    // MARK: Internal

    // MARK: Canonical tuple: forward vs reverse first packet

    @Test
    func forwardFirstPacketProjectsItsSourceAsClient() throws {
        let client = IPEndpoint(ip: "192.0.2.10", port: 50_000)
        let server = IPEndpoint(ip: "198.51.100.20", port: 443)
        var accumulator = SessionAccumulator()
        accumulator.add(packet(source: client, destination: server, at: 1))
        accumulator.add(packet(source: server, destination: client, at: 2))

        let summary = try #require(accumulator.summaries().first)
        #expect(summary.sourceEndpointValue == client)
        #expect(summary.destinationEndpointValue == server)
        #expect(summary.sourceEndpoint == client.display)
        #expect(summary.destinationEndpoint == server.display)
    }

    @Test
    func reverseFirstPacketProjectsTheOtherEndAsClient() throws {
        let a = IPEndpoint(ip: "192.0.2.10", port: 50_000)
        let b = IPEndpoint(ip: "198.51.100.20", port: 443)
        // Same canonical five-tuple as the forward case, but the earliest packet flows
        // b→a, so the client projection must be b — not the canonical tuple's `a`.
        var accumulator = SessionAccumulator()
        accumulator.add(packet(source: b, destination: a, at: 1))
        accumulator.add(packet(source: a, destination: b, at: 2))

        let summary = try #require(accumulator.summaries().first)
        #expect(summary.sourceEndpointValue == b)
        #expect(summary.destinationEndpointValue == a)
        // One conversation, regardless of first-packet direction.
        #expect(accumulator.summaries().count == 1)
    }

    // MARK: Earliest-timestamp selection & equal-timestamp tie-break

    @Test
    func earlierTimestampArrivingLaterBecomesTheClient() throws {
        let first = IPEndpoint(ip: "192.0.2.10", port: 50_000)
        let server = IPEndpoint(ip: "198.51.100.20", port: 443)
        let earlier = IPEndpoint(ip: "198.51.100.20", port: 443)
        var accumulator = SessionAccumulator()
        // Fold the later timestamp first, then a strictly-earlier one from the server
        // side: the earliest packet (server→client at t=1) now sets the direction.
        accumulator.add(packet(source: first, destination: server, at: 5))
        accumulator.add(packet(source: earlier, destination: first, at: 1))

        let summary = try #require(accumulator.summaries().first)
        #expect(summary.sourceEndpointValue == earlier)
        #expect(summary.destinationEndpointValue == first)
    }

    @Test
    func equalTimestampKeepsFirstSeenClient() throws {
        let client = IPEndpoint(ip: "192.0.2.10", port: 50_000)
        let server = IPEndpoint(ip: "198.51.100.20", port: 443)
        var accumulator = SessionAccumulator()
        // Both packets share t=1; first-seen wins as earliest, so client stays the
        // first packet's source even though the reverse packet has an equal timestamp.
        accumulator.add(packet(source: client, destination: server, at: 1))
        accumulator.add(packet(source: server, destination: client, at: 1))

        let summary = try #require(accumulator.summaries().first)
        #expect(summary.sourceEndpointValue == client)
        #expect(summary.destinationEndpointValue == server)
    }

    // MARK: Missing endpoints project nil, not a fabricated string

    @Test
    func missingEndpointsProjectNilAndDashStrings() throws {
        // A five-tuple with no per-packet endpoints (artificial) must project nil typed
        // values and the "—" display placeholder, never an invented address.
        var packet = DecodedPacket(timestamp: Date(timeIntervalSince1970: 1), originalLength: 64)
        packet.transport = .tcp
        packet.fiveTuple = FiveTuple(
            proto: .tcp,
            source: IPEndpoint(ip: "192.0.2.1", port: 1),
            destination: IPEndpoint(ip: "192.0.2.2", port: 2)
        )
        var accumulator = SessionAccumulator()
        accumulator.add(packet)

        let summary = try #require(accumulator.summaries().first)
        #expect(summary.sourceEndpointValue == nil)
        #expect(summary.destinationEndpointValue == nil)
        #expect(summary.sourceEndpoint == "—")
        #expect(summary.destinationEndpoint == "—")
    }

    // MARK: Projected values feed the binary IP substrate

    @Test
    func projectedClientIPParsesThroughTheBinaryValue() throws {
        let client = IPEndpoint(ip: "192.0.2.10", port: 50_000)
        let server = IPEndpoint(ip: "2001:db8::20", port: 443)
        var accumulator = SessionAccumulator()
        accumulator.add(packet(source: client, destination: server, at: 1))

        let summary = try #require(accumulator.summaries().first)
        // The typed projection carries the canonical standalone IP text, so the query
        // substrate parses it without ever touching the rendered "ip:port" string.
        let sourceIP = try #require(summary.sourceEndpointValue.flatMap { IPAddressValue(parsing: $0.ip) })
        #expect(sourceIP.family == .v4)
        let destinationIP = try #require(summary.destinationEndpointValue.flatMap { IPAddressValue(parsing: $0.ip) })
        #expect(destinationIP.family == .v6)
    }

    // MARK: Private

    /// A minimal decoded packet carrying just the fields the session fold reads for the
    /// endpoint projection: timestamp, source/destination endpoints and the five-tuple.
    private func packet(
        source: IPEndpoint,
        destination: IPEndpoint,
        at seconds: TimeInterval,
        length: Int = 100
    )
        -> DecodedPacket
    {
        var packet = DecodedPacket(timestamp: Date(timeIntervalSince1970: seconds), originalLength: length)
        packet.transport = .tcp
        packet.sourceEndpoint = source
        packet.destinationEndpoint = destination
        packet.fiveTuple = FiveTuple(proto: .tcp, source: source, destination: destination)
        return packet
    }
}
