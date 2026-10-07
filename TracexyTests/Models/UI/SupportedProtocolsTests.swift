import Foundation
import Testing
@testable import Tracexy

/// Help ▸ Supported Protocols lists every protocol Tracexy recognizes, once, with the
/// Session Expression keywords that find it.
@MainActor
struct SupportedProtocolsTests {
    @Test
    func listsEveryRecognizedProtocolOnce() {
        let rows = SupportedProtocols.rows
        #expect(Set(rows.map(\.kind)) == Set(ProtocolKind.allCases).subtracting([.other]))
        #expect(rows.count == ProtocolKind.allCases.count - 1)
        #expect(rows.first { $0.kind == .smb }?.keywords == ["smb", "smb2"])
        #expect(rows.first { $0.kind == .pop3 }?.keywords == ["pop"])
        // Outer framing has no keyword, by the grammar's design.
        #expect(rows.first { $0.kind == .ethernet }?.keywords.isEmpty == true)
        for row in rows {
            for keyword in row.keywords {
                #expect(SessionQueryParser.protocolKeywords[keyword] == row.kind)
            }
        }
    }

    @Test
    func countsSessionsOncePerProtocol() {
        func session(_ stack: [ProtocolKind]) -> SessionSummary {
            SessionSummary(
                id: UUID(), startTime: nil, duration: nil, processName: nil, host: "a.test",
                sourceEndpoint: "192.0.2.1:1", destinationEndpoint: "192.0.2.2:2", protocolStack: stack,
                status: .ok, latencyMilliseconds: nil, bytesUp: 0, bytesDown: 0
            )
        }
        let counts = SupportedProtocolsWindow.sessionCounts([
            session([.tcp, .tls, .http2]), session([.tcp, .tls]), session([.udp, .dns, .dns]),
        ])
        #expect(counts[.tcp] == 2)
        #expect(counts[.tls] == 2)
        #expect(counts[.http2] == 1)
        #expect(counts[.dns] == 1)
        #expect(counts[.quic] == nil)
    }
}
