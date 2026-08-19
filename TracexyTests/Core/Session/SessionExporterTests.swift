import Foundation
import Testing
@testable import Tracexy

@Suite("Session export")
struct SessionExporterTests {
    // MARK: Internal

    @Test("Frame matching never widens beyond the selected five tuple")
    func filtersSelectedSessionFrames() throws {
        let frames = SampleCapture.frames(now: Date(timeIntervalSince1970: 1_700_000_000))
        let sessions = SessionBuilder.build(from: frames, linkType: LinkType.ethernet)
        let session = try #require(sessions.first { $0.host == "auth.example.com" })

        let selected = SessionExporter.frames(
            matching: session.id,
            in: frames,
            defaultLinkType: LinkType.ethernet
        )

        #expect(selected.count == 2)
        let rebuilt = SessionBuilder.build(from: selected, linkType: LinkType.ethernet)
        #expect(rebuilt.map(\.id) == [session.id])
    }

    @Test("Classic pcap artifact round-trips only the selected session")
    func pcapRoundTrip() throws {
        let fixture = try makeFixture()
        let artifact = try SessionExporter.artifact(
            for: fixture.session,
            frames: fixture.frames,
            defaultLinkType: LinkType.ethernet,
            format: .pcap
        )

        let parsed = try PcapReader.read([UInt8](artifact.data))
        #expect(parsed.frames.count == fixture.frames.count)
        #expect(artifact.suggestedFileName.hasSuffix(".pcap"))
        #expect(SessionBuilder.build(from: parsed.frames, linkType: parsed.linkType).map(\.id) == [fixture.session.id])
    }

    @Test("Pcapng artifact round-trips timestamps and per-frame link type")
    func pcapngRoundTrip() throws {
        let fixture = try makeFixture()
        let artifact = try SessionExporter.artifact(
            for: fixture.session,
            frames: fixture.frames,
            defaultLinkType: LinkType.ethernet,
            format: .pcapng
        )

        let parsed = try PcapngReader.read([UInt8](artifact.data))
        #expect(parsed.frames.count == fixture.frames.count)
        #expect(parsed.frames.allSatisfy { $0.linkType == LinkType.ethernet })
        #expect(zip(parsed.frames, fixture.frames).allSatisfy { lhs, rhs in
            abs(lhs.timestamp.timeIntervalSince(rhs.timestamp)) < 0.00001
        })
        #expect(artifact.suggestedFileName.hasSuffix(".pcapng"))
    }

    @Test("Classic pcap rejects mixed link types")
    func pcapRejectsMixedLinkTypes() throws {
        let fixture = try makeFixture()
        let mixedFrames = framesWithMixedLinkTypes(fixture.frames)

        #expect(throws: SessionExportError.self) {
            try SessionExporter.artifact(
                for: fixture.session,
                frames: mixedFrames,
                defaultLinkType: LinkType.ethernet,
                format: .pcap
            )
        }
    }

    @Test("Pcapng preserves mixed link types through separate interfaces")
    func pcapngPreservesMixedLinkTypes() throws {
        let fixture = try makeFixture()
        let mixedFrames = framesWithMixedLinkTypes(fixture.frames)
        let artifact = try SessionExporter.artifact(
            for: fixture.session,
            frames: mixedFrames,
            defaultLinkType: LinkType.ethernet,
            format: .pcapng
        )

        let parsed = try PcapngReader.read([UInt8](artifact.data))
        #expect(parsed.frames.map(\.linkType) == [LinkType.ethernet, LinkType.raw])
    }

    @Test("Native session artifact is versioned JSON with the selected frames")
    func nativeSessionDocument() throws {
        let fixture = try makeFixture()
        let artifact = try SessionExporter.artifact(
            for: fixture.session,
            frames: fixture.frames,
            defaultLinkType: LinkType.ethernet,
            format: .session
        )

        let object = try #require(JSONSerialization.jsonObject(with: artifact.data) as? [String: Any])
        let summary = try #require(object["session"] as? [String: Any])
        let frames = try #require(object["frames"] as? [[String: Any]])
        #expect(object["formatVersion"] as? Int == 1)
        #expect(summary["id"] as? String == fixture.session.id.uuidString)
        #expect(frames.count == fixture.frames.count)
        #expect(artifact.suggestedFileName.hasSuffix(".tracexysession"))
    }

    @Test("Protected session document drops frame bytes entirely with no sentinel payload")
    func protectedDocumentOmitsFrameBytes() throws {
        let fixture = try makeFixture()
        let artifact = try SessionExporter.artifact(
            for: fixture.session,
            frames: fixture.frames,
            defaultLinkType: LinkType.ethernet,
            format: .session,
            privacy: SessionExportPrivacyPolicy(redactPayloadBodies: true)
        )

        let object = try #require(JSONSerialization.jsonObject(with: artifact.data) as? [String: Any])
        #expect(object["formatVersion"] as? Int == 2)
        let frames = try #require(object["frames"] as? [[String: Any]])
        #expect(frames.count == fixture.frames.count)
        // No frame carries a `bytes` key and none substitutes a sentinel payload.
        #expect(frames.allSatisfy { $0["bytes"] == nil })
        #expect(frames.allSatisfy { $0["payload"] == nil })
        // Timing/length/link/process metadata survives.
        #expect(frames.allSatisfy { $0["timestamp"] != nil })
        #expect(frames.allSatisfy { $0["originalLength"] != nil })
        #expect(frames.allSatisfy { $0["linkType"] != nil })
    }

    @Test("Protected document declares machine-readable privacy metadata and version 2")
    func protectedDocumentPrivacyMetadata() throws {
        let fixture = try makeFixture()
        let artifact = try SessionExporter.artifact(
            for: fixture.session,
            frames: fixture.frames,
            defaultLinkType: LinkType.ethernet,
            format: .session,
            privacy: SessionExportPrivacyPolicy(redactPayloadBodies: true, stripCredentials: true)
        )

        let object = try #require(JSONSerialization.jsonObject(with: artifact.data) as? [String: Any])
        #expect(object["formatVersion"] as? Int == 2)
        let privacy = try #require(object["privacy"] as? [String: Any])
        #expect(privacy["redactedPayloadBodies"] as? Bool == true)
        #expect(privacy["strippedCredentials"] as? Bool == true)
        #expect(privacy["maskedIPAddresses"] as? Bool == false)
        #expect(privacy["includesRawFrameBytes"] as? Bool == false)
    }

    @Test("Unprotected document stays backward-compatible version 1 with bytes present")
    func unprotectedDocumentBackwardCompatible() throws {
        let fixture = try makeFixture()
        let artifact = try SessionExporter.artifact(
            for: fixture.session,
            frames: fixture.frames,
            defaultLinkType: LinkType.ethernet,
            format: .session,
            privacy: .none
        )

        let object = try #require(JSONSerialization.jsonObject(with: artifact.data) as? [String: Any])
        #expect(object["formatVersion"] as? Int == 1)
        #expect(object["privacy"] == nil)
        let frames = try #require(object["frames"] as? [[String: Any]])
        #expect(frames.allSatisfy { $0["bytes"] != nil })
    }

    @Test("Stripping credentials removes DNS and free-form summary metadata")
    func stripCredentialsRemovesDecodedMetadata() throws {
        let session = makeRichSession(
            host: "internal.corp.example",
            sourceEndpoint: "192.168.1.42:54001",
            destinationEndpoint: "203.0.113.53:53",
            protocolStack: [.udp, .dns],
            sni: nil,
            dnsQuery: "vault.secret.corp",
            dnsAnswers: ["198.51.100.77"]
        )
        let fixture = try makeFixture()
        let artifact = try SessionExporter.artifact(
            for: session,
            frames: fixture.frames,
            defaultLinkType: LinkType.ethernet,
            format: .session,
            privacy: SessionExportPrivacyPolicy(stripCredentials: true)
        )

        let object = try #require(JSONSerialization.jsonObject(with: artifact.data) as? [String: Any])
        let summary = try #require(object["session"] as? [String: Any])
        #expect(summary["dnsQuery"] == nil)
        #expect((summary["dnsAnswers"] as? [Any])?.isEmpty == true)
        // The free-form info line collapses to protocol labels only — no invented data.
        #expect(summary["summary"] as? String == "UDP · DNS")

        // The credential-bearing strings must be structurally absent from the artifact.
        let text = try #require(String(bytes: artifact.data, encoding: .utf8))
        #expect(!text.contains("vault.secret.corp"))
        #expect(!text.contains("198.51.100.77"))
    }

    @Test("Masking rewrites IPv4 literals but preserves hostnames and ports")
    func maskingRewritesIPv4() throws {
        let session = makeRichSession(
            host: "93.184.16.34",
            sourceEndpoint: "192.168.1.42:52344",
            destinationEndpoint: "93.184.16.34:443",
            protocolStack: [.tcp, .tls],
            sni: "api.example.com",
            dnsQuery: "api.example.com",
            dnsAnswers: ["93.184.16.34"]
        )
        let fixture = try makeFixture()
        let artifact = try SessionExporter.artifact(
            for: session,
            frames: fixture.frames,
            defaultLinkType: LinkType.ethernet,
            format: .session,
            privacy: SessionExportPrivacyPolicy(maskIPAddresses: true)
        )

        let object = try #require(JSONSerialization.jsonObject(with: artifact.data) as? [String: Any])
        // Masking addresses also removes raw bytes, so this is a protected document.
        #expect(object["formatVersion"] as? Int == 2)
        let summary = try #require(object["session"] as? [String: Any])
        #expect(summary["host"] as? String == "[masked-ip]")
        #expect(summary["sourceEndpoint"] as? String == "[masked-ip]:52344")
        #expect(summary["destinationEndpoint"] as? String == "[masked-ip]:443")
        // Hostnames must never be corrupted by the masker.
        #expect(summary["sni"] as? String == "api.example.com")
        #expect(summary["dnsQuery"] as? String == "api.example.com")
        #expect((summary["dnsAnswers"] as? [String]) == ["[masked-ip]"])
        #expect(summary["summary"] as? String == "DNS api.example.com → [masked-ip]")

        let text = try #require(String(bytes: artifact.data, encoding: .utf8))
        #expect(!text.contains("93.184.16.34"))
        #expect(!text.contains("192.168.1.42"))
    }

    @Test("Masking catches an address immediately followed by sentence punctuation")
    func maskingRewritesAddressBeforePeriod() throws {
        let session = makeRichSession(
            host: "api.example.com",
            sourceEndpoint: "192.168.1.42:52344",
            destinationEndpoint: "93.184.16.34:443",
            protocolStack: [.tcp, .http],
            sni: nil,
            dnsQuery: nil,
            dnsAnswers: []
        )
        let fixture = try makeFixture()
        var punctuated = session
        punctuated.decodedLayers = [
            DecodedLayer(proto: .http, title: "HTTP", summary: "Connected to 93.184.16.34."),
        ]

        let artifact = try SessionExporter.artifact(
            for: punctuated,
            frames: fixture.frames,
            defaultLinkType: LinkType.ethernet,
            format: .session,
            privacy: SessionExportPrivacyPolicy(maskIPAddresses: true)
        )

        let object = try #require(JSONSerialization.jsonObject(with: artifact.data) as? [String: Any])
        let summary = try #require(object["session"] as? [String: Any])
        #expect(summary["summary"] as? String == "Connected to [masked-ip].")
    }

    @Test("Masking rewrites IPv6 literals while preserving endpoint ports")
    func maskingRewritesIPv6() throws {
        let session = makeRichSession(
            host: "2606:4700:4700::1111",
            sourceEndpoint: "192.168.1.42:52344",
            destinationEndpoint: "2606:4700:4700::1111:443",
            protocolStack: [.tcp, .tls],
            sni: "api.example.com",
            dnsQuery: nil,
            dnsAnswers: ["2606:4700:4700::64"]
        )
        let fixture = try makeFixture()
        let artifact = try SessionExporter.artifact(
            for: session,
            frames: fixture.frames,
            defaultLinkType: LinkType.ethernet,
            format: .session,
            privacy: SessionExportPrivacyPolicy(maskIPAddresses: true)
        )

        let object = try #require(JSONSerialization.jsonObject(with: artifact.data) as? [String: Any])
        let summary = try #require(object["session"] as? [String: Any])
        #expect(summary["host"] as? String == "[masked-ip]")
        #expect(summary["destinationEndpoint"] as? String == "[masked-ip]:443")
        #expect((summary["dnsAnswers"] as? [String]) == ["[masked-ip]"])

        let text = try #require(String(bytes: artifact.data, encoding: .utf8))
        #expect(!text.contains("2606:4700:4700::1111"))
        #expect(!text.contains("2606:4700:4700::64"))
    }

    @Test("Raw pcap and pcapng refuse any active privacy protection")
    func rawFormatsRefuseActiveProtection() throws {
        let fixture = try makeFixture()
        let policy = SessionExportPrivacyPolicy(redactPayloadBodies: true)

        for format in [SessionExportFormat.pcap, .pcapng] {
            do {
                _ = try SessionExporter.artifact(
                    for: fixture.session,
                    frames: fixture.frames,
                    defaultLinkType: LinkType.ethernet,
                    format: format,
                    privacy: policy
                )
                Issue.record("Expected raw export refusal for \(format)")
            } catch let error as SessionExportError {
                guard case .rawExportRequiresAcknowledgement = error else {
                    Issue.record("Unexpected error \(error) for \(format)")
                    continue
                }
            }
        }
    }

    // MARK: Private

    private func makeRichSession(
        host: String,
        sourceEndpoint: String,
        destinationEndpoint: String,
        protocolStack: [ProtocolKind],
        sni: String?,
        dnsQuery: String?,
        dnsAnswers: [String]
    )
        -> SessionSummary
    {
        SessionSummary(
            id: UUID(),
            startTime: Date(timeIntervalSince1970: 1_700_000_000),
            duration: 1.5,
            processName: "curl",
            host: host,
            sourceEndpoint: sourceEndpoint,
            destinationEndpoint: destinationEndpoint,
            protocolStack: protocolStack,
            status: .ok,
            latencyMilliseconds: 12.0,
            bytesUp: 128,
            bytesDown: 512,
            sni: sni,
            dnsQuery: dnsQuery,
            dnsAnswers: dnsAnswers
        )
    }

    private func makeFixture() throws -> (session: SessionSummary, frames: [CapturedFrame]) {
        let allFrames = SampleCapture.frames(now: Date(timeIntervalSince1970: 1_700_000_000))
        let sessions = SessionBuilder.build(from: allFrames, linkType: LinkType.ethernet)
        let session = try #require(sessions.first { $0.host == "auth.example.com" })
        let frames = SessionExporter.frames(
            matching: session.id,
            in: allFrames,
            defaultLinkType: LinkType.ethernet
        )
        return (session, frames)
    }

    private func framesWithMixedLinkTypes(_ frames: [CapturedFrame]) -> [CapturedFrame] {
        frames.enumerated().map { index, frame in
            CapturedFrame(
                bytes: frame.bytes,
                timestamp: frame.timestamp,
                originalLength: frame.originalLength,
                capturedLength: frame.capturedLength,
                linkType: index == 0 ? LinkType.ethernet : LinkType.raw,
                processName: frame.processName
            )
        }
    }
}
