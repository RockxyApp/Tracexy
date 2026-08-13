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
            abs(lhs.timestamp.timeIntervalSince(rhs.timestamp)) < 0.000_01
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

    // MARK: Private

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
