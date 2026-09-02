import Foundation
import Testing
@testable import Tracexy

// MARK: - CitedFrameReferenceTests

/// Constructing an exact cited-frame `CaptureEvidenceReference` from a provenance
/// must validate the locator's source token against the adopted file identity
/// first, and the reused ``CaptureEvidenceReader`` identity/length checks must still
/// catch a replaced or truncated file. A wrong token or an absent locator is a
/// controlled failure that constructs no reference and reads nothing.
struct CitedFrameReferenceTests {
    // MARK: Internal

    @Test("A current-identity token builds an exact reference that reads the cited bytes")
    func currentTokenReadsExactBytes() throws {
        let syn = PacketBuilder.tcpSynFrame(src: "198.51.100.5", dst: "203.0.113.9", srcPort: 44_000, dstPort: 443)
        try Self.withSavedCapture([syn]) { url, result in
            let identity = result.identity
            let provenance = try #require(result.connections.summaries.first?.firstProvenance)
            // The locator was minted from the adopted file identity at load.
            #expect(provenance.locator?.sourceToken == SavedCaptureStreamLoader.sourceToken(for: identity))

            let reference = try SavedCaptureStreamLoader.citedEvidenceReference(
                for: provenance, matching: identity
            )
            let bytes = try CaptureEvidenceReader.read(reference, from: url)
            #expect(bytes == syn)
            #expect(bytes.count == provenance.capturedLength)
        }
    }

    @Test("A wrong source token throws mismatch and constructs no reference")
    func wrongTokenThrowsMismatch() throws {
        let syn = PacketBuilder.tcpSynFrame(src: "198.51.100.6", dst: "203.0.113.10", srcPort: 44_100, dstPort: 443)
        try Self.withSavedCapture([syn]) { _, result in
            let provenance = try #require(result.connections.summaries.first?.firstProvenance)
            let forged = SessionFrameProvenance(
                ordinal: provenance.ordinal,
                timestamp: provenance.timestamp,
                capturedLength: provenance.capturedLength,
                originalLength: provenance.originalLength,
                linkType: provenance.linkType,
                locator: SessionEvidenceLocator(sourceToken: UUID(), offset: provenance.locator?.offset ?? 0)
            )
            #expect(throws: CitedFrameReferenceError.sourceTokenMismatch) {
                _ = try SavedCaptureStreamLoader.citedEvidenceReference(for: forged, matching: result.identity)
            }
        }
    }

    @Test("A nil locator throws the explicit missing-locator failure")
    func missingLocatorThrows() throws {
        let syn = PacketBuilder.tcpSynFrame(src: "198.51.100.7", dst: "203.0.113.11", srcPort: 44_200, dstPort: 443)
        try Self.withSavedCapture([syn]) { _, result in
            let provenance = try #require(result.connections.summaries.first?.firstProvenance)
            let noLocator = SessionFrameProvenance(
                ordinal: provenance.ordinal,
                timestamp: provenance.timestamp,
                capturedLength: provenance.capturedLength,
                originalLength: provenance.originalLength,
                linkType: provenance.linkType,
                locator: nil
            )
            #expect(throws: CitedFrameReferenceError.missingLocator) {
                _ = try SavedCaptureStreamLoader.citedEvidenceReference(for: noLocator, matching: result.identity)
            }
        }
    }

    @Test("A replaced file fails the reused identity check even with a valid reference")
    func replacedFileFailsIdentityCheck() throws {
        let syn = PacketBuilder.tcpSynFrame(src: "198.51.100.8", dst: "203.0.113.12", srcPort: 44_300, dstPort: 443)
        try Self.withSavedCapture([syn]) { url, result in
            let provenance = try #require(result.connections.summaries.first?.firstProvenance)
            let reference = try SavedCaptureStreamLoader.citedEvidenceReference(
                for: provenance, matching: result.identity
            )
            // Replace the file with different content/size: the identity/length checks
            // in the reused reader reject the stale offset rather than return bad bytes.
            let other = PacketBuilder.tcpSynFrame(
                src: "198.51.100.8", dst: "203.0.113.13", srcPort: 44_301, dstPort: 8_080
            )
            try PcapWriter.write(linkType: LinkType.ethernet, frames: [
                Self.frame(other), Self.frame(other),
            ], to: url)
            #expect(throws: PacketError.self) {
                _ = try CaptureEvidenceReader.read(reference, from: url)
            }
        }
    }

    // MARK: Private

    private static func frame(_ bytes: [UInt8]) -> CapturedFrame {
        CapturedFrame(bytes: bytes, timestamp: Date(timeIntervalSince1970: 1_700_000_000), originalLength: bytes.count)
    }

    private static func withSavedCapture(
        _ frames: [[UInt8]],
        _ body: (URL, SavedCaptureLoadResult) throws -> Void
    )
        throws
    {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("cited-frame-\(UUID().uuidString).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames.map(frame), to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let result = try SavedCaptureStreamLoader(contentsOf: url).load()
        try body(url, result)
    }
}
