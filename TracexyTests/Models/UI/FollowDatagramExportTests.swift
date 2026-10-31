import Foundation
import Testing
@testable import Tracexy

struct FollowDatagramExportTests {
    // MARK: Internal

    @Test
    func yamlPreservesDatagramBoundariesDirectionOrderAndBase64Bytes() throws {
        let result = Self.result(messages: [
            Self.message(
                ordinal: 1,
                direction: .aToB,
                payload: [0, 0xFF, 0x0A],
                timestamp: Date(timeIntervalSince1970: 10)
            ),
            Self.message(ordinal: 2, direction: .aToB, payload: [0x41], timestamp: nil),
            Self.message(ordinal: 3, direction: .bToA, payload: [], timestamp: Date(timeIntervalSince1970: 12)),
        ])

        let both = try #require(String(data: FollowDatagramExport.yaml(result, side: .both), encoding: .utf8))
        #expect(both.contains("  - packet: 1\n    peer: 0\n    index: 0\n    timestamp: 10.000000000"))
        #expect(both.contains("  - packet: 2\n    peer: 0\n    index: 1\n    captured_payload_length: 1"))
        #expect(both.contains("    data: !!binary \"\""))
        #expect(both.contains("  - packet: 3\n    peer: 1\n    index: 0\n    timestamp: 12.000000000"))
        #expect(both.contains(Data([0, 0xFF, 0x0A]).base64EncodedString()))
        #expect(!both.contains("locator"))
        #expect(!both.contains("identity"))
        #expect(!both.contains("source_path"))

        let oneSide = try #require(String(data: FollowDatagramExport.yaml(result, side: .aToB), encoding: .utf8))
        #expect(oneSide.contains("packet: 1"))
        #expect(oneSide.contains("packet: 2"))
        #expect(!oneSide.contains("packet: 3"))
        #expect(oneSide.contains("omitted_datagrams: 4"))
        #expect(oneSide.contains("omitted_captured_payload_bytes: 23"))

        let oneWay = Self.result(messages: [Self.message(ordinal: 1, direction: .aToB, payload: [0x41])])
        #expect(throws: FollowDatagramExport.ExportError.emptySelection) {
            try FollowDatagramExport.yaml(oneWay, side: .bToA)
        }
    }

    @Test
    func yamlReportsCaptureTruncationAndEnforcesExpansionBounds() throws {
        let message = Self.message(
            ordinal: 7,
            direction: .aToB,
            payload: [0x41, 0x42],
            timestamp: nil,
            capturedLength: 4,
            declaredLength: 8
        )
        let result = Self.result(messages: [message], limitations: [.capturedPayloadTruncated, .messageBytesBounded])
        let text = try #require(String(data: FollowDatagramExport.yaml(result, side: .both), encoding: .utf8))
        #expect(text.contains("captured_payload_length: 4"))
        #expect(text.contains("declared_payload_length: 8"))
        #expect(text.contains("retained_payload_length: 2"))
        #expect(text.contains("bound_omitted_payload_bytes: 2"))
        #expect(text.contains("source_completeness: complete"))
        #expect(text.contains("- captured_payload_truncated"))
        #expect(text.contains("- message_bytes_bounded"))
        #expect(!text.contains("timestamp:"))

        let oversized = Self.result(messages: [
            Self.message(ordinal: 1, direction: .aToB, payload: Array(repeating: 0x7F, count: 4_200_000))
        ])
        #expect(throws: FollowDatagramExport.ExportError.tooLarge) {
            try FollowDatagramExport.yaml(oversized, side: .both)
        }
    }

    @Test
    func rawConcatenatesSelectedPayloadsInCaptureOrder() throws {
        let result = Self.result(messages: [
            Self.message(ordinal: 1, direction: .aToB, payload: [0x00, 0xFF]),
            Self.message(ordinal: 2, direction: .bToA, payload: [0x42]),
            Self.message(ordinal: 3, direction: .aToB, payload: [0x41, 0x0A]),
        ], omittedMessageCount: 0, omittedPayloadByteCount: 0)
        #expect(try FollowDatagramExport.raw(result, side: .both) == Data([0x00, 0xFF, 0x42, 0x41, 0x0A]))
        #expect(try FollowDatagramExport.raw(result, side: .aToB) == Data([0x00, 0xFF, 0x41, 0x0A]))
        #expect(try FollowDatagramExport.raw(result, side: .bToA) == Data([0x42]))
        let emptySide = Self.result(
            messages: [Self.message(ordinal: 1, direction: .aToB, payload: [])],
            omittedMessageCount: 0, omittedPayloadByteCount: 0
        )
        #expect(try FollowDatagramExport.raw(emptySide, side: .aToB).isEmpty)
        #expect(throws: FollowDatagramExport.ExportError.emptySelection) {
            try FollowDatagramExport.raw(emptySide, side: .bToA)
        }
    }

    @Test
    func rawRejectsIncompleteSourcesAndUnknownDirectionOmissions() {
        let message = Self.message(ordinal: 1, direction: .aToB, payload: [1])
        let incomplete = [
            Self.result(
                messages: [message],
                omittedMessageCount: 0,
                omittedPayloadByteCount: 0,
                completeness: .incompleteTruncatedTail(.partialBody)
            ),
            Self.result(
                messages: [message],
                limitations: [.sourceTailTruncated],
                omittedMessageCount: 0,
                omittedPayloadByteCount: 0
            ),
            Self.result(
                messages: [message],
                limitations: [.messageBytesBounded],
                omittedMessageCount: 0,
                omittedPayloadByteCount: 0
            ),
            Self.result(
                messages: [message],
                limitations: [.capturedPayloadTruncated],
                omittedMessageCount: 0,
                omittedPayloadByteCount: 0
            ),
            Self.result(
                messages: [message],
                limitations: [.messageRetentionTruncated],
                omittedMessageCount: 0,
                omittedPayloadByteCount: 0
            ),
            Self.result(messages: [message], omittedMessageCount: 1, omittedPayloadByteCount: 0),
            Self.result(messages: [message], omittedMessageCount: 0, omittedPayloadByteCount: 1),
        ]
        for result in incomplete {
            #expect(throws: FollowDatagramExport.ExportError.incomplete) {
                try FollowDatagramExport.raw(result, side: .aToB)
            }
        }
    }

    @Test
    func rawRejectsMissingOrTruncatedPayloadAndEnforcesSizeLimit() throws {
        let messages = [
            Self.message(ordinal: 1, direction: .aToB, payload: [1], capturedLength: 2, declaredLength: 2),
            Self.message(ordinal: 1, direction: .aToB, payload: [1], capturedLength: 1, declaredLength: 2),
            Self.message(ordinal: 1, direction: .aToB, payload: [1], omitDeclaredLength: true),
        ]
        for message in messages {
            let result = Self.result(messages: [message], omittedMessageCount: 0, omittedPayloadByteCount: 0)
            #expect(throws: FollowDatagramExport.ExportError.incomplete) {
                try FollowDatagramExport.raw(result, side: .both)
            }
        }
        let limit = FollowDatagramExport.maximumExportBytes
        let oversized = Self.result(messages: [
            Self.message(ordinal: 1, direction: .aToB, payload: Array(repeating: 0x7F, count: limit)),
            Self.message(ordinal: 2, direction: .bToA, payload: [0]),
        ], omittedMessageCount: 0, omittedPayloadByteCount: 0)
        #expect(try FollowDatagramExport.raw(oversized, side: .aToB).count == limit)
        #expect(throws: FollowDatagramExport.ExportError.tooLarge) {
            try FollowDatagramExport.raw(oversized, side: .both)
        }
    }

    // MARK: Private

    private static func result(
        messages: [FollowDatagramMessage],
        limitations: FollowDatagramLimitations = [],
        omittedMessageCount: Int = 4,
        omittedPayloadByteCount: UInt64 = 23,
        completeness: FollowStreamCompleteness = .complete
    )
        -> FollowDatagramResult
    {
        let tuple = FiveTuple(
            proto: .udp,
            source: IPEndpoint(ip: "192.0.2.10", port: 53_000),
            destination: IPEndpoint(ip: "198.51.100.20", port: 53)
        )
        return FollowDatagramResult(
            identity: PcapFileIdentity(size: 100, modifiedAt: nil, device: 1, inode: 2),
            format: .pcap,
            tuple: tuple,
            messages: messages,
            omittedMessageCount: omittedMessageCount,
            omittedPayloadByteCount: omittedPayloadByteCount,
            matchedFrameCount: messages.count + omittedMessageCount,
            scannedFrameCount: messages.count + 2,
            limitations: limitations,
            completeness: completeness,
            finalProgress: PcapStreamProgress(bytesConsumed: 100, totalBytes: 100)
        )
    }

    private static func message(
        ordinal: UInt64,
        direction: ConnectionDirection,
        payload: [UInt8],
        timestamp: Date? = Date(timeIntervalSince1970: 1),
        capturedLength: Int? = nil,
        declaredLength: Int? = nil,
        omitDeclaredLength: Bool = false
    )
        -> FollowDatagramMessage
    {
        FollowDatagramMessage(
            direction: direction,
            provenance: SessionFrameProvenance(
                ordinal: FrameOrdinal(ordinal),
                timestamp: timestamp,
                capturedLength: capturedLength ?? payload.count,
                originalLength: declaredLength ?? capturedLength ?? payload.count,
                linkType: 1
            ),
            payload: payload,
            capturedPayloadLength: capturedLength ?? payload.count,
            declaredPayloadLength: omitDeclaredLength ? nil : (declaredLength ?? payload.count),
            dns: nil
        )
    }
}
