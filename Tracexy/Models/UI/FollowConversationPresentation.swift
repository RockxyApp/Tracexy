import Foundation
import SwiftUI

// MARK: - FollowTranscriptSearch

/// Case- and diacritic-insensitive find inside a rendered follow transcript. It
/// searches the text exactly as drawn, so a match is always something the reader
/// can see, and it is bounded so a one-letter query over 64 KiB stays cheap.
nonisolated enum FollowTranscriptSearch {
    static let maximumMatches = 2_000

    /// The ranges of `query` in `text`, in order, at most ``maximumMatches``.
    static func matches(of query: String, in text: String) -> [Range<String.Index>] {
        let needle = query.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !needle.isEmpty, !text.isEmpty else {
            return []
        }
        var ranges: [Range<String.Index>] = []
        var searchStart = text.startIndex
        while ranges.count < maximumMatches,
              let found = text.range(
                  of: needle,
                  options: [.caseInsensitive, .diacriticInsensitive],
                  range: searchStart ..< text.endIndex
              )
        {
            ranges.append(found)
            searchStart = found.upperBound
        }
        return ranges
    }

    /// `text` with every match marked for display. Without a query the text is
    /// returned unchanged.
    static func highlighted(_ text: String, query: String) -> AttributedString {
        let ranges = matches(of: query, in: text)
        guard !ranges.isEmpty else {
            return AttributedString(text)
        }
        var result = AttributedString()
        var cursor = text.startIndex
        for range in ranges {
            result += AttributedString(String(text[cursor ..< range.lowerBound]))
            var match = AttributedString(String(text[range]))
            match.backgroundColor = Color.yellow.opacity(0.45)
            match.foregroundColor = Color.primary
            result += match
            cursor = range.upperBound
        }
        result += AttributedString(String(text[cursor...]))
        return result
    }
}

// MARK: - FollowDatagramRowPresentation

/// One datagram as the UDP transcript draws it. Plain values only; the view lays
/// them out and owns no wording of its own.
nonisolated struct FollowDatagramRowPresentation: Identifiable, Equatable, Sendable {
    let id: Int
    let provenance: SessionFrameProvenance
    /// Sender and receiver by endpoint, never a role guess.
    let route: String
    let frameLabel: String
    /// Offset from the first datagram, or "Untimed".
    let timeLabel: String
    let sizeLabel: String
    /// DNS reading headline ("Query A www.example.test", "Response NXDOMAIN").
    let dnsHeadline: String?
    /// Answer records, one per line, with a closing count of any omitted.
    let dnsAnswers: [String]
    /// Pairing with its query or response, stated once.
    let pairing: String?
    /// Formatted payload, bounded; empty when nothing is shown for this mode.
    let payload: String
    /// Captured payload bytes this row does not draw.
    let hiddenByteCount: Int
}

// MARK: - FollowDatagramPresentation

/// The UDP transcript: rows in capture order under one display bound, with the
/// DNS reading taking the place of undecodable bytes in text mode.
nonisolated struct FollowDatagramPresentation: Equatable, Sendable {
    // MARK: Lifecycle

    init(
        result: FollowDatagramResult,
        mode: FollowStreamDisplayMode,
        maxDisplayBytes: Int = maximumDisplayBytes
    ) {
        var remaining = min(max(0, maxDisplayBytes), Self.maximumDisplayBytes)
        let firstTime = result.messages.first?.provenance.timestamp
        var rows: [FollowDatagramRowPresentation] = []
        rows.reserveCapacity(result.messages.count)
        var hidden = 0
        for (index, message) in result.messages.enumerated() {
            let showsPayload = message.dns == nil || mode == .hex
            let shown = showsPayload ? min(message.payload.count, remaining, Self.maximumBytesPerRow) : 0
            remaining -= shown
            let rowHidden = message.capturedPayloadLength - shown
            if showsPayload {
                hidden += max(0, message.payload.count - shown)
            }
            rows.append(FollowDatagramRowPresentation(
                id: index,
                provenance: message.provenance,
                route: Self.route(message.direction, tuple: result.tuple),
                frameLabel: "Frame \(message.provenance.ordinal.rawValue.formatted())",
                timeLabel: Self.timeLabel(message.provenance.timestamp, since: firstTime),
                sizeLabel: Self.sizeLabel(message),
                dnsHeadline: message.dns.map(Self.dnsHeadline),
                dnsAnswers: message.dns.map(Self.dnsAnswers) ?? [],
                pairing: Self.pairing(message, index: index, in: result.messages),
                payload: shown > 0 ? FollowStreamDirectionPresentation.format(
                    Array(message.payload.prefix(shown)), mode: mode
                ) : "",
                hiddenByteCount: showsPayload ? max(0, rowHidden) : 0
            ))
        }
        self.rows = rows
        viewOmittedByteCount = hidden
    }

    // MARK: Internal

    static let maximumDisplayBytes = 64 << 10
    static let maximumBytesPerRow = 4 << 10

    let rows: [FollowDatagramRowPresentation]
    /// Retained payload bytes the transcript does not draw (display bound only).
    let viewOmittedByteCount: Int

    static func responseCodeName(_ code: UInt8) -> String {
        switch code {
        case 0: "NOERROR"
        case 1: "FORMERR"
        case 2: "SERVFAIL"
        case 3: "NXDOMAIN"
        case 4: "NOTIMP"
        case 5: "REFUSED"
        default: "RCODE \(code)"
        }
    }

    // MARK: Private

    private static func route(_ direction: ConnectionDirection, tuple: FiveTuple) -> String {
        switch direction {
        case .aToB: "\(tuple.a.display) → \(tuple.b.display)"
        case .bToA: "\(tuple.b.display) → \(tuple.a.display)"
        }
    }

    private static func timeLabel(_ time: Date?, since first: Date?) -> String {
        guard let time, let first else {
            return "Untimed"
        }
        return String(format: "+%.3f s", time.timeIntervalSince(first))
    }

    private static func sizeLabel(_ message: FollowDatagramMessage) -> String {
        if message.isCaptureTruncated, let declared = message.declaredPayloadLength {
            return "\(message.capturedPayloadLength.formatted()) of \(declared.formatted()) bytes captured"
        }
        return message.capturedPayloadLength == 1
            ? "1 byte"
            : "\(message.capturedPayloadLength.formatted()) bytes"
    }

    private static func dnsHeadline(_ dns: FollowDNSMessage) -> String {
        let question = [
            dns.questionType.map(PacketDecoder.dnsTypeName),
            dns.questionName.isEmpty ? nil : dns.questionName,
        ].compactMap(\.self).joined(separator: " ")
        guard dns.isResponse else {
            return question.isEmpty ? "Query" : "Query \(question)"
        }
        var headline = "Response \(responseCodeName(dns.responseCode))"
        if dns.isTruncated {
            headline += ", truncated"
        }
        return question.isEmpty ? headline : "\(headline) for \(question)"
    }

    private static func dnsAnswers(_ dns: FollowDNSMessage) -> [String] {
        guard dns.isResponse else {
            return []
        }
        var lines = dns.answerRecords
        if dns.omittedAnswerCount > 0 {
            lines.append("\(dns.omittedAnswerCount.formatted()) more answers not listed")
        }
        return lines
    }

    private static func pairing(
        _ message: FollowDatagramMessage,
        index: Int,
        in messages: [FollowDatagramMessage]
    )
        -> String?
    {
        guard let dns = message.dns else {
            return nil
        }
        guard let partnerIndex = dns.pairedMessageIndex, messages.indices.contains(partnerIndex) else {
            return dns.isResponse ? "No matching query was retained" : "No response was observed"
        }
        let partner = messages[partnerIndex]
        let frame = partner.provenance.ordinal.rawValue.formatted()
        guard dns.isResponse else {
            return "Answered in frame \(frame)"
        }
        if let answered = message.provenance.timestamp, let asked = partner.provenance.timestamp {
            let milliseconds = answered.timeIntervalSince(asked) * 1_000
            return String(format: "Answers frame %@ after %.1f ms", frame, milliseconds)
        }
        return "Answers frame \(frame)"
    }
}

// MARK: - FollowDatagramLimitations presentation

extension FollowDatagramLimitations {
    nonisolated var presentationLabels: [String] {
        var labels: [String] = []
        if contains(.capturedPayloadTruncated) {
            labels.append("Some datagrams were captured shorter than sent")
        }
        if contains(.messageBytesBounded) {
            labels.append("Large datagrams are shown as a prefix")
        }
        if contains(.messageRetentionTruncated) {
            labels.append("Only the first datagrams are listed")
        }
        if contains(.sourceTailTruncated) {
            labels.append("Capture source has a truncated tail")
        }
        return labels
    }
}

// MARK: - TLSCertificateExtraction presentation

extension TLSCertificateExtraction {
    /// One sentence for an outcome that listed no certificate, or `nil` when it did.
    nonisolated var absenceExplanation: String? {
        switch self {
        case .notTLS: "This direction does not begin with a TLS record."
        case .noPayload: "No bytes were retained in this direction."
        case .incomplete: "The capture holds too little of the handshake to read its certificates."
        case .encryptedBeforeCertificate:
            "Certificates were not sent in the clear. TLS 1.3 and resumed sessions encrypt them."
        case let .certificates(list, unparsed, _):
            list.isEmpty
                ? (unparsed > 0
                    ? "A Certificate message was sent, but its contents could not be read."
                    : "The Certificate message was empty.")
                : nil
        }
    }
}
