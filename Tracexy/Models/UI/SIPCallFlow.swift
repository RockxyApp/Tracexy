import Foundation

// MARK: - SIPCallFlow

/// Telephony ▸ VoIP Calls ▸ Flow Sequence: the frames of one call for the Flow Graph —
/// its SIP messages, and each RTP stream sent to a media address its SDP offered, drawn
/// once at its first packet with its payload and packet count, as Wireshark's call
/// flow draws a stream as one arrow.
nonisolated enum SIPCallFlow {
    // MARK: Internal

    static func rows(callID: String, in frames: [CaptureFrameRow]) -> [CaptureFrameRow] {
        let signalling = frames.filter { $0.sip?.message.callID == callID }
        let media = Set(signalling.compactMap { $0.sip?.media }.map(normalized))
        var streams: [String: (first: CaptureFrameRow, count: Int)] = [:]
        var order: [String] = []
        for row in frames {
            guard let rtp = row.rtp, media.contains(normalized(rtp.destination)) else {
                continue
            }
            let key = "\(rtp.source.display)>\(rtp.destination.display)#\(rtp.ssrc)"
            if let stream = streams[key] {
                streams[key] = (stream.first, stream.count + 1)
            } else {
                streams[key] = (row, 1)
                order.append(key)
            }
        }
        let arrows = order.compactMap { key -> CaptureFrameRow? in
            guard let (first, count) = streams[key], let rtp = first.rtp else {
                return nil
            }
            var row = CaptureFrameRow(
                provenance: first.provenance, source: first.source, destination: first.destination,
                protocolName: "RTP",
                info: count == 1
                    ? String(localized: "(\(RTPStreams.payloadName(rtp.payloadType))), 1 packet")
                    :
                    String(
                        localized: "(\(RTPStreams.payloadName(rtp.payloadType))), \(count.formatted()) packets"
                    ),
                sessionID: first.sessionID, interfaceID: first.interfaceID, hasComment: first.hasComment
            )
            row.rtp = rtp
            return row
        }
        return (signalling + arrows).sorted { $0.ordinal < $1.ordinal }
    }

    // MARK: Private

    private static func normalized(_ endpoint: IPEndpoint) -> IPEndpoint {
        IPEndpoint(ip: IPAddressValue(parsing: endpoint.ip)?.compressedText ?? endpoint.ip, port: endpoint.port)
    }
}
