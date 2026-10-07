import Foundation

// MARK: - HTTP2ConnectionReader + Upgrade

/// HTTP/2 reached through an HTTP/1.1 upgrade (RFC 7540 §3.2, "h2c"): the client
/// sends an ordinary request with `Upgrade: h2c`, the server answers `101 Switching
/// Protocols`, and both sides continue in HTTP/2 — the client with its connection
/// preface, the server with its SETTINGS and the response to that first request on
/// stream 1.
extension HTTP2ConnectionReader {
    /// Headers that only negotiate the switch or manage the HTTP/1.1 connection;
    /// they are not part of the request the upgraded stream carries.
    static let upgradeOnlyHeaders: Set<String> = [
        "connection", "upgrade", "http2-settings", "keep-alive", "proxy-connection", "transfer-encoding", "te", "host",
    ]

    /// The most SETTINGS entries read from an `HTTP2-Settings` header.
    static let maximumUpgradeSettings = 64

    /// `nil` unless the connection opens with an HTTP/1.1 request answered by a 101
    /// that switches it to `h2c`, and what the client sends after that request is
    /// the connection preface (or nothing was retained yet).
    static func upgraded(aToB: [UInt8], bToA: [UInt8]) -> HTTP2Conversation? {
        guard let conversation = HTTPExchangeReader.read(aToB: aToB, bToA: bToA),
              let exchange = conversation.exchanges.last, exchange.status == 101,
              let requestLength = exchange.request.length,
              let response = exchange.response, let responseLength = response.length else
        {
            return nil
        }
        let client = conversation.clientIsAToB ? aToB : bToA
        let server = conversation.clientIsAToB ? bToA : aToB
        let responseHead = headLines(server, from: response.offset, to: response.bodyOffset)
        let switchesToH2C = responseHead.contains { name, value in
            name == "upgrade" && value.split(separator: ",").contains {
                $0.trimmingCharacters(in: .whitespaces).lowercased() == "h2c"
            }
        }
        guard switchesToH2C else {
            return nil
        }
        let clientStart = exchange.request.offset + requestLength
        let afterRequest = client.count - clientStart
        // The preface must follow the request; anything else is not HTTP/2.
        guard afterRequest >= 0,
              client[clientStart...].starts(with: preface.prefix(min(afterRequest, preface.count))) else
        {
            return nil
        }

        let requestHead = headLines(client, from: exchange.request.offset, to: exchange.request.bodyOffset)
        var headers = [
            HPACKHeader(name: ":method", value: exchange.method),
            HPACKHeader(name: ":path", value: exchange.target),
            HPACKHeader(name: ":scheme", value: "http"),
        ]
        if let host = exchange.host, !host.isEmpty {
            headers.append(HPACKHeader(name: ":authority", value: host))
        }
        headers += requestHead.filter { !upgradeOnlyHeaders.contains($0.name) }
            .map { HPACKHeader(name: $0.name, value: $0.value) }
        var firstStream = HTTP2Stream(id: 1)
        firstStream.requestHeaders = headers
        firstStream.requestOffset = exchange.request.offset
        firstStream.requestDataBytes = exchange.request.bodyLength ?? 0
        // The upgrade request is the whole of stream 1's request (RFC 7540 §3.2).
        firstStream.requestEnded = true

        var reading = read(
            client: client,
            server: server,
            clientIsAToB: conversation.clientIsAToB,
            clientStart: clientStart,
            serverStart: response.offset + responseLength,
            firstStream: firstStream
        )
        if reading.clientSettings.isEmpty,
           let encoded = requestHead.first(where: { $0.name == "http2-settings" })?.value
        {
            reading = reading.replacingClientSettings(upgradeSettings(encoded))
        }
        if afterRequest < preface.count, reading.clientStop == nil {
            reading = reading.replacingClientStop(.cutShort)
        }
        reading.upgrade = HTTP2Upgrade(
            requestOffset: exchange.request.offset,
            responseOffset: response.offset,
            clientStart: clientStart,
            serverStart: response.offset + responseLength
        )
        return reading
    }

    /// The SETTINGS payload an `HTTP2-Settings` header carries in base64url
    /// (RFC 7540 §3.2.1); empty when it does not decode to whole 6-byte entries.
    static func upgradeSettings(_ value: String) -> [HTTP2Setting] {
        var text = value.trimmingCharacters(in: .whitespaces)
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while text.count % 4 != 0 {
            text += "="
        }
        guard let data = Data(base64Encoded: text), data.count % 6 == 0 else {
            return []
        }
        let bytes = [UInt8](data)
        return stride(from: 0, to: min(bytes.count, maximumUpgradeSettings * 6), by: 6).map { offset in
            HTTP2Setting(
                identifier: UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1]),
                value: UInt32(bytes[offset + 2]) << 24 | UInt32(bytes[offset + 3]) << 16
                    | UInt32(bytes[offset + 4]) << 8 | UInt32(bytes[offset + 5])
            )
        }
    }

    /// The header lines of an HTTP/1 head in order, names lower-cased; the start
    /// line is skipped.
    private static func headLines(_ bytes: [UInt8], from start: Int, to end: Int) -> [(name: String, value: String)] {
        guard start < end, end <= bytes.count,
              let text = String(bytes: bytes[start ..< end], encoding: .isoLatin1) else
        {
            return []
        }
        return text.split(whereSeparator: \.isNewline).dropFirst().compactMap { line in
            guard let colon = line.firstIndex(of: ":") else {
                return nil
            }
            return (
                line[..<colon].trimmingCharacters(in: .whitespaces).lowercased(),
                line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            )
        }
    }
}

private extension HTTP2Conversation {
    func replacingClientSettings(_ settings: [HTTP2Setting]) -> HTTP2Conversation {
        HTTP2Conversation(
            clientIsAToB: clientIsAToB, frames: frames, streams: streams, clientSettings: settings,
            serverSettings: serverSettings, clientStop: clientStop, serverStop: serverStop, upgrade: upgrade
        )
    }

    func replacingClientStop(_ stop: Stop) -> HTTP2Conversation {
        HTTP2Conversation(
            clientIsAToB: clientIsAToB, frames: frames, streams: streams, clientSettings: clientSettings,
            serverSettings: serverSettings, clientStop: stop, serverStop: serverStop, upgrade: upgrade
        )
    }
}
