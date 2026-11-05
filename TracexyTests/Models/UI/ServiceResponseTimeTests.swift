import Foundation
import Testing
@testable import Tracexy

/// Statistics ▸ Service Response Time prints what `tshark -z smb2,srt`, `ldap,srt`
/// and `kerberos,srt` print: an SMB2 session whose Session Setup needs two rounds,
/// whose Create waits through a STATUS_PENDING reply, whose Close is answered twice and
/// whose Cancel is never answered; an LDAP bind, a search answered by two entries and
/// its result, and a modify; Kerberos AS-REQ refused then granted, and a TGS exchange.
struct ServiceResponseTimeTests {
    // MARK: Internal

    @Test
    func tablesMatchTshark() throws {
        let url = try Self.capture()
        defer { try? FileManager.default.removeItem(at: url) }
        let identity = try CaptureStreamReader(contentsOf: url).identity
        let rows = try CaptureFrameListScanner(contentsOf: url, expectedIdentity: identity, sourceToken: UUID()).scan()
            .rows
        let lines = { (service: ServiceResponseTime.Service) in
            ServiceResponseTime.table(service, rows: rows).map { row in
                "\(row.index) \(row.procedure) \(row.calls) \(ServiceResponseTime.seconds(row.minimum)) "
                    + "\(ServiceResponseTime.seconds(row.maximum)) \(ServiceResponseTime.seconds(row.average)) "
                    + ServiceResponseTime.seconds(row.sum)
            }
        }
        #expect(lines(.smb2) == [
            "0 Negotiate Protocol 1 0.010000 0.010000 0.010000 0.010000",
            "1 Session Setup 2 0.020000 0.030000 0.025000 0.050000",
            "5 Create 1 0.200000 0.200000 0.200000 0.200000",
            "6 Close 1 0.002000 0.002000 0.002000 0.002000",
        ])
        #expect(lines(.ldap) == [
            "0 Bind 1 0.020000 0.020000 0.020000 0.020000",
            "3 Search 3 0.050000 0.100000 0.070000 0.210000",
            "6 Modify 1 0.150000 0.150000 0.150000 0.150000",
        ])
        #expect(lines(.kerberos) == [
            "0 AS-REP 1 0.030000 0.030000 0.030000 0.030000",
            "1 AS-ERROR 1 0.010000 0.010000 0.010000 0.010000",
            "2 TGS-REP 1 0.030000 0.030000 0.030000 0.030000",
        ])
        #expect(ServiceResponseTime.csv(.ldap, ServiceResponseTime.table(.ldap, rows: rows)).hasPrefix(
            "Index,Procedure,Calls,Min SRT,Max SRT,Avg SRT,Sum SRT\r\n0,Bind,1,0.020000,"
        ))

        guard WiresharkOracle.isAvailable else {
            return
        }
        for (service, tap) in [(ServiceResponseTime.Service.smb2, "smb2"), (.ldap, "ldap"), (.kerberos, "kerberos")] {
            #expect(try lines(service) == Self.tshark(url, tap: tap), "\(tap)")
        }
    }

    @Test("Large but representable corrected times do not overflow SRT arithmetic")
    func distantCorrectedTimesRemainFinite() {
        let session = UUID()
        let requestTime = Date(timeIntervalSince1970: 1)
        let responseTime = Date(timeIntervalSince1970: 10_000_000_000_000)
        var request = CaptureFrameRow(
            provenance: SessionFrameProvenance(
                ordinal: FrameOrdinal(rawValue: 1), timestamp: requestTime,
                capturedLength: 0, originalLength: 0, linkType: LinkType.ethernet
            ),
            source: "", destination: "", protocolName: "SMB2", info: "", sessionID: session,
            interfaceID: 0, hasComment: false
        )
        request.srt = .smb2(messageID: 42, command: 0, isResponse: false, isInterim: false)
        var response = CaptureFrameRow(
            provenance: SessionFrameProvenance(
                ordinal: FrameOrdinal(rawValue: 2), timestamp: responseTime,
                capturedLength: 0, originalLength: 0, linkType: LinkType.ethernet
            ),
            source: "", destination: "", protocolName: "SMB2", info: "", sessionID: session,
            interfaceID: 0, hasComment: false
        )
        response.srt = .smb2(messageID: 42, command: 0, isResponse: true, isInterim: false)

        let row = ServiceResponseTime.table(.smb2, rows: [request, response]).first
        #expect(row?.calls == 1)
        #expect(row?.maximum.isFinite == true)
        #expect(row?.sum.isFinite == true)
        #expect(abs((row?.sum ?? 0) - responseTime.timeIntervalSince(requestTime)) < 1)
    }

    @Test("Streaming SMB2 SRT pairs requests and stays within its pending bound")
    func streamingSMB2AccumulatorIsBounded() {
        let session = UUID()
        func frame(
            _ ordinal: UInt64, _ id: UInt64, _ time: TimeInterval, command: Int = 8, response: Bool
        )
            -> CaptureFrameRow
        {
            var row = CaptureFrameRow(
                provenance: SessionFrameProvenance(
                    ordinal: FrameOrdinal(rawValue: ordinal), timestamp: Date(timeIntervalSince1970: time),
                    capturedLength: 0, originalLength: 0, linkType: LinkType.ethernet
                ),
                source: "", destination: "", protocolName: "SMB2", info: "", sessionID: session,
                interfaceID: 0, hasComment: false
            )
            row.srt = .smb2(messageID: id, command: command, isResponse: response, isInterim: false)
            return row
        }

        var accumulator = ServiceResponseTime.StreamingSMB2Accumulator(maximumPendingRequests: 1)
        accumulator.record(frame(1, 10, 100, response: false))
        accumulator.record(frame(2, 10, 100.05, command: 0x0C, response: false))
        accumulator.record(frame(3, 11, 101, response: false))
        accumulator.record(frame(4, 10, 100.125, response: true))
        let result = accumulator.result()
        #expect(result.omittedRequests == 1)
        #expect(result.rows.count == 1)
        #expect(result.rows.first?.calls == 1)
        #expect(abs((result.rows.first?.sum ?? 0) - 0.125) < 0.000001)
        #expect(ServiceResponseTime.table(.smb2, rows: [
            frame(1, 10, 100, response: false),
            frame(2, 10, 100.05, command: 0x0C, response: false),
            frame(4, 10, 100.125, response: true),
        ]).first?.sum == 0.125)
        let csv = ServiceResponseTime.csv(.smb2, result.rows, omittedRequests: result.omittedRequests)
        #expect(csv.contains("Omitted pending requests"))
        #expect(csv.contains(",1\r\n"))
    }

    @Test("Streaming LDAP and Kerberos preserve bounded request/reply semantics")
    func streamingLDAPAndKerberosAccumulators() {
        func row(_ ordinal: UInt64, _ session: UUID, _ time: TimeInterval, _ fact: SRTFrameFact) -> CaptureFrameRow {
            var row = CaptureFrameRow(
                provenance: SessionFrameProvenance(
                    ordinal: FrameOrdinal(rawValue: ordinal), timestamp: Date(timeIntervalSince1970: time),
                    capturedLength: 0, originalLength: 0, linkType: LinkType.ethernet
                ),
                source: "", destination: "", protocolName: "", info: "", sessionID: session,
                interfaceID: 0, hasComment: false
            )
            row.srt = fact
            return row
        }

        let session = UUID()
        var ldap = ServiceResponseTime.StreamingAccumulator(service: .ldap, maximumCorrelations: 1)
        ldap.record(row(1, session, 1, .ldap(messageID: 7, operation: 3)))
        ldap.record(row(2, session, 1.1, .ldap(messageID: 7, operation: 4)))
        ldap.record(row(3, session, 1.2, .ldap(messageID: 7, operation: 19)))
        ldap.record(row(4, session, 1.3, .ldap(messageID: 7, operation: 25)))
        ldap.record(row(5, session, 1.4, .ldap(messageID: 7, operation: 5)))
        ldap.record(row(6, session, 1.5, .ldap(messageID: 8, operation: 3)))
        let ldapResult = ldap.result()
        #expect(ldapResult.omittedCorrelations == 0)
        #expect(ldapResult.rows.first?.calls == 4)
        #expect(abs((ldapResult.rows.first?.sum ?? 0) - 1.0) < 0.000001)

        var boundedLDAP = ServiceResponseTime.StreamingAccumulator(service: .ldap, maximumCorrelations: 1)
        boundedLDAP.record(row(1, session, 1, .ldap(messageID: 7, operation: 3)))
        boundedLDAP.record(row(2, session, 1.1, .ldap(messageID: 7, operation: 4)))
        boundedLDAP.record(row(3, session, 1.2, .ldap(messageID: 8, operation: 3)))
        #expect(boundedLDAP.result().omittedCorrelations == 1)

        var kerberos = ServiceResponseTime.StreamingAccumulator(service: .kerberos, maximumCorrelations: 1)
        kerberos.record(row(1, session, 2, .kerberos(type: 10)))
        kerberos.record(row(2, session, 2.01, .kerberos(type: 14))) // Unrelated AP request is ignored.
        kerberos.record(row(3, session, 2.1, .kerberos(type: 11)))
        kerberos.record(row(4, session, 2.2, .kerberos(type: 12)))
        kerberos.record(row(5, session, 2.3, .kerberos(type: 30)))
        kerberos.record(row(6, session, 2.4, .kerberos(type: 10)))
        kerberos.record(row(7, session, 2.5, .kerberos(type: 13))) // A mismatched tracked reply consumes the request.
        kerberos.record(row(8, session, 2.6, .kerberos(type: 11)))
        kerberos.record(row(9, session, 2.7, .kerberos(type: 10)))
        kerberos.record(row(10, session, 2.8, .kerberos(type: 10))) // Duplicate replaces its timestamp.
        kerberos.record(row(11, session, 2.9, .kerberos(type: 30)))
        let kerberosResult = kerberos.result()
        #expect(kerberosResult.omittedCorrelations == 0)
        #expect(kerberosResult.rows.map(\.index) == [0, 1, 3])
        #expect(kerberosResult.rows.map(\.calls) == [1, 1, 1])
        #expect(abs((kerberosResult.rows.first(where: { $0.index == 0 })?.sum ?? 0) - 0.1) < 0.000001)
        #expect(abs((kerberosResult.rows.first(where: { $0.index == 1 })?.sum ?? 0) - 0.1) < 0.000001)
        #expect(abs((kerberosResult.rows.first(where: { $0.index == 3 })?.sum ?? 0) - 0.1) < 0.000001)

        var boundedKerberos = ServiceResponseTime.StreamingAccumulator(service: .kerberos, maximumCorrelations: 1)
        boundedKerberos.record(row(1, session, 3, .kerberos(type: 10)))
        boundedKerberos.record(row(2, UUID(), 3, .kerberos(type: 12)))
        #expect(boundedKerberos.result().omittedCorrelations == 1)
    }

    /// ICMP and ICMPv6 echo: four requests, one unanswered and one answered twice, as
    /// `tshark -z icmp,srt` and `icmpv6,srt` print them.
    @Test
    func echoSummaryMatchesTshark() throws {
        var frames: [(TimeInterval, [UInt8])] = []
        for (isV6, offset) in [(false, 0.0), (true, 10.0)] {
            for (sequence, request, reply) in [(1, 0.0, 0.012), (2, 1.0, 1.020), (3, 2.0, nil), (4, 3.0, 3.008)] {
                frames.append((offset + request, Self.echo(isV6: isV6, request: true, sequence: UInt16(sequence))))
                if let reply {
                    frames.append((offset + reply, Self.echo(isV6: isV6, request: false, sequence: UInt16(sequence))))
                }
            }
            // A second reply to request 4 is not paired again.
            frames.append((offset + 3.5, Self.echo(isV6: isV6, request: false, sequence: 4)))
        }
        frames.sort { $0.0 < $1.0 }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("echo-\(UUID().uuidString).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames.map { time, bytes in
            CapturedFrame(
                bytes: bytes, timestamp: Date(timeIntervalSince1970: 1_800_000_000 + time), originalLength: bytes.count
            )
        }, to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let identity = try CaptureStreamReader(contentsOf: url).identity
        let rows = try CaptureFrameListScanner(contentsOf: url, expectedIdentity: identity, sourceToken: UUID()).scan()
            .rows
        let v4 = EchoResponseTime(rows: rows, ipv6: false)
        #expect(v4.values == ["4", "3", "1", "25.0", "8.000", "20.000", "13.333", "12.000", "6.110", "7", "4"])
        #expect(EchoResponseTime(rows: rows, ipv6: true).values.prefix(9)
            == ["4", "3", "1", "25.0", "8.000", "20.000", "13.333", "12.000", "6.110"])

        guard WiresharkOracle.isAvailable else {
            return
        }
        for (ipv6, tap) in [(false, "icmp"), (true, "icmpv6")] {
            #expect(try EchoResponseTime(rows: rows, ipv6: ipv6).values == Self.tsharkEcho(url, tap: tap), "\(tap)")
        }
    }

    @Test
    func echoRequestsWithSameKeyInOppositeDirectionsRemainDistinct() throws {
        var frames: [(TimeInterval, [UInt8])] = []
        for (isV6, offset) in [(false, 0.0), (true, 10.0)] {
            frames += [
                (offset, Self.echo(isV6: isV6, request: true, sequence: 9)),
                (offset + 0.005, Self.echo(isV6: isV6, request: true, sequence: 9, reverseFlow: true)),
                (offset + 0.008, Self.echo(isV6: isV6, request: false, sequence: 9)),
                (offset + 0.010, Self.echo(isV6: isV6, request: false, sequence: 9, reverseFlow: true)),
            ]
        }
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("echo-directions-\(UUID().uuidString).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames.map { time, bytes in
            CapturedFrame(
                bytes: bytes, timestamp: Date(timeIntervalSince1970: 1_800_000_000 + time), originalLength: bytes.count
            )
        }, to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let identity = try CaptureStreamReader(contentsOf: url).identity
        let rows = try CaptureFrameListScanner(contentsOf: url, expectedIdentity: identity, sourceToken: UUID()).scan()
            .rows

        for (isV6, expectedFrames) in [(false, [4, 3]), (true, [8, 7])] {
            let batch = EchoResponseTime(rows: rows, ipv6: isV6)
            let frameColumns = isV6 ? ["8", "7"] : ["4", "3"]
            #expect(batch.values == ["2", "2", "0", "0.0", "5.000", "8.000", "6.500", "6.500", "2.121"] + frameColumns)
            #expect(batch.minimumFrame == UInt64(expectedFrames[0]))
            #expect(batch.maximumFrame == UInt64(expectedFrames[1]))

            var streaming = EchoResponseTimeStreamingAccumulator(ipv6: isV6)
            for row in rows {
                streaming.record(row)
            }
            #expect(streaming.failure == nil)
            #expect(streaming.result() == batch)
        }

        let observed = try #require(rows.first { $0.srt != nil })
        var untimed = CaptureFrameRow(
            provenance: SessionFrameProvenance(
                ordinal: observed.provenance.ordinal, timestamp: nil,
                capturedLength: observed.provenance.capturedLength,
                originalLength: observed.provenance.originalLength,
                linkType: observed.provenance.linkType
            ),
            source: observed.source, destination: observed.destination, protocolName: observed.protocolName,
            info: observed.info, sessionID: observed.sessionID, interfaceID: observed.interfaceID,
            hasComment: observed.hasComment
        )
        untimed.ip = observed.ip
        untimed.srt = observed.srt
        var untimedAccumulator = EchoResponseTimeStreamingAccumulator(ipv6: false)
        untimedAccumulator.record(untimed)
        #expect(untimedAccumulator.failure == .incompleteEchoFacts)
    }

    // MARK: Private

    private static let client = "192.0.2.10"
    private static let server = "192.0.2.5"

    /// tshark's two ICMP value lines as one list, "%" and trailing spaces dropped.
    private static func tsharkEcho(_ url: URL, tap: String) throws -> [String] {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = WiresharkOracle.tsharkURL
        process.arguments = ["-r", url.path, "-q", "-z", "\(tap),srt"]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let text = String(bytes: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        process.waitUntilExit()
        let lines = text.components(separatedBy: "\n")
        var values: [String] = []
        for (index, line) in lines.enumerated() where line.hasPrefix("Requests") || line.hasPrefix("Minimum") {
            values += lines[index + 1].replacingOccurrences(of: "%", with: "").split(separator: " ").map(String.init)
        }
        return values
    }

    /// An echo request or reply between 192.0.2.10 and 198.51.100.1 (or their IPv6
    /// counterparts), identifier 0x1234, eight bytes of data, with a correct checksum.
    private static func echo(isV6: Bool, request: Bool, sequence: UInt16, reverseFlow: Bool = false) -> [UInt8] {
        let type: UInt8 = isV6 ? (request ? 128 : 129) : (request ? 8 : 0)
        var message: [UInt8] = [type, 0, 0, 0, 0x12, 0x34, UInt8(sequence >> 8), UInt8(sequence & 0xFF)]
            + Array("abcdefgh".utf8)
        let client: [UInt16] = [0x2001, 0xDB8, 0, 0, 0, 0, 0, 0x10]
        let server: [UInt16] = [0x2001, 0xDB8, 0, 0, 0, 0, 0, 0x1]
        let sourceIsClient = request != reverseFlow
        let (source, destination) = sourceIsClient ? (client, server) : (server, client)
        var summed = message
        if isV6 {
            // The ICMPv6 checksum covers a pseudo-header of both addresses, length and 58.
            summed += (source + destination).flatMap { [UInt8($0 >> 8), UInt8($0 & 0xFF)] }
                + [0, 0, 0, UInt8(message.count), 0, 0, 0, 58]
        }
        var sum: UInt32 = 0
        for index in stride(from: 0, to: summed.count, by: 2) {
            sum += UInt32(summed[index]) << 8 | UInt32(index + 1 < summed.count ? summed[index + 1] : 0)
        }
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        let checksum = ~UInt16(sum)
        message[2] = UInt8(checksum >> 8)
        message[3] = UInt8(checksum & 0xFF)
        if isV6 {
            return PacketBuilder.ethernetIPv6(nextHeader: 58, src: source, dst: destination, payload: message)
        }
        return PacketBuilder.ethernetIPv4(
            proto: 1, src: sourceIsClient ? "192.0.2.10" : "198.51.100.1",
            dst: sourceIsClient ? "198.51.100.1" : "192.0.2.10",
            payload: message
        )
    }

    /// The SRT table's rows as "index procedure calls min max avg sum".
    private static func tshark(_ url: URL, tap: String) throws -> [String] {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = WiresharkOracle.tsharkURL
        process.arguments = ["-r", url.path, "-q", "-z", "\(tap),srt"]
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let text = String(bytes: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        process.waitUntilExit()
        return text.components(separatedBy: "\n").compactMap { line in
            guard let match = line.firstMatch(
                of: #/^\s+(\d+)\s+(.+?)\s+(\d+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*$/#
            ) else {
                return nil
            }
            return "\(match.1) \(match.2) \(match.3) \(match.4) \(match.5) \(match.6) \(match.7)"
        }
    }

    private static func tlv(_ tag: UInt8, _ value: [UInt8]) -> [UInt8] {
        let count = value.count
        let length: [UInt8] = count < 0x80 ? [UInt8(count)] : count < 256 ? [0x81, UInt8(count)]
            : [0x82, UInt8(count >> 8), UInt8(count & 0xFF)]
        return [tag] + length + value
    }

    private static func integer(_ value: Int) -> [UInt8] {
        var bytes: [UInt8] = []
        var rest = value
        repeat {
            bytes.insert(UInt8(rest & 0xFF), at: 0)
            rest >>= 8
        } while rest > 0
        if bytes[0] & 0x80 != 0 {
            bytes.insert(0, at: 0)
        }
        return tlv(0x02, bytes)
    }

    private static func smb2(command: UInt16, status: UInt32, flags: UInt32, messageID: UInt64) -> [UInt8] {
        func le(_ value: UInt64, _ count: Int) -> [UInt8] {
            (0 ..< count).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) }
        }
        let header = [0xFE, 0x53, 0x4D, 0x42] + le(64, 2) + le(0, 2) + le(UInt64(status), 4) + le(UInt64(command), 2)
            + le(1, 2) + le(UInt64(flags), 4) + le(0, 4) + le(messageID, 8) + le(0, 4) + le(0, 4) + le(0, 8)
            + [UInt8](repeating: 0, count: 16)
        let message = header + [0x24, 0, 0, 0] + [UInt8](repeating: 0, count: 32)
        return [0, 0, UInt8(message.count >> 8), UInt8(message.count & 0xFF)] + message
    }

    private static func capture() throws -> URL {
        var frames: [(TimeInterval, [UInt8])] = []
        var sequences: [String: UInt32] = [:]
        func tcp(_ time: TimeInterval, fromClient: Bool, port: UInt16, _ payload: [UInt8]) {
            let key = "\(fromClient)-\(port)"
            let sequence = sequences[key, default: 1_000]
            sequences[key] = sequence + UInt32(payload.count)
            frames.append((time, PacketBuilder.ethernetIPv4(
                proto: 6, src: fromClient ? client : server, dst: fromClient ? server : client,
                payload: PacketBuilder.tcp(
                    srcPort: fromClient ? 50_000 + port : port, dstPort: fromClient ? port : 50_000 + port,
                    flags: 0x18, payload: payload, sequence: sequence
                )
            )))
        }
        func udp(_ time: TimeInterval, fromClient: Bool, port: UInt16, _ payload: [UInt8]) {
            frames.append((time, PacketBuilder.ethernetIPv4(
                proto: 17, src: fromClient ? client : server, dst: fromClient ? server : client,
                payload: PacketBuilder.udp(
                    srcPort: fromClient ? port : 88,
                    dstPort: fromClient ? 88 : port,
                    payload: payload
                )
            )))
        }
        // SMB2 on 445.
        let smb = { (time: TimeInterval, request: Bool, command: UInt16, id: UInt64, status: UInt32, flags: UInt32) in
            tcp(
                time,
                fromClient: request,
                port: 445,
                smb2(command: command, status: status, flags: flags, messageID: id)
            )
        }
        smb(0.000, true, 0, 0, 0, 0)
        smb(0.010, false, 0, 0, 0, 1)
        smb(0.020, true, 1, 1, 0, 0)
        smb(0.050, false, 1, 1, 0xC0000016, 1)
        smb(0.060, true, 1, 2, 0, 0)
        smb(0.080, false, 1, 2, 0, 1)
        smb(0.100, true, 5, 3, 0, 0)
        smb(0.105, false, 5, 3, 0x00000103, 3)
        smb(0.300, false, 5, 3, 0, 3)
        smb(0.310, true, 6, 4, 0, 0)
        smb(0.312, false, 6, 4, 0, 1)
        smb(0.400, false, 6, 4, 0, 1)
        smb(0.500, true, 12, 5, 0, 0)
        // LDAP on 389.
        let message = { (id: Int, operation: [UInt8]) in tlv(0x30, integer(id) + operation) }
        let result = { (tag: UInt8) in tlv(tag, tlv(0x0A, [0]) + tlv(0x04, []) + tlv(0x04, [])) }
        let entry = { (name: String) in
            tlv(0x64, tlv(0x04, Array("cn=\(name),dc=example,dc=test".utf8)) + tlv(0x30, []))
        }
        let search = tlv(
            0x63,
            tlv(0x04, Array("dc=example,dc=test".utf8)) + tlv(0x0A, [2]) + tlv(0x0A, [0])
                + integer(0) + integer(0) + tlv(0x01, [0]) + tlv(0x87, Array("objectClass".utf8)) + tlv(0x30, [])
        )
        let modify = tlv(0x66, tlv(0x04, Array("cn=a,dc=example,dc=test".utf8)) + tlv(0x30, tlv(
            0x30,
            tlv(0x0A, [2])
                + tlv(0x30, tlv(0x04, Array("description".utf8)) + tlv(0x31, tlv(0x04, Array("x".utf8))))
        )))
        tcp(1.000, fromClient: true, port: 389, message(1, tlv(0x60, integer(3) + tlv(0x04, []) + tlv(0x80, []))))
        tcp(1.020, fromClient: false, port: 389, message(1, result(0x61)))
        tcp(1.100, fromClient: true, port: 389, message(2, search))
        tcp(1.150, fromClient: false, port: 389, message(2, entry("a")))
        tcp(1.160, fromClient: false, port: 389, message(2, entry("b")))
        tcp(1.200, fromClient: false, port: 389, message(2, result(0x65)))
        tcp(1.300, fromClient: true, port: 389, message(3, modify))
        tcp(1.450, fromClient: false, port: 389, message(3, result(0x67)))
        // Kerberos on UDP 88.
        let realm = tlv(0x1B, Array("EXAMPLE.TEST".utf8))
        let krbtgt = tlv(0x30, tlv(0xA0, integer(2)) + tlv(0xA1, tlv(0x30, tlv(0x1B, Array("krbtgt".utf8)) + realm)))
        let request = { (application: UInt8, type: Int) in
            let body = tlv(
                0x30,
                tlv(0xA0, tlv(0x03, [0, 0x40, 0x81, 0, 0x10])) + tlv(0xA2, realm) + tlv(0xA3, krbtgt)
                    + tlv(0xA5, tlv(0x18, Array("20370913024805Z".utf8))) + tlv(0xA7, integer(12_345))
                    + tlv(0xA8, tlv(0x30, integer(18)))
            )
            return tlv(application, tlv(0x30, tlv(0xA1, integer(5)) + tlv(0xA2, integer(type)) + tlv(0xA4, body)))
        }
        let reply = { (application: UInt8, type: Int) in
            tlv(application, tlv(0x30, tlv(0xA0, integer(5)) + tlv(0xA1, integer(type))))
        }
        let refusal = tlv(0x7E, tlv(
            0x30,
            tlv(0xA0, integer(5)) + tlv(0xA1, integer(30))
                + tlv(0xA4, tlv(0x18, Array("20260924000000Z".utf8))) + tlv(0xA5, integer(0)) + tlv(0xA6, integer(25))
                + tlv(0xA9, realm) + tlv(0xAA, krbtgt)
        ))
        udp(2.000, fromClient: true, port: 52_000, request(0x6A, 10))
        udp(2.010, fromClient: false, port: 52_000, refusal)
        udp(2.020, fromClient: true, port: 52_000, request(0x6A, 10))
        udp(2.050, fromClient: false, port: 52_000, reply(0x6B, 11))
        udp(2.100, fromClient: true, port: 52_001, request(0x6C, 12))
        udp(2.130, fromClient: false, port: 52_001, reply(0x6D, 13))

        let url = FileManager.default.temporaryDirectory.appendingPathComponent("srt-\(UUID().uuidString).pcap")
        try PcapWriter.write(linkType: LinkType.ethernet, frames: frames.map { time, bytes in
            CapturedFrame(
                bytes: bytes, timestamp: Date(timeIntervalSince1970: 1_800_000_000 + time), originalLength: bytes.count
            )
        }, to: url)
        return url
    }
}
