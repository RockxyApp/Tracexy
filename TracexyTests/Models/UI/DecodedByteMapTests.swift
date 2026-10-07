import AppKit
import Foundation
import SwiftUI
import Testing
@testable import Tracexy

/// The bytes → field half of the linked decode tree and hex pane. Pointing
/// at a byte names the innermost field that owns it; the field spans themselves
/// match Wireshark's PDML positions for the fixed Ethernet, IPv4, TCP and UDP
/// headers.
struct DecodedByteMapTests {
    // MARK: Internal

    @Test
    func innermostOwnerWins() {
        let layers = [
            DecodedLayer(
                proto: .ipv4, title: "IPv4",
                fields: [
                    DecodedField(name: "Header Length", value: "20 bytes", byteRange: 0 ..< 1),
                    DecodedField(name: "Total Length", value: "40", byteRange: 2 ..< 4),
                ],
                children: [
                    DecodedLayer(proto: .tcp, title: "Inner", byteRange: 2 ..< 4),
                ],
                byteRange: 0 ..< 20
            ),
        ]
        #expect(DecodedByteMap.owner(ofByte: 0, in: layers)?.description == "IPv4, Header Length: 20 bytes")
        // Equal spans go to the deeper owner: here a child layer over its parent's field.
        #expect(DecodedByteMap.owner(ofByte: 3, in: layers)?.path == ["IPv4", "Inner"])
        // No field there: the layer itself owns the byte.
        #expect(DecodedByteMap.owner(ofByte: 10, in: layers)?.description == "IPv4")
        #expect(DecodedByteMap.owner(ofByte: 10, in: layers)?.range == 0 ..< 20)
        #expect(DecodedByteMap.owner(ofByte: 40, in: layers) == nil)
        #expect(DecodedByteMap.pointerText(forByte: 2, in: layers) == "IPv4, Inner (bytes 2–3)")
        #expect(DecodedByteMap.pointerText(forByte: 0, in: layers) == "IPv4, Header Length: 20 bytes (byte 0)")
        #expect(DecodedByteMap.pointerText(forByte: 40, in: layers) == "Byte 40")
    }

    @Test
    func hexRowColumnsMatchTheDumpLayout() {
        // "0000   " then "XX " × 8, a gap, "XX " × 8, two spaces, 16 ASCII.
        #expect(HexDumpView.column(atCharacter: 0) == nil)
        #expect(HexDumpView.column(atCharacter: 7) == 0)
        #expect(HexDumpView.column(atCharacter: 9) == 0)
        #expect(HexDumpView.column(atCharacter: 10) == 1)
        #expect(HexDumpView.column(atCharacter: 30) == 7)
        #expect(HexDumpView.column(atCharacter: 31) == nil)
        #expect(HexDumpView.column(atCharacter: 32) == 8)
        #expect(HexDumpView.column(atCharacter: 55) == 15)
        #expect(HexDumpView.column(atCharacter: 56) == nil)
        #expect(HexDumpView.column(atCharacter: 58) == 0)
        #expect(HexDumpView.column(atCharacter: 73) == 15)
        #expect(HexDumpView.column(atCharacter: 74) == nil)
    }

    @Test
    func headerFieldSpansMatchWireshark() throws {
        let tcp = PacketBuilder.ethernetIPv4(
            proto: 6, src: "10.0.0.5", dst: "203.0.113.9",
            payload: PacketBuilder.tcp(
                srcPort: 50_000, dstPort: 443, flags: 0x18, payload: Array("hello".utf8), sequence: 7
            )
        )
        let udp = PacketBuilder.dnsQueryFrame(name: "example.com", src: "10.0.0.5", dst: "10.0.0.1")
        let tcpLayers = Self.decode(tcp)
        let udpLayers = Self.decode(udp)

        // Every byte of the fixed headers has a named field, not just a layer.
        for index in 14 ..< 54 {
            #expect(DecodedByteMap.owner(ofByte: index, in: tcpLayers)?.value != nil, "byte \(index)")
        }
        #expect(DecodedByteMap.owner(ofByte: 50, in: tcpLayers)?.description
            == "Transmission Control Protocol, Checksum: 0x0000")

        guard WiresharkOracle.isAvailable else {
            return
        }
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("byte-map-\(UUID().uuidString).pcap")
        let frames = [
            ReplayCorpus.Frame(bytes: tcp, offsetSeconds: 0, linkType: LinkType.ethernet),
            ReplayCorpus.Frame(bytes: udp, offsetSeconds: 1, linkType: LinkType.ethernet),
        ]
        try Data(ReplayCorpus.classicPcapBytes(frames)).write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }

        try Self.expectSpans(Self.tcpFields, layers: tcpLayers, oracle: WiresharkOracle.tsharkPDMLFields(url, frame: 1))
        try Self.expectSpans(Self.udpFields, layers: udpLayers, oracle: WiresharkOracle.tsharkPDMLFields(url, frame: 2))
    }

    /// A real click, delivered as AppKit mouse events to a hosted dump, lands on the
    /// byte under it with the dump's actual font metrics.
    @MainActor
    @Test(arguments: [(0, ByteDumpStyle.hex), (4, .hex), (0, .bits)])
    func clickingAByteReportsThatByte(zoom: Int, style: ByteDumpStyle) async throws {
        let frame = PacketBuilder.ethernetIPv4(
            proto: 6, src: "10.0.0.5", dst: "203.0.113.9",
            payload: PacketBuilder.tcp(srcPort: 50_000, dstPort: 443, flags: 0x18, payload: [], sequence: 7)
        )
        var clicked: [Int] = []
        let dump = HexDumpView(
            bytes: frame, onClickByte: { clicked.append($0) }
        )
        .frame(width: 900, alignment: .topLeading)
        .environment(\.packetTextZoom, zoom)
        .environment(\.byteDumpStyle, style)
        let hosting = NSHostingView(rootView: dump)
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 900, height: 300),
            styleMask: [.borderless], backing: .buffered, defer: false
        )
        window.contentView = hosting
        hosting.frame = NSRect(x: 0, y: 0, width: 900, height: 300)
        hosting.layoutSubtreeIfNeeded()
        // Far off-screen but ordered in, so SwiftUI's gesture system is live.
        window.setFrameOrigin(NSPoint(x: -20_000, y: -20_000))
        window.orderFrontRegardless()
        defer { window.orderOut(nil) }
        try await Task.sleep(for: .milliseconds(200))

        let perRow = style.bytesPerRow
        let rows = (frame.count + perRow - 1) / perRow
        let rowHeight = (hosting.fittingSize.height - CGFloat(2 * (rows - 1))) / CGFloat(rows)
        // Byte 0x17 (IPv4 Protocol): in hex row 1, column 7, then its ASCII cell; in
        // bits row 2, column 7 (a digit inside its cell), then its ASCII cell.
        let row = 0x17 / perRow
        let characters = style == .hex ? [7 + 3 * 7, 58 + 7] : [7 + 9 * 7 + 4, 80 + 7]
        for (index, character) in characters.enumerated() {
            let x = (CGFloat(character) + 0.5) * HexDumpView.characterWidth(zoom: zoom)
            let y = CGFloat(row) * (rowHeight + 2) + rowHeight / 2
            // Under a loaded suite the gesture can land late (or, the first time, be
            // taken as the window's activation click): wait for it, and send it once
            // more if nothing arrived.
            for _ in 0 ..< 2 where clicked.count == index {
                try click(window, at: hosting.convert(NSPoint(x: x, y: y), to: nil))
                for _ in 0 ..< 30 where clicked.count == index {
                    try await Task.sleep(for: .milliseconds(100))
                }
            }
        }
        #expect(clicked == [0x17, 0x17])
        let layers = Self.decode(frame)
        #expect(DecodedByteMap.owner(ofByte: 0x17, in: layers)?
            .description == "Internet Protocol v4, Protocol: TCP (6)")
    }

    // MARK: Private

    /// (layer title, Tracexy field name, Wireshark field) for the fixed headers.
    private static let linkAndIP: [(String, String, String)] = [
        ("Ethernet II", "Destination", "eth.dst"),
        ("Ethernet II", "Source", "eth.src"),
        ("Ethernet II", "Type", "eth.type"),
        ("Internet Protocol v4", "Header Length", "ip.hdr_len"),
        ("Internet Protocol v4", "Differentiated Services", "ip.dsfield"),
        ("Internet Protocol v4", "Total Length", "ip.len"),
        ("Internet Protocol v4", "Identification", "ip.id"),
        ("Internet Protocol v4", "Flags", "ip.flags"),
        ("Internet Protocol v4", "TTL", "ip.ttl"),
        ("Internet Protocol v4", "Protocol", "ip.proto"),
        ("Internet Protocol v4", "Header Checksum", "ip.checksum"),
        ("Internet Protocol v4", "Source", "ip.src"),
        ("Internet Protocol v4", "Destination", "ip.dst"),
    ]

    private static let tcpFields = linkAndIP + [
        ("Transmission Control Protocol", "Source Port", "tcp.srcport"),
        ("Transmission Control Protocol", "Destination Port", "tcp.dstport"),
        ("Transmission Control Protocol", "Seq", "tcp.seq_raw"),
        ("Transmission Control Protocol", "Ack", "tcp.ack_raw"),
        ("Transmission Control Protocol", "Header Length", "tcp.hdr_len"),
        ("Transmission Control Protocol", "Flags", "tcp.flags"),
        ("Transmission Control Protocol", "Window", "tcp.window_size_value"),
        ("Transmission Control Protocol", "Checksum", "tcp.checksum"),
        ("Transmission Control Protocol", "Urgent Pointer", "tcp.urgent_pointer"),
    ]

    private static let udpFields = linkAndIP + [
        ("User Datagram Protocol", "Source Port", "udp.srcport"),
        ("User Datagram Protocol", "Destination Port", "udp.dstport"),
        ("User Datagram Protocol", "Length", "udp.length"),
        ("User Datagram Protocol", "Checksum", "udp.checksum"),
    ]

    private static func decode(_ frame: [UInt8]) -> [DecodedLayer] {
        PacketDecoder.decode(
            PacketBuffer(frame), linkType: LinkType.ethernet, timestamp: nil, originalLength: frame.count
        ).layers
    }

    private static func field(_ name: String, inLayer title: String, _ layers: [DecodedLayer]) -> DecodedField? {
        for layer in layers {
            if layer.title == title, let field = layer.fields.first(where: { $0.name == name }) {
                return field
            }
            if let nested = field(name, inLayer: title, layer.children) {
                return nested
            }
        }
        return nil
    }

    private static func expectSpans(
        _ table: [(String, String, String)],
        layers: [DecodedLayer],
        oracle: [WiresharkOracle.PDMLField]
    ) {
        for (title, name, wireshark) in table {
            let ours = field(name, inLayer: title, layers)?.byteRange
            let theirs = oracle.first { $0.name == wireshark }.map { $0.position ..< $0.position + $0.size }
            #expect(ours != nil && ours == theirs, "\(title) \(name) vs \(wireshark)")
        }
    }

    @MainActor
    private func click(_ window: NSWindow, at point: NSPoint) throws {
        for type in [NSEvent.EventType.leftMouseDown, .leftMouseUp] {
            let event = try #require(NSEvent.mouseEvent(
                with: type, location: point, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                windowNumber: window.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 1
            ))
            window.sendEvent(event)
        }
    }
}
